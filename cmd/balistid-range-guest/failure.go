package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// A failure trial's scratch disk, the file its measured writer appends to, the console its marks go
// to directly (the unit's own output goes through the journal first), and the sysrq trigger.
const (
	scratchDev   = "/dev/disk/by-id/virtio-balistid-scratch"
	scratchMount = "/run/balistid-scratch"
	numbersFile  = scratchMount + "/numbers"
	consoleDev   = "/dev/ttyS0"
	sysrqTrigger = "/proc/sysrq-trigger"
	writerArg    = "writer"
)

var errFailNow = errors.New("failure moment reached")

// runFailure runs boot `boot` of failure trial tr (ADR 0018, point 3). Boot 1 makes ext4 on the
// scratch disk, mounts it, and for a reset reports its echo and reset_armed=yes before any load, so
// the host can boot again; it then hands numbers to the measured writer, a child process, at the
// trial's rate, and at a random moment in the load's second half writes "balistid-fail <H>" to the
// console and resets with sysrq b, or kills the writer and writes "balistid-killed". After a reset
// boot 2 reads the superblock before anything mounts the disk. Both report what the file holds.
func runFailure(ctx context.Context, tr rangejob.Trial, boot int, facts []fact) error {
	r := &report{facts: facts}
	add, fail := r.add, r.fail
	if !waitFor(func() bool { _, err := os.Stat(scratchDev); return err == nil }) {
		return fail("no scratch disk")
	}
	if boot == 2 {
		head := make([]byte, rangeguest.SuperblockEnd)
		if err := readHead(scratchDev, head); err != nil {
			return fail("superblock: " + err.Error())
		}
		journal, recovery, err := rangeguest.Superblock(head)
		if err != nil {
			return fail("superblock: " + err.Error())
		}
		add(rangevm.FactScratchJournal, yesNo(journal))
		add(rangevm.FactScratchRecovery, yesNo(recovery))
		if err := mountScratch(); err != nil {
			return fail(err.Error())
		}
		return r.stored()
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/mkfs.ext4", "-q", "-F", scratchDev).CombinedOutput(); err != nil {
		return fail(fmt.Sprintf("mkfs: %v: %.200s", err, out))
	}
	if err := mountScratch(); err != nil {
		return fail(err.Error())
	}
	if tr.Failure == rangejob.FailReset {
		add(rangevm.FactResetArmed, "yes")
		if err := write(r.facts); err != nil { // synced before the load: the host reads it after the reset
			return err
		}
	}
	return loadAndFail(ctx, tr, r)
}

// loadAndFail hands numbers to the writer until the failure moment and fails there.
func loadAndFail(ctx context.Context, tr rangejob.Trial, r *report) error {
	fail := r.fail
	span := time.Duration(tr.Load.Seconds) * time.Second
	extra, err := rand.Int(rand.Reader, big.NewInt(int64(span/2)))
	if err != nil {
		return fail("random failure moment: " + err.Error())
	}
	start := time.Now()
	failAt := start.Add(span/2 + time.Duration(extra.Int64()))
	stopSync := time.Duration(0)
	if tr.Load.Writer.LastSync > 0 {
		stopSync = failAt.Add(-tr.Load.Writer.LastSync).Sub(start)
	}
	self, err := os.Executable()
	if err != nil {
		return fail("own path: " + err.Error())
	}
	child := exec.CommandContext(ctx, self, writerArg, ms(tr.Load.Writer.Hold), ms(tr.Load.Writer.Sync), ms(stopSync)) //nolint:gosec // our own binary, durations from the table
	pipe, err := child.StdinPipe()
	if err != nil {
		return fail("writer pipe: " + err.Error())
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return fail("writer: " + err.Error())
	}
	var hand rangeguest.Handover
	_, _, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, func(seq uint64) error {
		if !time.Now().Before(failAt) {
			return errFailNow
		}
		if _, err := pipe.Write(binary.LittleEndian.AppendUint64(nil, seq)); err != nil {
			return fmt.Errorf("hand over: %w", err)
		}
		hand.Add(time.Now())
		return nil
	}, rangeguest.WallClock)
	if !errors.Is(genErr, errFailNow) {
		return fail(fmt.Sprintf("load ended before the failure: %v", genErr))
	}
	h := hand.H(time.Now())
	if err := mark(fmt.Sprintf("balistid-fail %d\n", h)); err != nil {
		return fail(err.Error())
	}
	if tr.Failure == rangejob.FailReset {
		// Reboot at once, without syncing or unmounting; with -no-reboot QEMU exits.
		_ = os.WriteFile(sysrqTrigger, []byte("b"), 0)
		return fail("sysrq b did not reset the guest")
	}
	if err := child.Process.Kill(); err != nil {
		return fail("kill writer: " + err.Error())
	}
	if err := mark("balistid-killed\n"); err != nil {
		return fail(err.Error())
	}
	_ = child.Wait()
	_ = pipe.Close()
	return r.stored()
}

// report collects a trial boot's facts.
type report struct{ facts []fact }

func (r *report) add(name, value string) { r.facts = append(r.facts, fact{name, value}) }

// fail reports why the guest could not run the trial, which the host judges INVALID.
func (r *report) fail(why string) error {
	r.add(rangevm.FactTrialError, why)
	return write(r.facts)
}

// stored adds what the numbers file holds and writes the report.
func (r *report) stored() error {
	data, err := os.ReadFile(numbersFile)
	if err != nil {
		return r.fail("numbers: " + err.Error())
	}
	prefix, count := rangeguest.StoredPrefix(data)
	r.add(rangevm.FactStoredPrefix, strconv.FormatUint(prefix, 10))
	r.add(rangevm.FactStoredCount, strconv.FormatUint(count, 10))
	return write(r.facts)
}

// writerMain is the measured writer's process: hold, sync and stop-sync in milliseconds, numbers on
// stdin, records appended to the numbers file.
func writerMain(args []string) error {
	if len(args) != 3 {
		return errors.New("want hold, sync and stop-sync in milliseconds")
	}
	var d [3]time.Duration
	for i, a := range args {
		n, err := strconv.Atoi(a)
		if err != nil || n < 0 {
			return fmt.Errorf("argument %d: not a number of milliseconds", i+1)
		}
		d[i] = time.Duration(n) * time.Millisecond
	}
	pol := rangeguest.Policy{Hold: d[0], Sync: d[1]}
	if d[2] > 0 {
		pol.StopSync = time.Now().Add(d[2])
	}
	f, err := os.OpenFile(numbersFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("numbers file: %w", err)
	}
	defer f.Close() //nolint:errcheck // synced by ServeWriter
	if err := rangeguest.ServeWriter(os.Stdin, rangeguest.NewWriter(f, pol, rangeguest.WallClock)); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func mountScratch() error {
	if err := os.MkdirAll(scratchMount, 0o700); err != nil {
		return fmt.Errorf("mount point: %w", err)
	}
	if err := syscall.Mount(scratchDev, scratchMount, "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount scratch: %w", err)
	}
	return nil
}

// mark writes one line straight to the serial console.
func mark(line string) error {
	f, err := os.OpenFile(consoleDev, os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}
	_, err = f.WriteString(line)
	return errors.Join(err, f.Close())
}

func readHead(dev string, head []byte) error {
	f, err := os.Open(dev) //nolint:gosec // the scratch disk by its virtio serial
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if _, err := io.ReadFull(f, head); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	return nil
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
