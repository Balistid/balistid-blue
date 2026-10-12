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
	"sync/atomic"
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
// trial's rate, and at a random moment in the load's second half writes "balistid-fail <H> <S>" to
// the console (S: what the writer had synced, ADR 0019) and resets with sysrq b, or kills the writer
// and writes "balistid-killed". After a reset
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
	self, err := os.Executable()
	if err != nil {
		return fail("own path: " + err.Error())
	}
	child := exec.CommandContext(ctx, self, writerArg, ms(tr.Load.Writer.Hold), ms(tr.Load.Writer.Sync)) //nolint:gosec // our own binary, values from the table
	pipe, err := child.StdinPipe()
	if err != nil {
		return fail("writer pipe: " + err.Error())
	}
	syncs, err := child.StdoutPipe()
	if err != nil {
		return fail("writer pipe: " + err.Error())
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return fail("writer: " + err.Error())
	}
	// synced follows the highest number the writer had written before its last fsync returned; a
	// broken report is the writer's failure, not a slow sync.
	var synced atomic.Uint64
	var reportErr atomic.Bool
	go func() {
		var b [rangeguest.RecordSize]byte
		for {
			if _, err := io.ReadFull(syncs, b[:]); err != nil {
				reportErr.Store(!errors.Is(err, io.EOF))
				return
			}
			synced.Store(binary.LittleEndian.Uint64(b[:]))
		}
	}()
	waited := make(chan struct{})
	go func() { _ = child.Wait(); close(waited) }()

	// One epoch for the load, the failure moment and the stop-sync moment (ADR 0020).
	start := time.Now()
	failAt := start.Add(span/2 + time.Duration(extra.Int64()))
	stopAt, stopped := failAt.Add(-tr.Load.Writer.LastSync), tr.Load.Writer.LastSync == 0
	var hand rangeguest.Handover
	_, _, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, func(seq uint64) error {
		now := time.Now()
		if !now.Before(failAt) {
			return errFailNow
		}
		if !stopped && !now.Before(stopAt) {
			if _, err := pipe.Write(binary.LittleEndian.AppendUint64(nil, rangeguest.StopSyncing)); err != nil {
				return fmt.Errorf("stop sync: %w", err)
			}
			stopped = true
		}
		if _, err := pipe.Write(binary.LittleEndian.AppendUint64(nil, seq)); err != nil {
			return fmt.Errorf("hand over: %w", err)
		}
		hand.Add(time.Now())
		return nil
	}, rangeguest.WallClock)
	switch {
	case !errors.Is(genErr, errFailNow):
		return fail(fmt.Sprintf("load ended before the failure: %v", genErr))
	case closed(waited) || reportErr.Load():
		return fail("the writer failed before the failure")
	}
	taken := time.Now()
	h := hand.H(taken)
	if err := mark(failMark(h, synced.Load())); err != nil {
		return fail(err.Error())
	}
	// H describes the moment it was taken: a mark that took longer to leave describes a failure
	// that did not happen then, so the trial reports instead of failing (ADR 0020).
	if err := markInTime(taken, time.Now()); err != nil {
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
	<-waited
	if err := killedBySIGKILL(child.ProcessState); err != nil {
		return fail(err.Error())
	}
	if err := mark(killMark); err != nil {
		return fail(err.Error())
	}
	_ = pipe.Close()
	return r.stored()
}

// killedBySIGKILL is nil only for a process that SIGKILL ended: a writer that had already exited
// lost its records for another reason, which a kill trial must not count as its own.
func killedBySIGKILL(st *os.ProcessState) error {
	if st == nil {
		return errors.New("the writer has not ended")
	}
	if ws, ok := st.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		return fmt.Errorf("the writer ended as %s, not by SIGKILL", st)
	}
	return nil
}

// markInTime is nil when the fail mark left within MarkWindow of the moment H was taken.
func markInTime(taken, left time.Time) error {
	if late := left.Sub(taken); late > rangevm.MarkWindow {
		return fmt.Errorf("the fail mark took %s to leave", late)
	}
	return nil
}

func closed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
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

// writerMain is the measured writer's process: hold and sync in milliseconds, numbers on stdin (0:
// stop syncing), records appended to the numbers file.
func writerMain(args []string) error {
	if len(args) != 2 {
		return errors.New("want hold and sync in milliseconds")
	}
	var v [2]uint64
	for i, a := range args {
		n, err := strconv.ParseUint(a, 10, 63)
		if err != nil {
			return fmt.Errorf("argument %d: not a number", i+1)
		}
		v[i] = n
	}
	pol := rangeguest.Policy{Hold: time.Duration(v[0]) * time.Millisecond, Sync: time.Duration(v[1]) * time.Millisecond} //nolint:gosec // parsed into 63 bits
	f, err := os.OpenFile(numbersFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("numbers file: %w", err)
	}
	defer f.Close() //nolint:errcheck // synced by ServeWriter
	if err := rangeguest.ServeWriter(os.Stdin, rangeguest.NewWriter(f, pol, rangeguest.WallClock), os.Stdout); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func mountScratch() error {
	if err := os.MkdirAll(scratchMount, 0o700); err != nil {
		return fmt.Errorf("mount point: %w", err)
	}
	// Only an fsync puts data on the scratch disk: no journal commit or flusher thread may write it
	// earlier, so what a control did not sync is lost for certain (ADR 0020).
	for name, value := range map[string]string{"dirty_writeback_centisecs": "0", "dirty_expire_centisecs": "360000"} {
		if err := os.WriteFile("/proc/sys/vm/"+name, []byte(value), 0); err != nil {
			return fmt.Errorf("vm.%s: %w", name, err)
		}
	}
	if err := syscall.Mount(scratchDev, scratchMount, "ext4", 0, "commit=300"); err != nil {
		return fmt.Errorf("mount scratch: %w", err)
	}
	return nil
}

// tcsbrk is TCSBRK (asm-generic/ioctls.h); with argument 1 it is tcdrain(3).
const tcsbrk = 0x5409

// mark writes text straight to the serial console and waits until the UART has sent it, so a
// sysrq b right after cannot cut it short.
func mark(text string) error {
	f, err := os.OpenFile(consoleDev, os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}
	_, werr := f.WriteString(text)
	var drain error
	for {
		// The writer child's SIGCHLD after a kill interrupts the drain, which the kernel does not
		// restart: retry, or the mark could be cut short.
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tcsbrk, 1)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			drain = fmt.Errorf("drain console: %w", errno)
		}
		break
	}
	return errors.Join(werr, drain, f.Close())
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

// The marks start on a line of their own: the console's last line may be a login prompt without an
// end (ADR 0019 point 3 for S).
const killMark = "\nbalistid-killed\n"

func failMark(h, synced uint64) string { return fmt.Sprintf("\nbalistid-fail %d %d\n", h, synced) }
