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
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// The file a failure trial's measured writer appends to, beside the collector's store on the scratch
// disk, the console its marks go to directly (the unit's own output goes through the journal first),
// and the sysrq trigger.
const (
	numbersFile  = scratchMount + "/numbers"
	consoleDev   = "/dev/ttyS0"
	sysrqTrigger = "/proc/sysrq-trigger"
	writerArg    = "writer"
)

var errFailNow = errors.New("failure moment reached")

// runFailure runs boot `boot` of failure trial tr (ADR 0018, point 3) on the scratch disk store-setup
// mounted. Boot 1, for a reset, reports its echo and reset_armed=yes before any load, so the host can
// boot again; it then hands numbers to the measured writer, a child process, at the trial's rate, and
// at a random moment in the load's second half writes "balistid-fail <H> <S>" to the console (S: what
// the writer had synced, ADR 0019) and resets with sysrq b, or kills the writer and writes
// "balistid-killed". After a reset boot 2 reports the superblock store-setup read before the mount.
// Both report what the file holds.
func runFailure(ctx context.Context, tr rangejob.Trial, boot int, r *report) error {
	add, fail := r.add, r.fail
	if !mounted(scratchMount) {
		return fail("scratch disk not mounted")
	}
	if boot == 2 {
		if err := r.superblock(superblockFile); err != nil {
			return fail("superblock: " + err.Error())
		}
		return r.stored(numbersFile)
	}
	if err := holdWriteback(); err != nil {
		return fail(err.Error())
	}
	if tr.Failure == rangejob.FailReset {
		add(rangevm.FactResetArmed, "yes")
		if err := write(r.facts); err != nil { // synced before the load: the host reads it after the reset
			return err
		}
	}
	return loadAndFail(ctx, tr, r, guestEnv)
}

// failEnv is what the load of a failure trial touches outside its process: the console the marks
// go to and how it is drained, the reset, the writer process and its numbers file, when the failure
// comes, and where the report goes. Tests replace it.
type failEnv struct {
	console   string
	drain     func(*os.File) error
	reset     func() error
	writer    func(ctx context.Context, args ...string) *exec.Cmd
	numbers   string
	failAfter func(span time.Duration) (time.Duration, error)
}

var guestEnv = failEnv{
	console: consoleDev,
	drain:   tcdrain,
	reset:   func() error { return os.WriteFile(sysrqTrigger, []byte("b"), 0) },
	writer: func(ctx context.Context, args ...string) *exec.Cmd {
		self, _ := os.Executable()
		return exec.CommandContext(ctx, self, append([]string{writerArg}, args...)...) //nolint:gosec // our own binary
	},
	numbers: numbersFile,
	failAfter: func(span time.Duration) (time.Duration, error) {
		extra, err := rand.Int(rand.Reader, big.NewInt(int64(span/2)))
		if err != nil {
			return 0, fmt.Errorf("random failure moment: %w", err)
		}
		return span/2 + time.Duration(extra.Int64()), nil
	},
}

// freezeWait bounds how long the writer may take to answer Freeze.
const freezeWait = time.Second

// loadAndFail hands numbers to the writer until the failure moment, freezes the writer so its synced
// state is final, takes H, writes the fail mark with H and S, and fails: a reset, or SIGKILL of the
// writer and the kill mark (ADR 0018 point 3, ADR 0020).
func loadAndFail(ctx context.Context, tr rangejob.Trial, r *report, env failEnv) error {
	fail := r.fail
	span := time.Duration(tr.Load.Seconds) * time.Second
	after, err := env.failAfter(span)
	if err != nil {
		return fail(err.Error())
	}
	child := env.writer(ctx, ms(tr.Load.Writer.Hold), ms(tr.Load.Writer.Sync), env.numbers)
	pipe, err := child.StdinPipe()
	if err != nil {
		return fail("writer pipe: " + err.Error())
	}
	reports, err := child.StdoutPipe()
	if err != nil {
		return fail("writer pipe: " + err.Error())
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return fail("writer: " + err.Error())
	}
	// The writer reports S after each fsync, and answers Freeze with the marker and its final S. A
	// broken report is the writer's failure, not a slow sync.
	var reportErr atomic.Bool
	var finalS atomic.Uint64
	frozen := make(chan struct{})
	go func() {
		var b [rangeguest.RecordSize]byte
		for {
			if _, err := io.ReadFull(reports, b[:]); err != nil {
				reportErr.Store(!errors.Is(err, io.EOF))
				return
			}
			if binary.LittleEndian.Uint64(b[:]) != rangeguest.Freeze {
				continue
			}
			if _, err := io.ReadFull(reports, b[:]); err != nil {
				reportErr.Store(true)
				return
			}
			finalS.Store(binary.LittleEndian.Uint64(b[:]))
			close(frozen)
		}
	}()
	waited := make(chan struct{})
	go func() { _ = child.Wait(); close(waited) }()
	send := func(n uint64) error {
		_, err := pipe.Write(binary.LittleEndian.AppendUint64(nil, n))
		return err //nolint:wrapcheck // callers say which message
	}

	// One epoch for the load, the failure moment and the stop-sync moment (ADR 0020).
	start := time.Now()
	failAt := start.Add(after)
	stopAt, stopped := failAt.Add(-tr.Load.Writer.LastSync), tr.Load.Writer.LastSync == 0
	var hand rangeguest.Handover
	_, _, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, func(seq uint64) error {
		now := time.Now()
		if !now.Before(failAt) {
			return errFailNow
		}
		if !stopped && !now.Before(stopAt) {
			if err := send(rangeguest.StopSyncing); err != nil {
				return fmt.Errorf("stop sync: %w", err)
			}
			stopped = true
		}
		if err := send(seq); err != nil {
			return fmt.Errorf("hand over: %w", err)
		}
		hand.Add(time.Now())
		return nil
	}, rangeguest.WallClock)
	if !errors.Is(genErr, errFailNow) {
		return fail(fmt.Sprintf("load ended before the failure: %v", genErr))
	}
	// Freeze: from the answer on the writer writes and syncs nothing, so S is exactly what an fsync
	// covered when the failure comes, and no writer I/O can fail during the mark.
	if err := send(rangeguest.Freeze); err != nil {
		return fail("freeze writer: " + err.Error())
	}
	select {
	case <-frozen:
	case <-waited:
		return fail("the writer ended before it froze")
	case <-time.After(freezeWait):
		return fail("the writer did not freeze")
	}
	taken := time.Now()
	h := hand.H(taken)
	if err := mark(env, failMark(h, finalS.Load())); err != nil {
		return fail(err.Error())
	}
	if err := markInTime(taken, time.Now()); err != nil {
		return fail(err.Error())
	}
	if closed(waited) || reportErr.Load() {
		return fail("the writer ended before the failure")
	}
	if tr.Failure == rangejob.FailReset {
		// Reboot at once, without syncing or unmounting; with -no-reboot QEMU exits.
		_ = env.reset()
		return fail("sysrq b did not reset the guest")
	}
	if err := child.Process.Kill(); err != nil {
		return fail("kill writer: " + err.Error())
	}
	<-waited
	if err := killedBySIGKILL(child.ProcessState); err != nil {
		return fail(err.Error())
	}
	if err := mark(env, killMark); err != nil {
		return fail(err.Error())
	}
	_ = pipe.Close()
	return r.stored(env.numbers)
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
type report struct {
	facts []fact
	send  func([]fact) error
}

func (r *report) add(name, value string) { r.facts = append(r.facts, fact{name, value}) }

// fail reports why the guest could not run the trial, which the host judges INVALID.
func (r *report) fail(why string) error {
	r.add(rangevm.FactTrialError, why)
	return r.send(r.facts)
}

// stored adds what the numbers file holds and writes the report.
func (r *report) stored(numbers string) error {
	data, err := os.ReadFile(numbers) //nolint:gosec // the trial's own numbers file
	if err != nil {
		return r.fail("numbers: " + err.Error())
	}
	prefix, count := rangeguest.StoredPrefix(data)
	r.add(rangevm.FactStoredPrefix, strconv.FormatUint(prefix, 10))
	r.add(rangevm.FactStoredCount, strconv.FormatUint(count, 10))
	return r.send(r.facts)
}

// writerMain is the measured writer's process: hold and sync in milliseconds and the numbers file;
// numbers on stdin (StopSyncing, Freeze), records appended to the file.
func writerMain(args []string) error {
	if len(args) != 3 || !filepath.IsAbs(args[2]) {
		return errors.New("want hold and sync in milliseconds and the numbers file")
	}
	var v [2]uint64
	for i, a := range args[:2] {
		n, err := strconv.ParseUint(a, 10, 63)
		if err != nil {
			return fmt.Errorf("argument %d: not a number", i+1)
		}
		v[i] = n
	}
	pol := rangeguest.Policy{Hold: time.Duration(v[0]) * time.Millisecond, Sync: time.Duration(v[1]) * time.Millisecond} //nolint:gosec // parsed into 63 bits
	f, err := os.OpenFile(args[2], os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)                                           //nolint:gosec // an absolute path the guest itself passes
	if err != nil {
		return fmt.Errorf("numbers file: %w", err)
	}
	defer f.Close() //nolint:errcheck // synced by ServeWriter
	if err := rangeguest.ServeWriter(os.Stdin, rangeguest.NewWriter(f, pol, rangeguest.WallClock), os.Stdout); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// holdWriteback stops the flusher threads: with commit=300 on the mount, only an fsync puts the
// measured writer's data on the scratch disk, so what a control did not sync is lost for certain
// (ADR 0020).
func holdWriteback() error {
	for name, value := range map[string]string{"dirty_writeback_centisecs": "0", "dirty_expire_centisecs": "360000"} {
		if err := os.WriteFile("/proc/sys/vm/"+name, []byte(value), 0); err != nil {
			return fmt.Errorf("vm.%s: %w", name, err)
		}
	}
	return nil
}

// superblock adds the two superblock facts store-setup wrote to path, exactly those and in order.
func (r *report) superblock(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // store-setup's file in /run
	if err != nil {
		return err //nolint:wrapcheck // the caller names it
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	for i, name := range []string{rangevm.FactScratchJournal, rangevm.FactScratchRecovery} {
		value, ok := "", false
		if i < len(lines) {
			value, ok = strings.CutPrefix(lines[i], name+" ")
		}
		if len(lines) != 2 || !ok || value != "yes" && value != "no" {
			return fmt.Errorf("%s does not hold the two superblock facts", path)
		}
		r.add(name, value)
	}
	return nil
}

// tcsbrk is TCSBRK (asm-generic/ioctls.h); with argument 1 it is tcdrain(3).
const tcsbrk = 0x5409

// mark appends text to the console and waits until it has been sent, so a sysrq b right after
// cannot cut it short.
func mark(env failEnv, text string) error {
	f, err := os.OpenFile(env.console, os.O_WRONLY|os.O_APPEND|syscall.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("console: %w", err)
	}
	_, werr := f.WriteString(text)
	return errors.Join(werr, env.drain(f), f.Close())
}

// tcdrain waits until the UART has sent everything written to f.
func tcdrain(f *os.File) error {
	for {
		// The writer child's SIGCHLD after a kill interrupts the drain, which the kernel does not
		// restart: retry, or the mark could be cut short.
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tcsbrk, 1)
		switch errno {
		case 0:
			return nil
		case syscall.EINTR:
			continue
		}
		return fmt.Errorf("drain console: %w", errno)
	}
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
