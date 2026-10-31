package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

const (
	// freezeFor holds the store's filesystem frozen: under the collector's WatchdogSec (10 s), so the watchdog
	// does not restart it and turn the queue's loss into a shutdown's.
	freezeFor = 6 * time.Second
	// bigArg is an exec argument near MAX_ARG_STRLEN (128 KiB); bigArgs of them make a record of about 1.2 MB,
	// under record_max_kib (2 MiB, stored whole), so a few dozen execs fill the collector's 64 MiB queue.
	bigArg     = 100 << 10
	bigArgs    = 12
	fillFile   = scratchMount + "/fill"
	kernelWait = 75 * time.Second
	// lossWait is how long after the injection a loss trial waits for the alert: lossAlarm's 65 s and a margin;
	// checkpointWait covers the ledger's next 5 s checkpoint after it.
	lossWait       = 80 * time.Second
	checkpointWait = 6 * time.Second
	// fiFreeze and fiThaw are FIFREEZE and FITHAW, _IOWR('X', 119 and 120, int): ioctls, which no audit rule records,
	// so a thaw never waits on the backlog the burst filled, as an exec of fsfreeze would.
	fiFreeze = 0xc0045877
	fiThaw   = 0xc0045878
)

// runLoss runs loss trial tr (ADR 0036, point 4): with the watcher started through the sink and the log growing,
// it injects tr's cause, proves it, and reports the ledger's entry of it and the alert at the sink.
func runLoss(ctx context.Context, tr rangejob.Trial, r *report) error {
	keys, err := rangeKeys()
	if err != nil {
		return r.fail(err.Error())
	}
	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	var cw cosignWatch
	go cw.run(wctx, keys)
	lctx, stopLoad := context.WithCancel(ctx)
	defer stopLoad()
	go lightLoad(lctx)
	if why := alarmReady(ctx, &cw); why != "" {
		return r.fail(why)
	}
	match := lossMatch(tr.Inject)
	prior, err := priorEntry(ctx, match)
	if err != nil {
		return r.fail(err.Error())
	}
	auditLost := func() string { return valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]) }
	restarts := func() string {
		return valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "NRestarts", collectorUnitName)))
	}
	lostBefore, restartsBefore := auditLost(), restarts()
	from, err := uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	proof, end := injectLoss(ctx, tr.Inject)
	if end == 0 {
		if end, err = uptime(); err != nil {
			return r.fail(err.Error())
		}
	}
	if err := waitLoss(ctx, tr, from, end); err != nil {
		return r.fail(err.Error())
	}
	stopLoad()
	entryFact := "no new entry of the cause"
	if at, err := priorEntry(ctx, match); err != nil {
		entryFact = "error: " + err.Error()
	} else if at > prior {
		entryFact = "yes"
	} else {
		entryFact += otherLoss(ctx, prior)
	}
	posts, refused, err := readSink()
	if err != nil {
		return r.fail(err.Error())
	}
	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	r.add(rangevm.FactInject, proof)
	r.add(rangevm.FactInjectMS, ms(from))
	r.add(rangevm.FactInjectEndMS, ms(end))
	r.add(rangevm.FactLossEntry, entryFact)
	r.add(rangevm.FactPosts, lossPostsFact(tr, posts, from))
	r.add(rangevm.FactRefused, strconv.Itoa(refused))
	r.add(rangevm.FactPiActive, valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", piUnit))))
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, auditLost())
	r.add(rangevm.FactOverflowAfter, freshOverflow(ctx))
	r.add(rangevm.FactCollectorRestarts, restartsBefore+" "+restarts())
	return r.send(r.facts)
}

// lossPostsFact is loss trial tr's posts after its injection at from; the control's are all since the watcher's
// start, as an alert while it warms up is a false alarm too.
func lossPostsFact(tr rangejob.Trial, posts []rangevm.Post, from time.Duration) string {
	if tr.Inject == rangejob.InjectNone {
		return postsFact(posts, 0)
	}
	return postsFact(posts, uint64(from.Milliseconds())) //nolint:gosec // uptime is positive
}

// waitLoss waits until the alert the judge takes for tr's loss reached the sink and a checkpoint more has been
// published, so the ledger's entry is in the log the guest then reads, or until lossWait after the injection; the
// control waits it out. A clock that cannot be read is an error.
func waitLoss(ctx context.Context, tr rangejob.Trial, from, end time.Duration) error {
	for deadline := end + lossWait; ; {
		posts, _, _ := readSink()
		now, err := uptime()
		seen := firstAfter(posts, "loss", from) || tr.Inject == rangejob.InjectStore && firstAfter(posts, "unknown", from)
		switch {
		case err != nil:
			return err
		case tr.Inject != rangejob.InjectNone && seen:
			pause(ctx, checkpointWait)
			return nil
		case now > deadline || !pause(ctx, time.Second):
			return nil
		}
	}
}

// lossMatch is which ledger entries an injection's loss makes: a loss of the queue's stage, of the cap's (a
// full filesystem), of the store's or the store's UNKNOWN; nil for a case whose loss no detector reports.
func lossMatch(inject string) func(entry.Body) bool {
	stage := func(s entry.Stage) func(entry.Body) bool {
		return func(b entry.Body) bool { l, ok := b.(entry.Loss); return ok && l.Stage == s }
	}
	switch inject {
	case rangejob.InjectQueue:
		return stage(entry.StageQueue)
	case rangejob.InjectFullFS:
		return stage(entry.StageCap)
	case rangejob.InjectStore:
		return func(b entry.Body) bool {
			h, ok := b.(entry.Health)
			return stage(entry.StageStore)(b) || ok && h.State == entry.StateUnknown && h.Reason == entry.ReasonStoreDown
		}
	}
	return func(entry.Body) bool { return false }
}

// priorEntry is the index of the log's last entry match takes, -1 when none does.
func priorEntry(ctx context.Context, match func(entry.Body) bool) (int64, error) {
	keys, err := rangeKeys()
	if err != nil {
		return 0, err
	}
	at, err := lastEntry(ctx, ledgerLog, keys.Log, match)
	switch {
	case errors.Is(err, errNoAnnouncement):
		return -1, nil
	case err != nil:
		return 0, err
	}
	return int64(at), nil //nolint:gosec // a log index is far below 2^63
}

// otherLoss says what the log holds instead of the cause's entry: its last loss of any stage and its last health
// with unstored records, which the Pi alerts as a loss too, beside the cause's last entry before the injection,
// and the collector's last journaled store failure, which tells where the store met the full filesystem.
func otherLoss(ctx context.Context, prior int64) string {
	var loss entry.Loss
	var health entry.Health
	lossAt, err := priorEntry(ctx, func(b entry.Body) bool {
		l, ok := b.(entry.Loss)
		if ok {
			loss = l
		}
		return ok
	})
	if err != nil {
		return "; the log's losses: error: " + err.Error()
	}
	healthAt, err := priorEntry(ctx, func(b entry.Body) bool {
		h, ok := b.(entry.Health)
		if ok && h.Unstored > 0 {
			health = h
		}
		return ok && h.Unstored > 0
	})
	if err != nil {
		return "; the log's health: error: " + err.Error()
	}
	failed := output(ctx, "/usr/bin/journalctl", "-b", "-u", collectorUnitName, "-o", "cat", "--no-pager", "-g", "store failed", "-n", "1")
	if _, after, ok := strings.Cut(failed, "reason="); ok {
		failed = "store failed: reason=" + strings.TrimSpace(after)
	} else {
		failed = "no store failure journaled"
	}
	return fmt.Sprintf("; loss %d s%d r%d; unstored health %d s%d r%d u%d; prior %d; %.140s", lossAt, loss.Stage, loss.Records,
		healthAt, health.State, health.Reason, health.Unstored, prior, failed)
}

// injectLoss injects a loss cause and returns "ok" with its proof held, else why not, and when it ended if the
// injection knows that better than its return (the queue's thaw), else 0.
func injectLoss(ctx context.Context, inject string) (string, time.Duration) {
	var err error
	var end time.Duration
	switch inject {
	case rangejob.InjectQueue:
		end, err = freezeStore(ctx)
	case rangejob.InjectFullFS:
		err = fillScratch()
	case rangejob.InjectStore:
		err = failStore()
	case rangejob.InjectKernel:
		err = stopAuditd(ctx)
	case rangejob.InjectDispatcher:
		if _, after, _, _ := overflow(ctx, laurelPID()); after != "yes" {
			err = fmt.Errorf("the plugin queue reports overflow %q", after)
		}
	case rangejob.InjectNone:
	default:
		err = fmt.Errorf("no injection %q", inject)
	}
	if err != nil {
		return "error: " + err.Error(), end
	}
	return "ok", end
}

// freezeStore freezes the store's filesystem for freezeFor under execs with large arguments, so the collector's
// writer blocks and its queue fills; the proof is the freeze and the thaw both done, and it returns the thaw's
// uptime, where the injection ends.
func freezeStore(ctx context.Context) (time.Duration, error) {
	args := make([]string, bigArgs)
	for i := range args {
		args[i] = strings.Repeat("q", bigArg)
	}
	burst, stop := context.WithTimeout(ctx, freezeFor+2*time.Second)
	defer stop()
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxChildren)
	wg.Go(func() {
		for burst.Err() == nil {
			sem <- struct{}{}
			wg.Go(func() {
				defer func() { <-sem }()
				_ = exec.CommandContext(burst, "/usr/bin/true", args...).Run() //nolint:gosec // our own fixed arguments
			})
		}
	})
	defer func() { stop(); wg.Wait() }()
	if err := systemctl(ctx, "is-active", collectorUnitName); err != nil {
		return 0, err
	}
	d, err := os.OpenFile(scratchMount, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", scratchMount, err)
	}
	defer d.Close() //nolint:errcheck // read-only
	if err := unix.IoctlSetInt(int(d.Fd()), fiFreeze, 0); err != nil {
		return 0, fmt.Errorf("FIFREEZE: %w", err)
	}
	pause(ctx, freezeFor)
	thawErr := unix.IoctlSetInt(int(d.Fd()), fiThaw, 0)
	end, err := uptime()
	switch {
	case thawErr != nil:
		return 0, fmt.Errorf("FITHAW: %w", thawErr)
	case err != nil:
		return 0, err
	}
	return end, nil
}

// fillScratch fills the scratch filesystem outside the store, so the store meets a full filesystem; the proof
// is no block left for an unprivileged writer.
func fillScratch() error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(scratchMount, &st); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	f, err := os.OpenFile(fillFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("fill: %w", err)
	}
	defer f.Close()                                                                         //nolint:errcheck // written by fallocate, nothing to flush
	if err := syscall.Fallocate(int(f.Fd()), 0, 0, int64(st.Bavail)*st.Bsize); err != nil { //nolint:gosec // block counts of a 512 MiB disk
		return fmt.Errorf("fallocate: %w", err)
	}
	if err := syscall.Statfs(scratchMount, &st); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	if left := st.Bavail * uint64(st.Bsize); left > 1<<20 { //nolint:gosec // as above
		return fmt.Errorf("%d bytes still free", left)
	}
	return nil
}

// ext4Shutdown is EXT4_IOC_SHUTDOWN, _IOR('X', 125, __u32), and ext4NoLogFlush its flag that drops the
// journal: the filesystem fails every later read and write, as a dying disk under the store would.
const (
	ext4Shutdown   = 0x8004587d
	ext4NoLogFlush = 2
	shutdownProbe  = scratchMount + "/probe"
)

// failStore shuts the store's filesystem down, so its writes fail; the proof is a write there refused after it.
// chattr +i was tried first and does not stop writes to the files the store already holds open.
func failStore() error {
	d, err := os.OpenFile(scratchMount, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", scratchMount, err)
	}
	defer d.Close() //nolint:errcheck // read-only
	if err := unix.IoctlSetPointerInt(int(d.Fd()), ext4Shutdown, ext4NoLogFlush); err != nil {
		return fmt.Errorf("EXT4_IOC_SHUTDOWN: %w", err)
	}
	if err := os.WriteFile(shutdownProbe, []byte("x"), 0o600); err == nil {
		return errors.New("a write to the store's filesystem still succeeds after its shutdown")
	}
	return nil
}

// stopAuditd stops auditd and floods syscall records until the kernel counts a loss, then resumes it; the proof
// is the lost counter moving. No exec while auditd stands: each would wait out the backlog.
func stopAuditd(ctx context.Context) error {
	before := rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]
	pid, err := strconv.Atoi(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "MainPID", "auditd.service")))
	switch {
	case err != nil:
		return fmt.Errorf("auditd pid: %w", err)
	case pid <= 0:
		return errors.New("auditd has no main pid")
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP auditd: %w", err)
	}
	flood, stop := context.WithTimeout(ctx, kernelWait)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for seq := uint64(0); flood.Err() == nil; seq++ {
				_ = rangeguest.Peek(seq)
			}
		})
	}
	<-flood.Done()
	stop()
	err = syscall.Kill(pid, syscall.SIGCONT)
	wg.Wait()
	if err != nil {
		return fmt.Errorf("SIGCONT auditd: %w", err)
	}
	if after := rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]; after == before || after == "" {
		return fmt.Errorf("kernel lost %q before, %q after", before, after)
	}
	return nil
}
