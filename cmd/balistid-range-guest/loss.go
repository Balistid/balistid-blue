package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/auditstat"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const (
	// freezeFor holds the store's filesystem frozen: under the collector's WatchdogSec (10 s), so the watchdog
	// does not restart it and turn the queue's loss into a shutdown's.
	freezeFor = 6 * time.Second
	// bigArg is an exec argument near MAX_ARG_STRLEN (128 KiB); bigArgs of them make a record of about 1.2 MB,
	// under record_max_kib (2 MiB, stored whole), so a few dozen execs fill the collector's 64 MiB queue.
	bigArg   = 100 << 10
	bigArgs  = 12
	fillFile = scratchMount + "/fill"
	// fillSlack bounds what the fill leaves above a WAL: the store's admit slack (64 KiB), so the least a record
	// needs, a WAL, twice its size and that slack, is more than is left.
	fillSlack  = 64 << 10
	kernelWait = 75 * time.Second
	// lossWait is how long after the injection a loss trial waits for the alert: lossAlarm's 65 s and a margin;
	// checkpointWait covers the ledger's next 5 s checkpoint after it.
	lossWait       = 80 * time.Second
	checkpointWait = 6 * time.Second
	// fiFreeze and fiThaw are FIFREEZE and FITHAW, _IOWR('X', 119 and 120, int): ioctls, which no audit rule records,
	// so a thaw never waits on the backlog the burst filled, as an exec of fsfreeze would.
	fiFreeze = 0xc0045877
	fiThaw   = 0xc0045878
	// lostPoll is how often a kernel trial asks the kernel for lost (ADR 0039, point 4); stateEvery how often a
	// dispatcher trial reads auditd's state file, which auditd rewrites every report_interval (5 s).
	lostPoll     = 100 * time.Millisecond
	stateEvery   = 200 * time.Millisecond
	overflowWait = 60 * time.Second
	// freshStateWait covers two of auditd's state writes; stateChanged is a read the file changed under.
	freshStateWait = 12 * time.Second
	stateChanged   = "changed"
)

// injected is what an injection did: its proof, "ok" or why not; its end when it knows that better than its
// return, else 0; the loss's bracket when the guest saw the loss itself, else zero (the injection's own); and a
// transient kernel trial's resume, in uptime and in the ledger's clock. finish ends what the injection left
// running (a stopped auditd) before the trial reads the ledger, nil without.
type injected struct {
	proof         string
	end, from, to time.Duration
	resumeAt      time.Duration
	resumeNs      int64
	finish        func()
}

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
	overflowBefore := rangeguest.OverflowDetected(readTrim(auditdState))
	from, err := uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	fromNs := time.Now().UnixNano() // after the bracket's start, in the clock the ledger stamps entries with (internal/anchor)
	inj := injectLoss(ctx, tr.Inject)
	if inj.end == 0 {
		if inj.end, err = uptime(); err != nil {
			return r.fail(err.Error())
		}
	}
	if inj.to == 0 {
		inj.from, inj.to = from, inj.end
	}
	err = waitLoss(ctx, tr, from, inj.to)
	if inj.finish != nil {
		inj.finish()
	}
	if err != nil {
		return r.fail(err.Error())
	}
	okAfter := "-"
	if tr.Inject == rangejob.InjectKernelTransient {
		okAfter = "none"
		if inj.resumeNs != 0 && waitUptime(ctx, inj.resumeAt+rangevm.LossAlarm+checkpointWait) {
			okAfter = okAfterResume(ctx, inj.resumeNs)
		}
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
	r.add(rangevm.FactInject, inj.proof)
	r.add(rangevm.FactInjectMS, ms(from))
	r.add(rangevm.FactInjectEndMS, ms(inj.end))
	r.add(rangevm.FactLossFromMS, ms(inj.from))
	r.add(rangevm.FactLossToMS, ms(inj.to))
	r.add(rangevm.FactLossEntry, entryFact)
	r.add(rangevm.FactPosts, lossPostsFact(tr, posts, from))
	r.add(rangevm.FactRefused, strconv.Itoa(refused))
	r.add(rangevm.FactPiActive, valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", piUnit))))
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, auditLost())
	r.add(rangevm.FactOverflowBefore, overflowBefore)
	r.add(rangevm.FactOverflowAfter, freshOverflow(ctx))
	r.add(rangevm.FactCollectorRestarts, restartsBefore+" "+restarts())
	r.add(rangevm.FactFirstUnknown, firstUnknown(ctx, fromNs))
	r.add(rangevm.FactOKAfterResume, okAfter)
	return r.send(r.facts)
}

// waitUptime waits until uptime at, false when ctx ended or the clock could not be read first.
func waitUptime(ctx context.Context, at time.Duration) bool {
	for {
		now, err := uptime()
		switch {
		case err != nil:
			return false
		case now >= at:
			return true
		case !pause(ctx, min(at-now, time.Second)):
			return false
		}
	}
}

// okAfterResume is a transient kernel trial's FactOKAfterResume for auditd resumed at resumeNs, in the ledger's
// clock.
func okAfterResume(ctx context.Context, resumeNs int64) string {
	keys, err := rangeKeys()
	if err != nil {
		return "error: " + err.Error()
	}
	return okAfterIn(ctx, ledgerLog, keys.Log, resumeNs)
}

// okAfterIn is okAfterResume for the log at root under v: "0" when the last health before resumeNs was OK, else
// the ms to the first health OK from resumeNs on, "none" without one.
func okAfterIn(ctx context.Context, root string, v note.Verifier, resumeNs int64) string {
	okAtResume, first := false, int64(-1)
	_, err := eachEntry(ctx, root, v, func(_ uint64, e entry.Entry) {
		h, ok := e.Body.(entry.Health)
		switch {
		case !ok:
		case e.At < resumeNs:
			okAtResume = h.State == entry.StateOK
		case h.State == entry.StateOK && first < 0:
			first = e.At - resumeNs
		}
	})
	switch {
	case err != nil:
		return "error: " + err.Error()
	case okAtResume:
		return "0"
	case first < 0:
		return "none"
	}
	return strconv.FormatInt(first/int64(time.Millisecond), 10)
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
		tag := rangevm.LossTag(tr.Inject)
		seen := tag != "" && firstAfter(posts, tag, from) || tr.Inject == rangejob.InjectStore && firstAfter(posts, "unknown", from)
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
// full filesystem), of the store's or the store's UNKNOWN, of the kernel's or of the dispatcher's (ADR 0038); none
// for the control.
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
	case rangejob.InjectKernelTransient, rangejob.InjectKernelSustained:
		return stage(entry.StageKernel)
	case rangejob.InjectDispatcher:
		return stage(entry.StageDispatcher)
	}
	return func(entry.Body) bool { return false }
}

// firstUnknown attributes a store trial's unknown alert by the ledger's own stamps (ADR 0039, point 3): "before N"
// when the ledger logged an UNKNOWN within rangevm.LossAlarm before fromNs, whose alert may land after the
// injection, else the reason of its first UNKNOWN from fromNs on, "none" without one.
func firstUnknown(ctx context.Context, fromNs int64) string {
	keys, err := rangeKeys()
	if err != nil {
		return "error: " + err.Error()
	}
	return firstUnknownIn(ctx, ledgerLog, keys.Log, fromNs)
}

// firstUnknownIn is firstUnknown for the log at root under v.
func firstUnknownIn(ctx context.Context, root string, v note.Verifier, fromNs int64) string {
	before, after := "", "none"
	_, err := eachEntry(ctx, root, v, func(_ uint64, e entry.Entry) {
		h, ok := e.Body.(entry.Health)
		switch {
		case !ok || h.State != entry.StateUnknown:
		case e.At < fromNs && e.At >= fromNs-rangevm.LossAlarm.Nanoseconds():
			before = "before " + strconv.Itoa(int(h.Reason))
		case e.At >= fromNs && after == "none":
			after = strconv.Itoa(int(h.Reason))
		}
	})
	switch {
	case err != nil:
		return "error: " + err.Error()
	case before != "":
		return before
	}
	return after
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
// with unstored records, which the Pi alerts as lossunstored, beside the cause's last entry before the injection,
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
	journal := output(ctx, "/usr/bin/journalctl", "-b", "-u", collectorUnitName, "-o", "cat", "--no-pager", "-n", "400")
	failed := "no store failure in the journal's last 400 lines"
	if journal == "" {
		failed = "the collector's journal could not be read"
	}
	for line := range strings.Lines(journal) {
		// the collector journals JSON: its last store failure, of an append, flush, close or open, from its message on
		if _, after, ok := strings.Cut(line, `"msg":"store `); ok && strings.Contains(after, "failed") {
			failed = "store " + strings.TrimSpace(after)
		}
	}
	return fmt.Sprintf("; loss %d s%d r%d; unstored health %d s%d r%d u%d; prior %d; %.140s", lossAt, loss.Stage, loss.Records,
		healthAt, health.State, health.Reason, health.Unstored, prior, failed)
}

// injectLoss injects a loss cause; its proof is "ok" when held, else why not.
func injectLoss(ctx context.Context, inject string) injected {
	var err error
	var inj injected
	switch inject {
	case rangejob.InjectQueue:
		inj.end, err = freezeStore(ctx)
	case rangejob.InjectFullFS:
		err = fillScratch()
	case rangejob.InjectStore:
		err = failStore()
	case rangejob.InjectKernelTransient, rangejob.InjectKernelSustained:
		inj, err = stopAuditd(ctx, inject == rangejob.InjectKernelSustained)
	case rangejob.InjectDispatcher:
		inj.from, inj.to, err = overflowDispatcher(ctx)
	case rangejob.InjectNone:
	default:
		err = fmt.Errorf("no injection %q", inject)
	}
	inj.proof = "ok"
	if err != nil {
		inj.proof = "error: " + err.Error()
	}
	return inj
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

// fillScratch fills the scratch filesystem outside the store, so the store meets a full filesystem: no room for
// its next record. The proof is fillLeft's, for an unprivileged writer.
func fillScratch() error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(scratchMount, &st); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	f, err := os.OpenFile(fillFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("fill: %w", err)
	}
	defer f.Close() //nolint:errcheck // written by fallocate, nothing to flush
	// A whole WAL stays free: the store admitted its writes in flight against it, so they finish, and its next
	// record, which needs a WAL more, drops at the free-space cap; a fill to the last block races those writes.
	fill := int64(st.Bavail)*st.Bsize - shard.WALMaxBytes //nolint:gosec // block counts of a 512 MiB disk
	if fill <= 0 {
		return fmt.Errorf("%d bytes free, less than a WAL", int64(st.Bavail)*st.Bsize) //nolint:gosec // as above
	}
	if err := syscall.Fallocate(int(f.Fd()), 0, 0, fill/st.Bsize*st.Bsize); err != nil {
		return fmt.Errorf("fallocate: %w", err)
	}
	if err := syscall.Statfs(scratchMount, &st); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	return fillLeft(int64(st.Bavail) * st.Bsize) //nolint:gosec // as above
}

// fillLeft proves a fill by what it left: a WAL at least, so the store's writes in flight finish, and less than a
// WAL and the admit slack, so its next record drops.
func fillLeft(left int64) error {
	switch {
	case left < shard.WALMaxBytes:
		return fmt.Errorf("%d bytes left, less than a WAL (%d): the fill raced the store's writes", left, shard.WALMaxBytes)
	case left >= shard.WALMaxBytes+fillSlack:
		return fmt.Errorf("%d bytes still free, a WAL is %d", left, shard.WALMaxBytes)
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

// stopAuditd stops auditd and floods syscall records until the kernel's lost rises, asked by AUDIT_GET every
// lostPoll, so no exec waits out the backlog while auditd stands. The bracket runs from the sending of the last read
// before the rise to the answer of the first after it. Transient resumes auditd at once; sustained leaves it
// stopped until finish, as the alert must come while it stands (ADR 0039, point 5).
func stopAuditd(ctx context.Context, sustained bool) (injected, error) {
	conn, err := auditstat.Dial()
	if err != nil {
		return injected{}, fmt.Errorf("lost: %w", err)
	}
	defer conn.Close() //nolint:errcheck // a netlink socket that only asked
	pid, err := strconv.Atoi(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "MainPID", "auditd.service")))
	switch {
	case err != nil:
		return injected{}, fmt.Errorf("auditd pid: %w", err)
	case pid <= 0:
		return injected{}, errors.New("auditd has no main pid")
	}
	last, err := uptime()
	if err != nil {
		return injected{}, err
	}
	base, err := conn.Status()
	if err != nil {
		return injected{}, fmt.Errorf("lost: %w", err)
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return injected{}, fmt.Errorf("SIGSTOP auditd: %w", err)
	}
	flood, stopFlood := context.WithTimeout(ctx, kernelWait)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for seq := uint64(0); flood.Err() == nil; seq++ {
				_ = rangeguest.Peek(seq)
			}
		})
	}
	resume := func() error {
		stopFlood()
		err := syscall.Kill(pid, syscall.SIGCONT)
		wg.Wait()
		if err != nil {
			return fmt.Errorf("SIGCONT auditd: %w", err)
		}
		return nil
	}
	rise, err := lostRise(flood, conn, base.Lost, &last)
	if err == nil && rise == 0 {
		err = fmt.Errorf("kernel lost stayed %d for %s", base.Lost, kernelWait)
	}
	if err != nil {
		return injected{}, errors.Join(err, resume())
	}
	inj := injected{end: rise, from: last, to: rise}
	if sustained {
		stopFlood()
		inj.finish = func() { _ = resume() } // the lost counter after it, read by exec, shows a failed resume
		return inj, nil
	}
	rerr := resume()
	inj.resumeNs = time.Now().UnixNano()
	if inj.resumeAt, err = uptime(); err != nil {
		return injected{}, errors.Join(err, rerr)
	}
	return inj, rerr
}

// lostRise asks conn every lostPoll until lost is no longer base, and returns the uptime of the answer that showed
// it, 0 when ctx ended first; *last becomes the uptime at which the last read before it was sent.
func lostRise(ctx context.Context, conn *auditstat.Conn, base uint32, last *time.Duration) (time.Duration, error) {
	for pause(ctx, lostPoll) {
		sent, err := uptime()
		if err != nil {
			return 0, err
		}
		s, err := conn.Status()
		if err != nil {
			return 0, fmt.Errorf("lost: %w", err)
		}
		got, err := uptime()
		if err != nil {
			return 0, err
		}
		if s.Lost != base {
			return got, nil
		}
		*last = sent
	}
	return 0, nil
}

// overflowDispatcher stops Laurel and execs until auditd's state file, read and never signalled, says its plugin
// queue overflowed, then resumes Laurel. It waits for a fresh "no" first, so the bracket, from the mtime of the
// last state file that read no to that of the first that read yes, starts near the injection.
func overflowDispatcher(ctx context.Context) (time.Duration, time.Duration, error) {
	first, err := readState()
	if err != nil {
		return 0, 0, err
	}
	no, err := freshState(ctx, first.at)
	if err != nil {
		return 0, 0, err
	}
	if no.value != "no" {
		return 0, 0, fmt.Errorf("the state file reads overflow %q before the injection", no.value)
	}
	pid, err := strconv.Atoi(laurelPID())
	if err != nil {
		return 0, 0, errors.New("no laurel process")
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return 0, 0, fmt.Errorf("SIGSTOP laurel: %w", err)
	}
	flood, stopFlood := context.WithTimeout(ctx, overflowWait)
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; i < floodMax && flood.Err() == nil; i++ {
			_ = exec.CommandContext(flood, "/usr/bin/true").Run()
		}
	})
	var yes time.Duration
	for yes == 0 && err == nil && pause(flood, stateEvery) {
		var st stateRead
		if st, err = readState(); err != nil || st.value == stateChanged || st.at == no.at {
			continue
		}
		switch st.value {
		case "no":
			no = st
		case "yes":
			yes = st.at
		default:
			err = fmt.Errorf("the state file reads overflow %q", st.value)
		}
	}
	stopFlood()
	wg.Wait()
	if cerr := syscall.Kill(pid, syscall.SIGCONT); cerr != nil {
		err = errors.Join(err, fmt.Errorf("SIGCONT laurel: %w", cerr))
	}
	switch {
	case err != nil:
		return 0, 0, err
	case yes == 0:
		return 0, 0, fmt.Errorf("no overflow in the state file within %s", overflowWait)
	}
	return no.at, yes, nil
}

// freshState waits for a whole state file other than the one of mtime at.
func freshState(ctx context.Context, at time.Duration) (stateRead, error) {
	for deadline := time.Now().Add(freshStateWait); time.Now().Before(deadline) && pause(ctx, stateEvery); {
		st, err := readState()
		if err != nil {
			return stateRead{}, err
		}
		if st.value != stateChanged && st.at != at {
			return st, nil
		}
	}
	return stateRead{}, errors.New("auditd wrote no fresh state file")
}

// stateRead is auditd's state file's overflow flag and its mtime in uptime.
type stateRead struct {
	value string
	at    time.Duration
}

// readState reads the state file and its mtime through one descriptor; a read the file changed under is
// stateChanged.
func readState() (stateRead, error) {
	f, err := os.OpenFile(auditdState, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return stateRead{}, fmt.Errorf("state file: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	before, err := f.Stat()
	if err != nil {
		return stateRead{}, fmt.Errorf("state file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return stateRead{}, fmt.Errorf("state file: %w", err)
	}
	after, err := f.Stat()
	switch {
	case err != nil:
		return stateRead{}, fmt.Errorf("state file: %w", err)
	case !after.ModTime().Equal(before.ModTime()):
		return stateRead{value: stateChanged}, nil
	}
	up, err := uptime()
	if err != nil {
		return stateRead{}, err
	}
	age := time.Since(after.ModTime())
	if age < 0 || age > up {
		return stateRead{}, fmt.Errorf("state file mtime %s from now", age)
	}
	return stateRead{value: rangeguest.OverflowDetected(string(data)), at: up - age}, nil
}
