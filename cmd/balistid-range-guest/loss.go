package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sys/unix"

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
	// under record_max_kib (2 MiB, stored whole). queueExecs of them overfill the range's 8 MiB queue twice, in
	// fewer kernel records than auditd's plugin queue holds, so the dispatcher cannot overflow even if Laurel
	// took none of them during the freeze.
	bigArg     = 100 << 10
	bigArgs    = 12
	queueExecs = 16
	// execveChunk is the kernel's MAX_EXECVE_AUDIT_LEN: an argument longer than it spans records of at most it.
	execveChunk = 7500
	fillFile    = scratchMount + "/fill"
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
	// lostPoll is how often a kernel trial reads the kernel's log; stateEvery how often a dispatcher trial reads
	// auditd's state file, which auditd rewrites every report_interval (5 s).
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
// running (a stopped auditd) before the trial reads the ledger, nil without; release runs it.
type injected struct {
	proof         string
	end, from, to time.Duration
	resumeAt      time.Duration
	resumeNs      int64
	finish        func() error
}

func (i injected) release() error {
	if i.finish == nil {
		return nil
	}
	return i.finish()
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
	stopDiag := diagState(ctx)
	inj := injectLoss(ctx, tr.Inject)
	diag("inject", inj.proof)
	if inj.end == 0 {
		if inj.end, err = uptime(); err != nil {
			return r.fail(errors.Join(err, inj.release()).Error())
		}
	}
	if inj.to == 0 {
		inj.from, inj.to = from, inj.end
	}
	if err := errors.Join(waitLoss(ctx, tr, from, inj.to), inj.release()); err != nil {
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
	stopDiag()
	diagFacts(r.facts)
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
	return okAfterIn(ctx, ledgerLog, keys.Log, resumeNs, rangevm.LossAlarm.Nanoseconds())
}

// okAfterIn is okAfterResume for the log at root under v: the ms from resumeNs to the start of the health OK in
// force window after it, "0" when that OK began before, "none" when the health then is not OK.
func okAfterIn(ctx context.Context, root string, v note.Verifier, resumeNs, window int64) string {
	state, start := entry.State(0), int64(0)
	_, err := eachEntry(ctx, root, v, func(_ uint64, e entry.Entry) {
		h, ok := e.Body.(entry.Health)
		if !ok || e.At > resumeNs+window {
			return
		}
		if h.State == entry.StateOK && state != entry.StateOK {
			start = e.At
		}
		state = h.State
	})
	switch {
	case err != nil:
		return "error: " + err.Error()
	case state != entry.StateOK:
		return "none"
	}
	return strconv.FormatInt(max(0, start-resumeNs)/int64(time.Millisecond), 10)
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

// freezeStore freezes the store's filesystem for freezeFor and execs queueExecs times with large arguments, one
// at a time, so the collector's writer blocks and its queue fills; the proof is the freeze, every exec and the
// thaw done, and it returns the thaw's uptime, where the injection ends.
func freezeStore(ctx context.Context) (time.Duration, error) {
	args := make([]string, bigArgs)
	for i := range args {
		args[i] = strings.Repeat("q", bigArg)
	}
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
	thawAt := time.Now().Add(freezeFor)
	burst, stop := context.WithDeadline(ctx, thawAt)
	var execErr error
	for i := 0; i < queueExecs && execErr == nil; i++ {
		if err := exec.CommandContext(burst, "/usr/bin/true", args...).Run(); err != nil { //nolint:gosec // our own fixed arguments
			execErr = fmt.Errorf("exec %d of %d: %w", i+1, queueExecs, err)
		}
	}
	stop()
	pause(ctx, time.Until(thawAt))
	thawErr := unix.IoctlSetInt(int(d.Fd()), fiThaw, 0)
	end, err := uptime()
	switch {
	case thawErr != nil:
		return 0, errors.Join(execErr, fmt.Errorf("FITHAW: %w", thawErr))
	case execErr != nil:
		return 0, execErr
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

// stopAuditd stops auditd and floods syscall records until the kernel logs its first lost record (no exec while
// auditd stands: each would wait out the backlog). The kernel's log, not AUDIT_GET, times it: audit_receive sleeps
// the sender of any audit request up to backlog_wait_time while the backlog is full. Two marks the guest writes
// there tie the kernel's clock to uptime. When printk's rate limit dropped the first count, the bracket starts where
// lost was last read as it was. Transient resumes auditd at once; sustained leaves it stopped until finish, as the
// alert must come while it stands (ADR 0039, point 5; ADR 0045).
func stopAuditd(ctx context.Context, sustained bool) (injected, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "MainPID", "auditd.service")))
	switch {
	case err != nil:
		return injected{}, fmt.Errorf("auditd pid: %w", err)
	case pid <= 0:
		return injected{}, errors.New("auditd has no main pid")
	}
	baseAt, err := uptime()
	if err != nil {
		return injected{}, err
	}
	base, err := strconv.ParseUint(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"], 10, 32)
	if err != nil {
		return injected{}, fmt.Errorf("lost before: %w", err)
	}
	klog, err := openKmsg()
	if err != nil {
		return injected{}, err
	}
	defer klog.close()
	first, err := klog.mark("before")
	if err != nil {
		return injected{}, err
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
	var resumedAt time.Duration
	var resumedNs int64
	resume := func() error { // the resume's time is taken before the signal: the OK window starts no later
		stopFlood()
		resumedNs = time.Now().UnixNano()
		at, uerr := uptime()
		resumedAt = at
		err := syscall.Kill(pid, syscall.SIGCONT)
		wg.Wait()
		if err != nil {
			err = fmt.Errorf("SIGCONT auditd: %w", err)
		}
		return errors.Join(uerr, err)
	}
	var rise time.Duration
	var exact bool
	for rise == 0 && err == nil && pause(flood, lostPoll) {
		rise, exact, err = klog.scan(flood, uint32(base), first)
	}
	if err == nil && rise == 0 {
		err = fmt.Errorf("the kernel logged no lost record over %d within %s", base, kernelWait)
	}
	if err != nil {
		return injected{}, errors.Join(err, resume())
	}
	var inj injected
	var rerr error
	if sustained {
		stopFlood()
		inj.finish = resume
	} else {
		rerr = resume()
		inj.resumeNs, inj.resumeAt = resumedNs, resumedAt
	}
	second, err := klog.mark("after")
	if err == nil {
		err = klog.awaitMark(ctx, second)
	}
	if err == nil {
		inj.from, inj.to, err = kernelBracket(rise, first, second)
	}
	if err != nil {
		return injected{}, errors.Join(err, rerr, inj.release())
	}
	if !exact {
		inj.from = baseAt
	}
	inj.end = inj.to
	return inj, rerr
}

// kmsgMark is a mark the guest wrote to the kernel's log: the uptime just before and just after the write, and
// the kernel's timestamp of it once read back.
type kmsgMark struct {
	tag           string
	before, after time.Duration
	at            time.Duration
	seen          bool
}

// kernelBracket turns the kernel's timestamp of the rise into uptime: each mark bounds the offset between the
// two clocks by its write, and the bracket takes the widest offset either mark allows.
func kernelBracket(rise time.Duration, marks ...*kmsgMark) (time.Duration, time.Duration, error) {
	lo, hi := time.Duration(math.MaxInt64), time.Duration(math.MinInt64)
	for _, m := range marks {
		if !m.seen {
			return 0, 0, fmt.Errorf("mark %s not read back from the kernel's log", m.tag)
		}
		lo, hi = min(lo, m.before-m.at), max(hi, m.after-m.at)
	}
	from, to := rise+lo, rise+hi
	if from <= 0 || to < from {
		return 0, 0, fmt.Errorf("the rise at %s maps to %s..%s of uptime", rise, from, to)
	}
	return from, to, nil
}

// kmsgReader reads /dev/kmsg from its end without blocking, through a raw descriptor: an *os.File would wait in
// the poller instead of returning EAGAIN.
type kmsgReader struct {
	fd    int
	buf   []byte
	marks []*kmsgMark
}

// kmsgMarkPrefix starts the guest's marks; kmsgBatch bounds the records one scan reads, so a busy log cannot hold
// a caller past its deadline.
const (
	kmsgMarkPrefix = "balistid-range-guest: mark "
	kmsgBatch      = 4096
)

func openKmsg() (*kmsgReader, error) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/kmsg: %w", err)
	}
	if _, err := unix.Seek(fd, 0, io.SeekEnd); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("seek /dev/kmsg: %w", err)
	}
	return &kmsgReader{fd: fd, buf: make([]byte, 8192)}, nil
}

func (k *kmsgReader) close() { _ = unix.Close(k.fd) }

// mark writes a mark tagged tag; scan reads its timestamp back.
func (k *kmsgReader) mark(tag string) (*kmsgMark, error) {
	before, err := uptime()
	if err != nil {
		return nil, err
	}
	_, werr := unix.Write(k.fd, []byte(kmsgMarkPrefix+tag+"\n"))
	after, err := uptime()
	if err = errors.Join(werr, err); err != nil {
		return nil, fmt.Errorf("mark %s: %w", tag, err)
	}
	m := &kmsgMark{tag: tag, before: before, after: after}
	k.marks = append(k.marks, m)
	return m, nil
}

// scan reads the waiting records, at most kmsgBatch and none once ctx ended: it stamps the marks it meets, and
// returns the kernel's time of the first record that counts lost above base, 0 before one came, and whether it
// counts base+1, the rise itself.
func (k *kmsgReader) scan(ctx context.Context, base uint32, need *kmsgMark) (time.Duration, bool, error) {
	for i := 0; i < kmsgBatch && ctx.Err() == nil; i++ {
		n, err := unix.Read(k.fd, k.buf)
		switch {
		case errors.Is(err, unix.EAGAIN):
			return 0, false, nil
		case errors.Is(err, unix.EPIPE): // overwritten before it was read: the next read resumes
			continue
		case err != nil:
			return 0, false, fmt.Errorf("read /dev/kmsg: %w", err)
		}
		r, err := rangeguest.ParseKmsg(string(k.buf[:n]))
		if err != nil {
			return 0, false, fmt.Errorf("read /dev/kmsg: %w", err)
		}
		if at, exact, err := takeRecord(r, k.marks, base, need); at != 0 || err != nil {
			return at, exact, err
		}
	}
	return 0, false, nil
}

// takeRecord stamps the mark r is, or returns the kernel's time of r when it counts lost above base, and whether it
// counts base+1; a count before need was stamped came before the stop.
func takeRecord(r rangeguest.KmsgRecord, marks []*kmsgMark, base uint32, need *kmsgMark) (time.Duration, bool, error) {
	for _, m := range marks {
		if r.Msg == kmsgMarkPrefix+m.tag {
			m.at, m.seen = r.At, true
		}
	}
	lost, ok := rangeguest.AuditLost(r.Msg)
	switch {
	case !ok || lost <= base:
		return 0, false, nil
	case !need.seen:
		return 0, false, fmt.Errorf("lost %d logged before mark %s", lost, need.tag)
	}
	return max(r.At, time.Nanosecond), lost == base+1, nil
}

// awaitMark reads the kernel's log until m is stamped, for at most a second.
func (k *kmsgReader) awaitMark(ctx context.Context, m *kmsgMark) error {
	wait, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	for !m.seen {
		if _, _, err := k.scan(wait, math.MaxUint32, m); err != nil {
			return err
		}
		if !m.seen && !pause(wait, 10*time.Millisecond) {
			return fmt.Errorf("mark %s not read back from the kernel's log", m.tag)
		}
	}
	return nil
}

// overflowDispatcher stops Laurel and execs until auditd's state file, read and never signalled, says its plugin
// queue overflowed, then resumes Laurel. The bracket is the guest's own uptime, no wall clock: the overflow came
// after the last "no" generation was written, so after the last read that still saw the one before it, and before
// the read that first saw "yes" ended. That holds as auditd 4.2.1 truncates the file before it reads the flag
// (src/auditd.c:231, :249). It waits for a fresh "no" first, so the bracket starts near the injection.
func overflowDispatcher(ctx context.Context) (time.Duration, time.Duration, error) {
	w := stateWatch{read: readState, now: uptime}
	if _, _, _, err := w.poll(); err != nil {
		return 0, 0, err
	}
	for deadline := time.Now().Add(freshStateWait); w.from == 0 && w.to == 0; {
		if time.Now().After(deadline) || !pause(ctx, stateEvery) {
			return 0, 0, errors.New("auditd wrote no fresh state file")
		}
		if err := w.step(); err != nil {
			return 0, 0, err
		}
	}
	if w.to != 0 {
		return 0, 0, errors.New("the state file reads overflow yes before the injection")
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
	for w.to == 0 && err == nil && pause(flood, stateEvery) {
		err = w.step()
	}
	stopFlood()
	wg.Wait()
	if cerr := syscall.Kill(pid, syscall.SIGCONT); cerr != nil {
		err = errors.Join(err, fmt.Errorf("SIGCONT laurel: %w", cerr))
	}
	switch {
	case err != nil:
		return 0, 0, err
	case w.to == 0:
		return 0, 0, fmt.Errorf("no overflow in the state file within %s", overflowWait)
	}
	return w.from, w.to, nil
}

// stateWatch follows auditd's state file by the guest's uptime. A generation is told apart by its mtime, which is
// never turned into a time; seen is the uptime before the latest read that still returned the current one; from
// and to are the bracket so far, 0 until set.
type stateWatch struct {
	read     func() (stateRead, error)
	now      func() (time.Duration, error)
	cur      stateRead
	seen     time.Duration
	from, to time.Duration
}

// step polls once and moves the bracket: a fresh "no" restarts it after the generation before it, which that "no"
// was written after; the first "yes" ends it when this read ended. Any other flag fails.
func (w *stateWatch) step() error {
	fresh, prev, after, err := w.poll()
	if err != nil || !fresh {
		return err
	}
	switch w.cur.value {
	case "no":
		w.from = prev
	case "yes":
		w.to = after
	default:
		return fmt.Errorf("the state file reads overflow %q", w.cur.value)
	}
	return nil
}

// poll reads the state file once. fresh is true when it returned a new generation (never on the first read); prev
// is then the uptime before the last read of the generation before it, which that one was written after. after is
// the uptime once this read ended. A read the file changed under tells nothing.
func (w *stateWatch) poll() (fresh bool, prev, after time.Duration, err error) {
	before, err := w.now()
	if err != nil {
		return false, 0, 0, err
	}
	st, err := w.read()
	if err != nil {
		return false, 0, 0, err
	}
	if after, err = w.now(); err != nil {
		return false, 0, 0, err
	}
	switch {
	case st.value == stateChanged:
		return false, 0, after, nil
	case w.cur.mtime.IsZero():
		w.cur, w.seen = st, before
		return false, 0, after, nil
	case st.mtime.Equal(w.cur.mtime):
		w.seen = before
		return false, 0, after, nil
	}
	prev = w.seen
	w.cur, w.seen = st, before
	return true, prev, after, nil
}

// stateRead is auditd's state file's overflow flag and its mtime.
type stateRead struct {
	value string
	mtime time.Time
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
	value := rangeguest.OverflowDetected(string(data))
	if value == "missing" { // truncated and not yet written: a read under a change
		value = stateChanged
	}
	return stateRead{value: value, mtime: after.ModTime()}, nil
}
