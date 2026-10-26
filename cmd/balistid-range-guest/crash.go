package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// A collector failure's limits (ADR 0023): S counts only when its commit line came at most commitStale
// before the failure, the killed collector must be gone within killWait so the kill mark leaves within
// MarkWindow, and the restarted one must journal a commit within backWait.
const (
	commitStale = store.FlushEvery + 500*time.Millisecond
	killWait    = 50 * time.Millisecond
	backWait    = 30 * time.Second
	wakeArg     = "balistid-wake"
)

// crashEnv is what a collector failure touches outside its own logic: the console, reset and failure
// moment of failEnv, the collector's main pid, its commit lines, the numbered execs and the store read.
// Tests replace it.
type crashEnv struct {
	fail    failEnv
	mainPID func(ctx context.Context) string
	watch   func(ctx context.Context) (*commitWatch, error)
	emit    func(seq uint64) error
	wait    func() error
	wake    func(ctx context.Context) error
	read    storeRead
}

func guestCrashEnv(ctx context.Context) crashEnv {
	execs := rangeguest.NewExecs(maxChildren)
	return crashEnv{
		fail:    guestEnv,
		mainPID: collectorPID,
		watch: func(ctx context.Context) (*commitWatch, error) {
			return watchCommits(commitFollower(ctx), time.Now)
		},
		emit: execs.Emit,
		wait: execs.Wait,
		wake: func(ctx context.Context) error {
			return exec.CommandContext(ctx, "/usr/bin/true", wakeArg).Run()
		},
		read: func(before, after func(rawrecord.Record) error) error { return readStore(ctx, before, after) },
	}
}

// runCrash runs boot `boot` of collector failure trial tr (crash_loss_ms, ADR 0018 point 3, ADR 0023).
// Boot 1, for a reset, reports its echo and reset_armed=yes before any load. It then execs numbered
// events at the trial's rate and, at a random moment in the load's second half, writes "balistid-fail
// <H> <S>", H the end of the contiguous numbers execed 900 ms earlier and S the highest seq the
// collector journaled as committed, then resets with sysrq b, or SIGKILLs the collector, writes
// "balistid-killed" and reads the store once the restarted collector commits. After a reset boot 2
// reports the superblock and reads the store.
func runCrash(ctx context.Context, tr rangejob.Trial, boot int, r *report) error {
	if !mounted(scratchMount) {
		return r.fail("scratch disk not mounted")
	}
	env := guestCrashEnv(ctx)
	if boot == 2 {
		if err := r.superblock(superblockFile); err != nil {
			return r.fail("superblock: " + err.Error())
		}
		return storedRun(env.read, r)
	}
	if err := holdWriteback(); err != nil {
		return r.fail(err.Error())
	}
	if tr.Failure == rangejob.FailReset {
		r.add(rangevm.FactResetArmed, "yes")
		if err := r.send(r.facts); err != nil { // synced before the load: the host reads it after the reset
			return err
		}
	}
	return crashLoadAndFail(ctx, tr, r, env)
}

// crashLoadAndFail runs the load and the failure of boot 1. It fails the run itself, before any mark,
// when the load did not hold the trial's rate in every whole 10 s window before the failure (a lighter
// load would make the collector's loss look smaller) or when S is stale.
func crashLoadAndFail(ctx context.Context, tr rangejob.Trial, r *report, env crashEnv) error {
	fail := r.fail
	pid := env.mainPID(ctx)
	n, err := strconv.Atoi(pid)
	if err != nil {
		return fail("the collector is not running")
	}
	proc, err := os.FindProcess(n) // a pidfd: the kill reaches this process, never a reused pid
	if err != nil {
		return fail("collector process: " + err.Error())
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	w, err := env.watch(watchCtx)
	if err != nil {
		stopWatch()
		return fail("commit line: " + err.Error())
	}
	defer func() { stopWatch(); w.wait() }()
	after, err := env.fail.failAfter(time.Duration(tr.Load.Seconds) * time.Second)
	if err != nil {
		return fail(err.Error())
	}
	start := time.Now()
	failAt := start.Add(after)
	var hand rangeguest.Handover
	_, _, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, func(seq uint64) error {
		if !time.Now().Before(failAt) {
			return errFailNow
		}
		if err := env.emit(seq); err != nil {
			return err
		}
		hand.Add(time.Now())
		return nil
	}, rangeguest.WallClock)
	if !errors.Is(genErr, errFailNow) {
		return fail(fmt.Sprintf("load ended before the failure: %v", genErr))
	}
	taken := time.Now()
	h := hand.H(taken)
	s, _ := w.last()
	if err := crashPremise(&hand, start, taken, tr.Load.Rate, s, w.committedAt()); err != nil {
		return fail(err.Error())
	}
	if err := mark(env.fail, failMark(h, s)); err != nil {
		return fail(err.Error())
	}
	if err := markInTime(taken, time.Now()); err != nil {
		return fail(err.Error())
	}
	if tr.Failure == rangejob.FailReset {
		_ = env.fail.reset() // reboot at once, without syncing or unmounting; with -no-reboot QEMU exits
		return fail("sysrq b did not reset the guest")
	}
	if err := killNow(proc); err != nil {
		return fail(err.Error())
	}
	if err := mark(env.fail, killMark); err != nil {
		return fail(err.Error())
	}
	killed := time.Now()
	if err := env.wait(); err != nil {
		return fail("load: " + err.Error())
	}
	if err := collectorBack(ctx, env, w, pid, killed); err != nil {
		return fail(err.Error())
	}
	stopWatch()
	w.wait()
	return storedRun(env.read, r)
}

// crashPremise is why a failure at taken would not measure the collector at the trial's rate, or nil:
// a whole 10 s window from start below the rate, no commit line yet, or the last one, which S comes
// from, older than commitStale.
func crashPremise(hand *rangeguest.Handover, start, taken time.Time, rate int, s uint64, at time.Time) error {
	least, want := hand.WindowMin(start, taken, rate), uint64(rate)*10 //nolint:gosec // positive table value
	switch {
	case least < want:
		return fmt.Errorf("rate not held before the failure: %d in the slowest whole 10 s window, want %d", least, want)
	case s == 0:
		return errors.New("no commit line before the failure")
	case taken.Sub(at) > commitStale:
		return fmt.Errorf("the last commit line came %s before the failure, over %s", taken.Sub(at), commitStale)
	}
	return nil
}

// killNow sends SIGKILL to the collector and returns once it is gone: SIGKILL cannot be caught, so a
// process that ends right after it ended by it.
func killNow(p *os.Process) error {
	if err := p.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill the collector: %w", err)
	}
	for deadline := time.Now().Add(killWait); ; time.Sleep(time.Millisecond) {
		if err := p.Signal(syscall.Signal(0)); errors.Is(err, os.ErrProcessDone) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the collector did not end within %s of SIGKILL", killWait)
		}
	}
}

// collectorBack execs until systemd runs a collector other than the killed pid and it journals a
// commit: Laurel reconnects only when it writes, and a line it writes into the dead connection is
// lost, so the store read's barrier must not be that line.
func collectorBack(ctx context.Context, env crashEnv, w *commitWatch, killed string, since time.Time) error {
	var seen time.Time
	for deadline := since.Add(backWait); time.Now().Before(deadline); time.Sleep(store.FlushEvery) {
		if err := env.wake(ctx); err != nil {
			return fmt.Errorf("wake exec: %w", err)
		}
		if pid := env.mainPID(ctx); seen.IsZero() && pid != "" && pid != killed {
			seen = time.Now()
		}
		if _, at := w.last(); !seen.IsZero() && at.After(seen) {
			return nil
		}
	}
	return fmt.Errorf("no restarted collector committed within %s of the kill", backWait)
}

// storedRun reads the store and reports the numbers it holds, its recovery records and how far its
// seqs run without a gap.
func storedRun(read storeRead, r *report) error {
	c, err := rangeguest.NewCounter(rangejob.LoadExec, 0)
	if err != nil {
		return r.fail(err.Error())
	}
	var rec recovery
	var seqs uint64 // the end of the seqs 1..N read without a gap
	each := func(x rawrecord.Record) error {
		if x.Seq == seqs+1 {
			seqs++
		}
		switch x.Provider {
		case store.SensorProvider:
			c.Line(x.Data)
		case store.HealthProvider:
			rec.add(x)
		}
		return nil
	}
	if err := read(each, each); err != nil {
		return r.fail("store: " + err.Error())
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactStoredPrefix, u(c.Numbers().Prefix()))
	r.add(rangevm.FactStoredCount, u(c.Numbers().Total()))
	r.add(rangevm.FactRecovered, u(rec.count))
	r.add(rangevm.FactRecoveredLast, u(rec.last))
	r.add(rangevm.FactRecoveredSeq, u(rec.seq))
	r.add(rangevm.FactSeqPrefix, u(seqs))
	return r.send(r.facts)
}

// recovery is what the store's recovery records say (store.Open after a crash, ADR 0013 point 5): how
// many there are, and of the first the last seq it found durable and its own seq. A first one of
// another schema or without its last leaves last 0, which the host judges INVALID.
type recovery struct{ count, last, seq uint64 }

func (rc *recovery) add(x rawrecord.Record) {
	var rec map[string]json.RawMessage
	var event string
	if json.Unmarshal(x.Data, &rec) != nil || json.Unmarshal(rec["event"], &event) != nil || event != "recovered" {
		return
	}
	if rc.count++; rc.count > 1 {
		return
	}
	var schema int
	var last uint64
	rc.seq = x.Seq
	if json.Unmarshal(rec["schema_version"], &schema) == nil && schema == healthSchema && json.Unmarshal(rec["last"], &last) == nil {
		rc.last = last
	}
}
