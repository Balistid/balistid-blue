package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// maxChildren bounds the exec generator's children running at once; stateWait bounds how long
// auditd may take to rewrite its state file.
const (
	maxChildren = 64
	stateWait   = 5 * time.Second
)

// credentials is the unit's systemd credentials directory, or nil outside a trial.
func credentials() fs.FS {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		return os.DirFS(dir)
	}
	return nil
}

// runTrial runs the trial the host named (ADR 0018) as root from the image by its method: it echoes
// the trial, phase and kernel first, then runs the method, which reports its facts for the host to
// judge. A trial it cannot run reports trial_error, which the host judges INVALID.
func runTrial(ctx context.Context, name, phase string) error {
	r := &report{send: write}
	r.add(rangevm.FactTrial, name)
	r.add(rangevm.FactPhase, phase)
	r.add(rangevm.FactKernel, readTrim("/proc/sys/kernel/osrelease"))
	tr, boot, err := rangeguest.TrialFor(name, phase)
	if err != nil {
		return r.fail(err.Error())
	}
	switch tr.Method() {
	case rangejob.MethodRate:
		return runRate(ctx, tr, r)
	case rangejob.MethodWriterFailure:
		return runFailure(ctx, tr, boot, r)
	case rangejob.MethodCollectorFailure:
		return runCrash(ctx, tr, boot, r)
	case rangejob.MethodRecord:
		return runRecord(ctx, r)
	case rangejob.MethodRefusal:
		return runRefusal(ctx, tr, r)
	case rangejob.MethodReady:
		return runReady(ctx, r)
	case rangejob.MethodExposure:
		return runExposure(ctx, r)
	case rangejob.MethodCPU:
		return runCPU(ctx, tr, r)
	case rangejob.MethodAlarm:
		return runAlarm(ctx, tr, r)
	case rangejob.MethodLoss:
		return runLoss(ctx, tr, r)
	}
	return r.fail("no method runs trial " + tr.Name)
}

// runRate generates the numbered load of rate trial tr (ADR 0018, point 4), reads what the collector
// stored up to a barrier (ADR 0022, point 3) and reports the counts.
func runRate(ctx context.Context, tr rangejob.Trial, r *report) error {
	add, fail := r.add, r.fail
	lostBefore := valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"])
	overflowBefore := freshOverflow(ctx)
	collector0 := sampleUnit(ctx, collectorUnitName)

	var skip uint64
	if tr.Load.Drop {
		skip = uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) / 2 //nolint:gosec // non-negative table values
	}
	counter, err := rangeguest.NewCounter(tr.Load.Kind, skip)
	if err != nil {
		return fail(err.Error())
	}
	emit, wait := rangeguest.Peek, func() error { return nil }
	if tr.Load.Kind == rangejob.LoadExec {
		execs := rangeguest.NewExecs(maxChildren)
		emit, wait = execs.Emit, execs.Wait
	}
	statBefore := readTrim("/proc/stat")
	generated, windowMin, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, emit, rangeguest.WallClock)
	genErr = errors.Join(genErr, wait())
	statLoaded := readTrim("/proc/stat")
	// The collector's CPU over the load, read before the store read stops it and its cgroup.
	collectorCPU, collectorMem := collectorMeasures(collector0, sampleUnit(ctx, collectorUnitName))

	followErr := rateRead(counter, func(before, after func(rawrecord.Record) error) error { return readStore(ctx, before, after) })
	nums := counter.Numbers()
	// Steal under load and while the reader drains, each on its own: a short burst of host contention
	// in either is INVALID, not diluted by the other into a PASS or a MISS.
	cpu, steal, loadErr := rangeguest.TickDelta(statBefore, statLoaded)
	drainCPU, drainSteal, drainErr := rangeguest.TickDelta(statLoaded, readTrim("/proc/stat"))
	tickErr := errors.Join(loadErr, drainErr)
	switch {
	case genErr != nil:
		return fail("generator: " + genErr.Error())
	case tickErr != nil:
		return fail("CPU ticks: " + tickErr.Error())
	}
	follow := "ok"
	stored, missing, duplicate, outside := uint64(0), generated, uint64(0), uint64(0)
	if followErr != nil {
		follow = followErr.Error()
		reportCollector(ctx, os.Stdout, output)
	} else {
		stored, missing, duplicate, outside = nums.Count(generated)
	}
	if outside > 0 {
		// Show what counted as outside: the store is gone after the run. Quoted, so a record cannot
		// put a line of its own, such as a mark, on the console.
		for _, rec := range counter.Outside() {
			fmt.Printf("balistid-range-guest: outside record: %q\n", rec)
		}
		fmt.Printf("balistid-range-guest: outside numbers above %d: %v\n", generated, nums.Above(generated, 3))
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	add(rangevm.FactGenerated, u(generated))
	add(rangevm.FactWindowMin, u(windowMin))
	add(rangevm.FactLostBefore, lostBefore)
	add(rangevm.FactLostAfter, valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]))
	add(rangevm.FactOverflowBefore, overflowBefore)
	add(rangevm.FactOverflowAfter, freshOverflow(ctx))
	add(rangevm.FactCPUTicks, u(cpu))
	add(rangevm.FactStealTicks, u(steal))
	add(rangevm.FactDrainCPU, u(drainCPU))
	add(rangevm.FactDrainSteal, u(drainSteal))
	add(rangevm.FactFollow, follow)
	add(rangevm.FactStored, u(stored))
	add(rangevm.FactMissing, u(missing))
	add(rangevm.FactDuplicate, u(duplicate))
	add(rangevm.FactOutside, u(outside))
	add(rangevm.FactCollectorUS, collectorCPU)
	add(rangevm.FactCollectorMem, collectorMem)
	return r.send(r.facts)
}

// freshOverflow asks auditd to rewrite its state file and reads the overflow flag from that rewrite.
func freshOverflow(ctx context.Context) string {
	return rangeguest.FreshState(ctx, auditdState, func(ctx context.Context) error {
		return exec.CommandContext(ctx, "/usr/bin/auditctl", "--signal", "state").Run()
	}, stateWait, 50*time.Millisecond)
}

// errStoreLost is a rate trial whose store dropped records: its cap is the host's, so only a full
// scratch disk drops, which says the range sized it wrong, not that the collector lost them: INVALID.
var errStoreLost = errors.New("the store dropped records: the scratch disk is full")

// rateRead counts a rate trial's numbers from one store read and fails it with errStoreLost when
// the store dropped records, on either side of the barrier.
func rateRead(c *rangeguest.Counter, read storeRead) error {
	storeLost := false
	err := read(rateRecords(c, &storeLost), storeLoss(&storeLost))
	if err == nil && storeLost {
		return errStoreLost
	}
	return err
}

// storeLoss sets *storeLost at a loss record of the store behind the barrier too: the store records a
// drop before the record after it, so one there dropped only later records, yet the disk was full.
func storeLoss(storeLost *bool) func(rawrecord.Record) error {
	return func(r rawrecord.Record) error {
		*storeLost = *storeLost || r.Provider == store.LossProvider
		return nil
	}
}

// rateRecords counts a rate trial's numbers in the Laurel lines and sets *storeLost at a loss record of
// the store.
func rateRecords(c *rangeguest.Counter, storeLost *bool) func(rawrecord.Record) error {
	return func(r rawrecord.Record) error {
		switch r.Provider {
		case store.SensorProvider:
			c.Line(r.Data)
		case store.LossProvider:
			*storeLost = true
		}
		return nil
	}
}
