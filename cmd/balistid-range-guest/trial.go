package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
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

// runTrial runs the rate trial the host named (ADR 0018, point 4) as root from the image: it echoes
// the trial and phase first, follows Laurel's log, generates the numbered load, closes the window
// with a canary and reports the counts for the host to judge. A trial it cannot run reports
// trial_error, which the host judges INVALID.
func runTrial(ctx context.Context, name, phase string) error {
	var facts []fact
	add := func(name, value string) { facts = append(facts, fact{name, value}) }
	add(rangevm.FactTrial, name)
	add(rangevm.FactPhase, phase)
	add(rangevm.FactKernel, readTrim("/proc/sys/kernel/osrelease"))
	fail := func(why string) error {
		add(rangevm.FactTrialError, why)
		return write(facts)
	}
	tr, err := rangeguest.TrialFor(name, phase)
	if err != nil {
		return fail(err.Error())
	}
	lostBefore := valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"])
	overflowBefore := freshOverflow(ctx)

	var skip uint64
	if tr.Load.Drop {
		skip = uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) / 2 //nolint:gosec // non-negative table values
	}
	fl := rangeguest.NewFollower(laurelLog, tr.Load.Kind, skip)
	if err := fl.Start(); err != nil {
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

	token, err := token("balistid-canary-")
	if err != nil {
		return fail(err.Error())
	}
	nums, followErr := fl.Finish(ctx, token, func(ctx context.Context) error {
		return exec.CommandContext(ctx, "/usr/bin/true", token).Run() //nolint:gosec // our own random token
	}, waitLimit)
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
	} else {
		stored, missing, duplicate, outside = nums.Count(generated)
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
	return write(facts)
}

// freshOverflow asks auditd to rewrite its state file and reads the overflow flag from that rewrite.
func freshOverflow(ctx context.Context) string {
	return rangeguest.FreshState(ctx, auditdState, func(ctx context.Context) error {
		return exec.CommandContext(ctx, "/usr/bin/auditctl", "--signal", "state").Run()
	}, stateWait, 50*time.Millisecond)
}
