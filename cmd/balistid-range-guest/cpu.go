package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// The units whose CPU cpu_cores counts (ADR 0023 point 5): auditd's cgroup holds Laurel too. A CPU
// trial's load has drained once the kernel's audit backlog is empty and no commit line came for
// cpuDrainQuiet, at most cpuDrainWait after it.
const (
	auditdUnitName = "auditd.service"
	cpuDrainQuiet  = 3 * time.Second
	cpuDrainWait   = 60 * time.Second
)

// unitSample is a unit's cgroup CPU µs and memory peak and the invocation they belong to, or why not.
type unitSample struct {
	usec       uint64
	memPeak    string
	invocation string
	err        error
}

// sampleUnit reads unit's cgroup through systemd: a restarted unit has another invocation and fresh
// counters.
func sampleUnit(ctx context.Context, unit string) unitSample {
	show := func(prop string) string {
		return strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "--property="+prop, "--value", unit))
	}
	cg, inv := show("ControlGroup"), show("InvocationID")
	if !strings.HasPrefix(cg, "/") || inv == "" {
		return unitSample{err: fmt.Errorf("%s has no cgroup or invocation", unit)}
	}
	usec, err := usageUsec(readTrim("/sys/fs/cgroup" + cg + "/cpu.stat"))
	if err != nil {
		return unitSample{err: fmt.Errorf("%s: %w", unit, err)}
	}
	return unitSample{usec: usec, memPeak: readTrim("/sys/fs/cgroup" + cg + "/memory.peak"), invocation: inv}
}

// sampleLaurel reads Laurel's CPU inside auditd's cgroup, so the cgroup's cost can be split between
// them: the invocation is Laurel's pid and start time, which a Laurel that auditd restarted changes.
func sampleLaurel() unitSample {
	pid := laurelPID()
	if pid == "" {
		return unitSample{err: errors.New("no laurel process")}
	}
	usec, start, err := procCPU(readTrim("/proc/" + pid + "/stat"))
	if err != nil {
		return unitSample{err: fmt.Errorf("laurel: %w", err)}
	}
	return unitSample{usec: usec, invocation: pid + "@" + start}
}

// procCPU is the utime and stime of a /proc/<pid>/stat line in µs, every thread's, at Linux's fixed
// USER_HZ of 100, and the process's start time. The command name may hold spaces and parentheses.
func procCPU(stat string) (uint64, string, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, "", errors.New("no command name in stat")
	}
	f := strings.Fields(stat[end+1:]) // f[0] is field 3, the state
	if len(f) < 20 {
		return 0, "", fmt.Errorf("stat has %d fields after the name", len(f))
	}
	utime, errU := strconv.ParseUint(f[11], 10, 64)
	stime, errS := strconv.ParseUint(f[12], 10, 64)
	if errU != nil || errS != nil || utime > math.MaxUint64/20_000 || stime > math.MaxUint64/20_000 {
		return 0, "", fmt.Errorf("utime %q, stime %q", f[11], f[12])
	}
	return (utime + stime) * 10_000, f[19], nil
}

// usageUsec is usage_usec of a cgroup's cpu.stat.
func usageUsec(stat string) (uint64, error) {
	for _, line := range strings.Split(stat, "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("usage_usec %q", v)
			}
			return n, nil
		}
	}
	return 0, errors.New("no usage_usec in cpu.stat")
}

// used is the CPU µs between two samples of one invocation, or why there is none.
func used(before, after unitSample) (uint64, string) {
	switch {
	case before.err != nil:
		return 0, before.err.Error()
	case after.err != nil:
		return 0, after.err.Error()
	case before.invocation != after.invocation:
		return 0, "restarted"
	case after.usec < before.usec:
		return 0, "counter went back"
	}
	return after.usec - before.usec, ""
}

// collectorMeasures are a rate trial's measures of the collector, a number or why not: its CPU µs over
// the load and its cgroup's memory peak.
func collectorMeasures(before, after unitSample) (cpu, mem string) {
	n, why := used(before, after)
	if why != "" {
		return why, why
	}
	return strconv.FormatUint(n, 10), after.memPeak
}

// runCPU execs numbered events at the trial's rate and reports the CPU of the collector's and of
// auditd's cgroups, and Laurel's share of the latter, from before the load until it drained, with the
// load's counts and steal (cpu_cores, ADR 0023 point 5).
func runCPU(ctx context.Context, tr rangejob.Trial, r *report) error {
	watchCtx, stopWatch := context.WithCancel(ctx)
	w, err := watchCommits(commitFollower(watchCtx), time.Now)
	if err != nil {
		stopWatch()
		return r.fail("commit line: " + err.Error())
	}
	defer func() { stopWatch(); w.wait() }()
	collector0, auditd0, laurel0 := sampleUnit(ctx, collectorUnitName), sampleUnit(ctx, auditdUnitName), sampleLaurel()
	statBefore := readTrim("/proc/stat")
	execs := rangeguest.NewExecs(maxChildren)
	generated, windowMin, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, execs.Emit, rangeguest.WallClock)
	if err := errors.Join(genErr, execs.Wait()); err != nil {
		return r.fail("generator: " + err.Error())
	}
	cpu, steal, err := rangeguest.TickDelta(statBefore, readTrim("/proc/stat"))
	if err != nil {
		return r.fail("CPU ticks: " + err.Error())
	}
	if err := drained(w, time.Now, func() string {
		return rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["backlog"]
	}); err != nil {
		return r.fail(err.Error())
	}
	collectorUS, whyC := used(collector0, sampleUnit(ctx, collectorUnitName))
	auditdUS, whyA := used(auditd0, sampleUnit(ctx, auditdUnitName))
	laurelUS, whyL := used(laurel0, sampleLaurel())
	counter, err := rangeguest.NewCounter(rangejob.LoadExec, 0)
	if err != nil {
		return r.fail(err.Error())
	}
	if err := readStore(ctx, func(x rawrecord.Record) error {
		if x.Provider == store.SensorProvider {
			counter.Line(x.Data)
		}
		return nil
	}, nil); err != nil {
		return r.fail("store: " + err.Error())
	}
	stored, missing, _, _ := counter.Numbers().Count(generated)
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactGenerated, u(generated))
	r.add(rangevm.FactWindowMin, u(windowMin))
	r.add(rangevm.FactCPUTicks, u(cpu))
	r.add(rangevm.FactStealTicks, u(steal))
	r.add(rangevm.FactCollectorUS, u(collectorUS))
	r.add(rangevm.FactAuditdUS, u(auditdUS))
	if whyL == "" {
		whyL = u(laurelUS) // informational: auditd_usec already holds it
	}
	r.add(rangevm.FactLaurelUS, whyL)
	r.add(rangevm.FactUnits, unitsState(whyC, whyA))
	r.add(rangevm.FactStored, u(stored))
	r.add(rangevm.FactMissing, u(missing))
	return r.send(r.facts)
}

// unitsState is "same" when both units' CPU was read over one invocation each, else why not.
func unitsState(collector, auditd string) string {
	switch {
	case collector != "":
		return "collector: " + collector
	case auditd != "":
		return "auditd: " + auditd
	}
	return "same"
}

// drained returns once the kernel's audit backlog is "0" and no commit line came for cpuDrainQuiet, or
// fails after cpuDrainWait, without any commit line, or once the journal follower ended: CPU sampled
// before auditd, Laurel and the collector caught up would understate their cost. What Laurel holds
// without sending is not seen (ADR 0023).
func drained(w *commitWatch, now func() time.Time, backlog func() string) error {
	last := ""
	for deadline := now().Add(cpuDrainWait); now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		seq, at := w.last()
		switch {
		case closed(w.done):
			return errors.New("commit line: the journal follower ended")
		case seq == 0:
			return errors.New("no commit line during the load")
		case now().Sub(at) < cpuDrainQuiet:
			last = "" // commits resumed: an earlier backlog no longer says why the wait ran out
			continue
		}
		if last = backlog(); last == "0" {
			return nil
		}
	}
	if last != "" {
		return fmt.Errorf("the kernel's audit backlog was still %q %s after the load", last, cpuDrainWait)
	}
	return fmt.Errorf("the collector still committed %s after the load", cpuDrainWait)
}
