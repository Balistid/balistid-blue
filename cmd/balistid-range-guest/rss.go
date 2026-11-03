package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// rssEvery is how often an RSS trial sums the resident memory of the recorder's units (rss_mib).
const rssEvery = time.Second

// runRSS generates the trial's load and, every rssEvery from before it until it drained, sums the VmRSS of
// every process of the image's long-running balistid services, and of auditd's cgroup with Laurel as a trend
// (rss_mib). A unit whose cgroup cannot be read fails the trial; the host judges the largest sum.
func runRSS(ctx context.Context, tr rangejob.Trial, r *report) error {
	units := longRunning(balistidUnits(ctx), func(u string) string {
		return strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "Type", u))
	})
	if len(units) == 0 {
		return r.fail("no long-running balistid service")
	}
	before, cgroups := map[string]unitSample{}, []string{}
	for _, u := range units {
		s := sampleUnit(ctx, u)
		if s.err != nil {
			return r.fail(s.err.Error())
		}
		before[u], cgroups = s, append(cgroups, s.cgroup)
	}
	var emit func(uint64) error
	wait := func() error { return nil }
	switch tr.Load.Kind {
	case rangejob.LoadExec:
		execs := rangeguest.NewExecs(maxChildren)
		emit, wait = execs.Emit, execs.Wait
	case rangejob.LoadPtrace:
		emit = rangeguest.Peek
	case rangejob.LoadExecLarge:
		emit = func(seq uint64) error { return execArgv(ctx, argv2M, "rss-"+strconv.FormatUint(seq, 10)) }
	default:
		return r.fail("no RSS load " + tr.Load.Kind)
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	w, err := watchCommits(commitFollower(watchCtx), time.Now)
	if err != nil {
		stopWatch()
		return r.fail("commit line: " + err.Error())
	}
	defer func() { stopWatch(); w.wait() }()
	lost := func() string { return valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]) }
	lostBefore := lost()
	auditd, laurel := []string{sampleUnit(ctx, auditdUnitName).cgroup}, []string{laurelPID()}
	stop := sampleRSS(ctx, rssEvery, func(m *rssMax) { m.sample("/", cgroups, auditd, laurel) })
	generated, windowMin, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, emit, rangeguest.WallClock)
	genErr = errors.Join(genErr, wait())
	var drainErr error
	if genErr == nil {
		drainErr = drained(w, time.Now, func() string {
			return rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["backlog"]
		})
	}
	m := stop()
	switch {
	case genErr != nil:
		return r.fail("generator: " + genErr.Error())
	case drainErr != nil:
		return r.fail(drainErr.Error())
	case m.err != nil:
		return r.fail("rss: " + m.err.Error())
	}
	same := "same"
	for _, u := range units {
		if _, why := used(before[u], sampleUnit(ctx, u)); why != "" && same == "same" {
			same = u + ": " + why
		}
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactGenerated, u(generated))
	r.add(rangevm.FactWindowMin, u(windowMin))
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, lost())
	r.add(rangevm.FactUnits, same)
	r.add(rangevm.FactRSSUnits, strings.Join(units, ","))
	r.add(rangevm.FactRSSSamples, u(m.samples))
	r.add(rangevm.FactRSSProcsMin, strconv.Itoa(m.procsMin))
	r.add(rangevm.FactRSSMaxKiB, u(m.kib))
	audit := u(m.auditKiB)
	if m.auditWhy != "" {
		audit = m.auditWhy
	}
	r.add(rangevm.FactRSSAuditKiB, audit)
	return r.send(r.facts)
}

// longRunning are the services of units, the comma-separated unit files balistidUnits lists, that rss_mib
// sums: not the range's own and not a oneshot, by the Type typeOf reads.
func longRunning(units string, typeOf func(string) string) []string {
	var out []string
	for _, u := range strings.Split(units, ",") {
		if strings.HasSuffix(u, ".service") && !strings.HasPrefix(u, "balistid-range-") && typeOf(u) != "oneshot" {
			out = append(out, u)
		}
	}
	return out
}

// rssMax is what an RSS trial's samples found: how many, the largest sum of the recorder's units and the fewest
// processes any of them held in one, and the largest sum of auditd's cgroup with Laurel or why there is none.
type rssMax struct {
	samples, kib, auditKiB uint64
	procsMin               int
	auditWhy               string
	err                    error
}

// sample adds one sum of cgroups under root and one of auditd with pids; a recorder's cgroup that cannot be
// read ends the samples, auditd's only its trend.
func (m *rssMax) sample(root string, cgroups, auditd, pids []string) {
	kib, procs, err := rssKiB(root, cgroups, nil)
	if err != nil {
		m.err = err
		return
	}
	low := 0
	if len(procs) > 0 {
		low = slices.Min(procs)
	}
	if m.samples == 0 || low < m.procsMin {
		m.procsMin = low
	}
	m.samples++
	m.kib = max(m.kib, kib)
	if a, _, err := rssKiB(root, auditd, pids); err != nil {
		m.auditWhy = err.Error()
	} else {
		m.auditKiB = max(m.auditKiB, a)
	}
}

// sampleRSS calls sample at once and every every until stop, which returns what it found; an error ends it early.
func sampleRSS(ctx context.Context, every time.Duration, sample func(*rssMax)) (stop func() rssMax) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan rssMax, 1)
	go func() {
		var m rssMax
		tick := time.NewTicker(every)
		defer tick.Stop()
		for sample(&m); m.err == nil; sample(&m) {
			select {
			case <-ctx.Done():
				done <- m
				return
			case <-tick.C:
			}
		}
		done <- m
	}()
	return func() rssMax { cancel(); return <-done }
}

// rssKiB sums under root the VmRSS of every process in cgroups, their child cgroups included, and in pids, each
// process once; procs is how many each cgroup held. A process gone or exited before its status was read holds no
// memory and is skipped; a cgroup that cannot be read is an error, never a sum without it.
func rssKiB(root string, cgroups, pids []string) (kib uint64, procs []int, err error) {
	seen := map[string]bool{}
	add := func(pid string) (int, error) {
		if _, err := strconv.ParseUint(pid, 10, 31); err != nil {
			return 0, fmt.Errorf("%q is not a pid", pid)
		}
		if seen[pid] {
			return 0, nil
		}
		seen[pid] = true
		v, ok, err := vmRSS(root, pid)
		if !ok || err != nil {
			return 0, err
		}
		kib += v
		return 1, nil
	}
	for _, cg := range cgroups {
		if !strings.HasPrefix(cg, "/") || cg == "/" {
			return 0, nil, fmt.Errorf("cgroup %q is not a unit's", cg)
		}
		n := 0
		err := filepath.WalkDir(filepath.Join(root, "sys/fs/cgroup", cg), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
				return err
			}
			data, err := os.ReadFile(path) //nolint:gosec // a unit's cgroup under /sys/fs/cgroup, or a test's
			if err != nil {
				return err //nolint:wrapcheck // the caller names the cgroup
			}
			for _, pid := range strings.Fields(string(data)) {
				c, err := add(pid)
				if err != nil {
					return err
				}
				n += c
			}
			return nil
		})
		if err != nil {
			return 0, nil, fmt.Errorf("cgroup %s: %w", cg, err)
		}
		procs = append(procs, n)
	}
	for _, pid := range pids {
		if _, err := add(pid); err != nil {
			return 0, nil, err
		}
	}
	return kib, procs, nil
}

// vmRSS is the VmRSS in KiB of pid under root; ok is false for a process gone, or exited, that holds none.
func vmRSS(root, pid string) (kib uint64, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(root, "proc", pid, "status")) //nolint:gosec // a pid's status under /proc, or a test's
	switch {
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("pid %s: %w", pid, err)
	}
	v := rangeguest.StatusField(string(data), "VmRSS")
	if v == "" {
		return 0, false, nil
	}
	digits, unit := strings.CutSuffix(v, " kB")
	n, err := strconv.ParseUint(digits, 10, 64)
	if !unit || err != nil {
		return 0, false, fmt.Errorf("pid %s: VmRSS %q", pid, v)
	}
	return n, true, nil
}
