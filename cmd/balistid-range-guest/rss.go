package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// rssEvery is how often an RSS trial sums the resident memory of the recorder's units (rss_mib).
const rssEvery = time.Second

// unitOOMMessage is the MESSAGE_ID systemd logs when the kernel's OOM killer killed a process of a unit
// (SD_MESSAGE_UNIT_OUT_OF_MEMORY): it stays in the journal after systemd restarted the unit and removed its cgroup.
const unitOOMMessage = "fe6faa94e7774663a0da52717891d8ef"

// rssDrainWait bounds how long an RSS trial waits for the store to catch up with its load. Laurel holds 2 MB records
// at about the load's 4 MB/s on one core (ADR 0054), so a backlog it builds drains no faster than the load came.
func rssDrainWait(kind string) time.Duration {
	if kind == rangejob.LoadExecLarge {
		return 3 * time.Minute
	}
	return cpuDrainWait
}

// runRSS generates the trial's load and, every rssEvery from before it until it drained, sums the VmRSS of every
// process of the image's long-running balistid services, and of auditd's cgroup, Laurel in it, as a trend
// (rss_mib, ADR 0054). It reports the facts it has also when the run is not whole, so the host finds a MISS in them:
// the sums, the VmHWM at the end, the OOM events and the collector's queue; what dropped part of the load after the
// kernel; and rss_run, "ok" or why not.
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
	queue := collectorQueue(ctx)
	watchCtx, stopWatch := context.WithCancel(ctx)
	w, err := watchCommits(commitFollower(watchCtx), time.Now)
	if err != nil {
		stopWatch()
		return r.fail("commit line: " + err.Error())
	}
	defer func() { stopWatch(); w.wait() }()
	lost := func() string { return valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]) }
	lostBefore, overflowBefore := lost(), freshOverflow(ctx)
	auditd := []string{sampleUnit(ctx, auditdUnitName).cgroup}
	stop := sampleRSS(ctx, rssEvery, time.Now, func(m *rssMax) { m.sample("/", cgroups, auditd) })
	from := time.Now()
	generated, windowMin, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, emit, rangeguest.WallClock)
	genErr = errors.Join(genErr, wait())
	to := time.Now()
	var drainErr error
	if genErr == nil {
		drainErr = drained(w, time.Now, func() string {
			return rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["backlog"]
		}, rssDrainWait(tr.Load.Kind))
	}
	m := stop()
	run := "ok"
	switch {
	case genErr != nil:
		run = "generator: " + genErr.Error()
	case drainErr != nil:
		run = drainErr.Error()
	case m.err != nil:
		run = "rss: " + m.err.Error()
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	hwm := "VmHWM: "
	if kib, _, _, err := cgroupSum("/", cgroups, "VmHWM"); err != nil {
		hwm += err.Error()
	} else {
		hwm = u(kib)
	}
	same := "same"
	for _, unit := range units {
		if _, why := used(before[unit], sampleUnit(ctx, unit)); why != "" && same == "same" {
			same = unit + ": " + why
		}
	}
	events := m.oomEvents()
	oom := u(events) // a journal not read cannot unsay events the cgroups showed
	switch n, err := oomJournal(ctx, units); {
	case err == nil:
		oom = u(events + n)
	case events == 0:
		oom = "journal: " + err.Error()
	}
	r.add(rangevm.FactGenerated, u(generated))
	r.add(rangevm.FactWindowMin, u(windowMin))
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, lost())
	r.add(rangevm.FactOverflowBefore, overflowBefore)
	r.add(rangevm.FactOverflowAfter, freshOverflow(ctx))
	r.add(rangevm.FactUnits, same)
	r.add(rangevm.FactRSSRun, run)
	r.add(rangevm.FactRSSUnits, strings.Join(units, ","))
	r.add(rangevm.FactRSSSamples, u(m.samples))
	r.add(rangevm.FactRSSLoadGapMS, loadGap(m.at, from, to))
	r.add(rangevm.FactRSSProcsMin, strconv.Itoa(m.procsMin))
	r.add(rangevm.FactRSSMaxKiB, u(m.kib))
	r.add(rangevm.FactRSSHWMKiB, hwm)
	r.add(rangevm.FactRSSOOM, oom)
	r.add(rangevm.FactRSSQueueBytes, queue)
	audit := u(m.auditKiB)
	if m.auditWhy != "" {
		audit = m.auditWhy
	}
	r.add(rangevm.FactRSSAuditKiB, audit)
	// Last: reading the store stops the collector.
	r.add(rangevm.FactLostRecords, storeLosses(ctx))
	return r.send(r.facts)
}

// collectorQueue is the -queue-bytes of the collector's running process, read from its argv, or why not.
func collectorQueue(ctx context.Context) string {
	owner, err := collectorProcess(ctx)
	if err != nil {
		return err.Error()
	}
	argv, err := os.ReadFile("/proc/" + owner.pid + "/cmdline")
	if err != nil {
		return "cmdline: " + err.Error()
	}
	return queueFlag(string(argv))
}

// queueFlag is the -queue-bytes value in a NUL-separated argv, as Go's flag package takes "-name value",
// "-name=value" and two dashes, up to "--"; absent, the collector's default, rangevm.CollectorQueueBytes. Given twice
// or without a value it is why not.
func queueFlag(cmdline string) string {
	args := strings.Split(strings.TrimSuffix(cmdline, "\x00"), "\x00")
	var values []string
	for i := 1; i < len(args) && args[i] != "--"; i++ {
		name, value, inline := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(args[i], "-"), "-"), "=")
		if !strings.HasPrefix(args[i], "-") || name != "queue-bytes" {
			continue
		}
		if !inline {
			if i++; i >= len(args) {
				return "-queue-bytes without a value"
			}
			value = args[i]
		}
		values = append(values, value)
	}
	switch len(values) {
	case 0:
		return strconv.Itoa(rangevm.CollectorQueueBytes)
	case 1:
		return values[0]
	}
	return fmt.Sprintf("-queue-bytes given %d times", len(values))
}

// oomJournal counts systemd's messages since boot that the OOM killer killed a process of one of units.
func oomJournal(ctx context.Context, units []string) (uint64, error) {
	args := []string{"-b", "-q", "--no-pager", "-o", "cat", "MESSAGE_ID=" + unitOOMMessage}
	for _, u := range units {
		args = append(args, "UNIT="+u) // matches of one field are alternatives, of two fields both hold
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/journalctl", args...).Output()
	if err != nil {
		return 0, fmt.Errorf("journalctl: %w", err)
	}
	return uint64(len(strings.FieldsFunc(string(out), func(r rune) bool { return r == '\n' }))), nil
}

// storeLosses reads the store once and counts the records that say part of the load was dropped after the kernel,
// before or behind the read's barrier (rssLoss), or why it could not.
func storeLosses(ctx context.Context) string {
	var n uint64
	count := func(x rawrecord.Record) error {
		if rssLoss(x) {
			n++
		}
		return nil
	}
	if err := readStore(ctx, count, count); err != nil {
		return "store: " + err.Error()
	}
	return strconv.FormatUint(n, 10)
}

// rssLoss reports whether x says a record was dropped after the kernel: a loss record of the store, a "lost" record of
// the collector's queue, or a stats record whose counts since the collector started hold a loss, which also counts a
// "lost" record given way. A health record that does not read counts too: it may be one.
func rssLoss(x rawrecord.Record) bool {
	switch x.Provider {
	case store.LossProvider:
		return true
	case store.HealthProvider:
		h, ok := decodeHealth(x.Data)
		return !ok || h.kind == "lost" ||
			h.kind == "stats" && (h.lost == nil || h.lostHealth == nil || *h.lost > 0 || *h.lostHealth > 0)
	}
	return false
}

// longRunning are the services of units, the comma-separated unit files balistidUnits lists, that rss_mib
// sums: not a oneshot, by the Type typeOf reads, and not the range's own but its litewitness and the agent's
// stand-in, which local mode puts on the host (ADR 0043).
func longRunning(units string, typeOf func(string) string) []string {
	var out []string
	for _, u := range strings.Split(units, ",") {
		ours := !strings.HasPrefix(u, "balistid-range-") || rangevm.RSSUnits()[u]
		if strings.HasSuffix(u, ".service") && ours && typeOf(u) != "oneshot" {
			out = append(out, u)
		}
	}
	return out
}

// rssMax is what an RSS trial's samples found: when each began, the largest sum of the recorder's units and the
// fewest processes any of them held in one, the most OOM events each unit's cgroup showed, and the largest sum of
// auditd's cgroup or why there is none.
type rssMax struct {
	at                     []time.Time
	samples, kib, auditKiB uint64
	procsMin               int
	oom                    []uint64
	auditWhy               string
	err                    error
}

// sample adds one sum of cgroups under root and one of auditd's; a recorder's cgroup that cannot be read ends the
// samples, auditd's only its trend.
func (m *rssMax) sample(root string, cgroups, auditd []string) {
	kib, procs, oom, err := cgroupSum(root, cgroups, "VmRSS")
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
	if len(m.oom) != len(oom) {
		m.oom = make([]uint64, len(oom))
	}
	for i, n := range oom {
		m.oom[i] = max(m.oom[i], n)
	}
	if a, _, _, err := cgroupSum(root, auditd, "VmRSS"); err != nil {
		m.auditWhy = err.Error()
	} else {
		m.auditKiB = max(m.auditKiB, a)
	}
}

// oomEvents is the sum over the units' cgroups of the most OOM events each showed.
func (m rssMax) oomEvents() uint64 {
	var n uint64
	for _, v := range m.oom {
		n += v
	}
	return n
}

// sampleRSS samples once before it returns, so before the load the caller starts next, then every every until stop,
// which returns what the samples found and when each began by now; an error ends them early.
func sampleRSS(ctx context.Context, every time.Duration, now func() time.Time, sample func(*rssMax)) (stop func() rssMax) {
	var m rssMax
	m.at = append(m.at, now())
	sample(&m)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan rssMax, 1)
	go func() {
		tick := time.NewTicker(every)
		defer tick.Stop()
		for m.err == nil {
			select {
			case <-ctx.Done():
				done <- m
				return
			case <-tick.C:
			}
			m.at = append(m.at, now())
			sample(&m)
		}
		done <- m
	}()
	return func() rssMax { cancel(); return <-done }
}

// loadGap is the longest time in ms from the load's start to its end that lies between two samples, or why the
// samples do not cover it: none at or before its start, or none at or after its end. Samples of the drain cover
// only the time from the load's last sample to its end.
func loadGap(at []time.Time, from, to time.Time) string {
	switch {
	case len(at) == 0 || at[0].After(from):
		return "no sample before the load"
	case at[len(at)-1].Before(to):
		return "no sample after the load"
	}
	var longest time.Duration
	for i := 1; i < len(at); i++ {
		if at[i].After(from) && at[i-1].Before(to) {
			longest = max(longest, at[i].Sub(at[i-1]))
		}
	}
	return strconv.FormatInt(longest.Milliseconds(), 10)
}

// cgroupSum sums under root the status field (VmRSS or VmHWM) of every process in cgroups, their child cgroups
// included, each process once; procs is how many each cgroup held and oom the oom and oom_kill events of its
// memory.events, which count its children's too. A process gone or exited before its status was read holds no
// memory and is skipped; a cgroup or its memory.events that cannot be read is an error, never a sum without it.
func cgroupSum(root string, cgroups []string, field string) (kib uint64, procs []int, oom []uint64, err error) {
	seen := map[string]bool{}
	for _, cg := range cgroups {
		if !strings.HasPrefix(cg, "/") || cg == "/" {
			return 0, nil, nil, fmt.Errorf("cgroup %q is not a unit's", cg)
		}
		dir := filepath.Join(root, "sys/fs/cgroup", cg)
		events, err := os.ReadFile(filepath.Join(dir, "memory.events")) //nolint:gosec // a unit's cgroup under /sys/fs/cgroup, or a test's
		if err != nil {
			return 0, nil, nil, fmt.Errorf("cgroup %s: %w", cg, err)
		}
		n, err := oomCount(string(events))
		if err != nil {
			return 0, nil, nil, fmt.Errorf("cgroup %s: %w", cg, err)
		}
		oom = append(oom, n)
		held := 0
		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
				return err
			}
			data, err := os.ReadFile(path) //nolint:gosec // a unit's cgroup under /sys/fs/cgroup, or a test's
			if err != nil {
				return err //nolint:wrapcheck // the caller names the cgroup
			}
			for _, pid := range strings.Fields(string(data)) {
				if _, err := strconv.ParseUint(pid, 10, 31); err != nil {
					return fmt.Errorf("%q is not a pid", pid)
				}
				if seen[pid] {
					continue
				}
				seen[pid] = true
				v, ok, err := statusKiB(root, pid, field)
				if err != nil {
					return err
				}
				if ok {
					kib, held = kib+v, held+1
				}
			}
			return nil
		})
		if err != nil {
			return 0, nil, nil, fmt.Errorf("cgroup %s: %w", cg, err)
		}
		procs = append(procs, held)
	}
	return kib, procs, oom, nil
}

// oomCount is the sum of the oom and oom_kill counts of a cgroup's memory.events; each must be there once.
func oomCount(events string) (uint64, error) {
	counts := map[string]uint64{}
	for _, line := range strings.Split(events, "\n") {
		key, value, _ := strings.Cut(line, " ")
		if key != "oom" && key != "oom_kill" {
			continue
		}
		v, err := strconv.ParseUint(value, 10, 32)
		if _, twice := counts[key]; err != nil || twice {
			return 0, fmt.Errorf("memory.events %s %q", key, value)
		}
		counts[key] = v
	}
	if len(counts) != 2 {
		return 0, errors.New("memory.events without oom and oom_kill")
	}
	return counts["oom"] + counts["oom_kill"], nil
}

// statusKiB is the status field (VmRSS, VmHWM) in KiB of pid under root; ok is false for a process gone, or exited,
// that holds none.
func statusKiB(root, pid, field string) (kib uint64, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(root, "proc", pid, "status")) //nolint:gosec // a pid's status under /proc, or a test's
	switch {
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("pid %s: %w", pid, err)
	}
	v := rangeguest.StatusField(string(data), field)
	if v == "" {
		return 0, false, nil
	}
	digits, unit := strings.CutSuffix(v, " kB")
	n, err := strconv.ParseUint(digits, 10, 64)
	if !unit || err != nil {
		return 0, false, fmt.Errorf("pid %s: %s %q", pid, field, v)
	}
	return n, true, nil
}
