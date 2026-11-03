package main

import (
	"context"
	"encoding/json"
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

// oomInjection is rss-oom-control's injection: the ledger's MemoryMax, until the VM ends, far below what it holds,
// so the kernel OOM-kills it at once and at each restart (ADR 0054).
var oomInjection = []string{"set-property", "--runtime", ledgerUnit, "MemoryMax=1M"}

// rssDrainWait bounds how long an RSS trial waits for the store to catch up with its load. Laurel holds 2 MB records
// at about 4 MB/s on one core (ADR 0054), so a backlog it builds drains no faster than the load came.
func rssDrainWait(kind string) time.Duration {
	if kind == rangejob.LoadExecLarge {
		return 3 * time.Minute
	}
	return cpuDrainWait
}

// rssReadyWait bounds how long an RSS trial waits for every unit it samples to run: the guest starts after the
// collector, ledger and auditstat only, and a unit that failed at boot waits its RestartSec (the Pi's watcher 30 s).
const rssReadyWait = 2 * time.Minute

// runRSS generates the trial's load and, every rssEvery from before it until it drained, sums the VmRSS of every
// process of the image's long-running balistid services, and of auditd's cgroup, Laurel in it, as a trend
// (rss_mib, ADR 0054). It reports the facts it has also when the run is not whole, so the host finds a MISS in them:
// the sums, the VmHWM at the end, the OOM events and the collector's queue; what dropped part of the load after the
// kernel; and rss_run, "ok" or every reason the run is not whole. Every unit is read before the store, whose read
// stops the collector and the units after it.
func runRSS(ctx context.Context, tr rangejob.Trial, r *report) error {
	units := longRunning(balistidUnits(ctx), func(u string) string {
		return strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "Type", u))
	})
	if len(units) == 0 {
		return r.fail("no long-running balistid service")
	}
	state := func(u string) string {
		return strings.Join(strings.Fields(output(ctx, "/usr/bin/systemctl", "show", "--value", "-p", "ActiveState,SubState,NRestarts", u)), "/")
	}
	if err := untilRunning(ctx, units, state, rssReadyWait, time.Second); err != nil {
		return r.fail(err.Error())
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
	lostBefore, overflowBefore := lost(), stateLine(ctx, rangeguest.StateOverflow)
	auditd := []string{sampleUnit(ctx, auditdUnitName).cgroup}
	stop := sampleRSS(ctx, rssEvery, time.Now, func(m *rssMax) { m.sample("/", cgroups, auditd) })
	var injectErr error
	if tr.Inject == rangejob.InjectOOM {
		injectErr = systemctl(ctx, oomInjection...)
	}
	from := time.Now()
	generated, windowMin, genErr := rangeguest.Generate(tr.Load.Rate, tr.Load.Seconds, emit, rangeguest.WallClock)
	genErr = errors.Join(genErr, wait())
	to := time.Now()
	var drainErr error
	if genErr == nil {
		// auditd's queue first: the kernel's backlog empties while 2 MB records still wait there for Laurel, and
		// the units' memory counts until they reached the store.
		if drainErr = auditIdle(ctx, "rss drain", rssDrainWait(tr.Load.Kind)); drainErr == nil {
			drainErr = drained(w, time.Now, func() string {
				return rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["backlog"]
			}, rssDrainWait(tr.Load.Kind))
		}
	}
	m := stop()
	var runErrs []string
	note := func(what string, err error) {
		if err != nil {
			runErrs = append(runErrs, what+err.Error())
		}
	}
	note("OOM injection: ", injectErr)
	note("generator: ", genErr)
	note("", drainErr)
	note("rss: ", m.err)
	hwm, err := m.final("/", cgroups)
	note("VmHWM: ", err)
	same := "same"
	for _, unit := range units {
		if _, why := used(before[unit], sampleUnit(ctx, unit)); why != "" && same == "same" {
			same = unit + ": " + why
		}
	}
	journalOOM, err := oomJournal(ctx, units)
	note("OOM journal: ", err)
	lostAfter, overflowAfter := lost(), stateLine(ctx, rangeguest.StateOverflow)
	lostRecords, err := storeLosses(ctx, from.UnixNano(), time.Now().UnixNano()) // last: the read stops the collector
	if err != nil {
		reportCollector(ctx, os.Stdout, output)
	}
	note("store: ", err)
	run := "ok"
	if len(runErrs) > 0 {
		run = strings.Join(runErrs, "; ")
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactGenerated, u(generated))
	r.add(rangevm.FactWindowMin, u(windowMin))
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, lostAfter)
	r.add(rangevm.FactOverflowBefore, overflowBefore)
	r.add(rangevm.FactOverflowAfter, overflowAfter)
	r.add(rangevm.FactLostRecords, u(lostRecords))
	r.add(rangevm.FactUnits, same)
	r.add(rangevm.FactRSSRun, run)
	r.add(rangevm.FactRSSUnits, strings.Join(units, ","))
	r.add(rangevm.FactRSSSamples, u(m.samples))
	r.add(rangevm.FactRSSLoadGapMS, loadGap(m.at, from, to))
	r.add(rangevm.FactRSSProcsMin, strconv.Itoa(m.procsMin))
	r.add(rangevm.FactRSSMaxKiB, u(m.kib))
	r.add(rangevm.FactRSSHWMKiB, u(hwm))
	// Both counts for the host's log, as the OOM control proves each path in a real kill.
	hostLine(os.Stdout, "rss oom: %d in the units' memory.events, %d in the journal", m.oomEvents(), journalOOM)
	r.add(rangevm.FactRSSOOM, u(m.oomEvents()+journalOOM)) // a journal not read cannot unsay the cgroups' events
	r.add(rangevm.FactRSSQueueBytes, queue)
	audit := u(m.auditKiB)
	if m.auditWhy != "" {
		audit = m.auditWhy
	}
	r.add(rangevm.FactRSSAuditKiB, audit)
	return r.send(r.facts)
}

// untilRunning waits up to wait, polling every poll, until state, "ActiveState/SubState/..." of a unit, shows each of
// units active, or says which was not and how.
func untilRunning(ctx context.Context, units []string, state func(string) string, wait, poll time.Duration) error {
	for deadline := time.Now().Add(wait); ; {
		down := ""
		for _, u := range units {
			if s := state(u); !strings.HasPrefix(s, "active/") {
				down = fmt.Sprintf("%s is %q", u, s)
				break
			}
		}
		switch {
		case down == "":
			return nil
		case !time.Now().Before(deadline):
			return fmt.Errorf("not running %s after the boot: %s", wait, down)
		case !pause(ctx, poll):
			return fmt.Errorf("waiting for %s: %w", down, ctx.Err())
		}
	}
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

// storeLosses reads the store once and counts the records that say part of the load was dropped after the kernel
// between from and to (ns, the load's start and the read's), before or behind the read's barrier (rssLoss), printing
// each; a read that failed returns those it counted and why.
func storeLosses(ctx context.Context, from, to int64) (uint64, error) {
	log := &lossLog{w: os.Stdout}
	count := func(x rawrecord.Record) error {
		if rssLoss(x, from, to) != "" {
			log.add(x)
		}
		return nil
	}
	err := readStore(ctx, count, count)
	log.done()
	return uint64(log.n), err //nolint:gosec // a count, never negative
}

// rssLoss says which loss x is, or "" when it is none of the load's: any loss record of the store, whose disk the load
// filled; a "lost" record of the collector whose span from first_at to last_at, the collector's clock, meets from to
// to, so not a loss before the load or of the read's own stop of the collector; or a health record that does not read,
// which may be one. The collector's stats count health records given way too, which are no records of the load (T25),
// and repeat its "lost" records, so they are not read.
func rssLoss(x rawrecord.Record, from, to int64) string {
	switch x.Provider {
	case store.LossProvider:
		return fmt.Sprintf("of the store: %.120q", x.Data)
	case store.HealthProvider:
		var raw map[string]json.RawMessage
		var schema int
		var kind, stage string
		var count uint64
		var first, last int64
		if json.Unmarshal(x.Data, &raw) != nil || json.Unmarshal(raw["schema_version"], &schema) != nil || schema != healthSchema {
			return fmt.Sprintf("unreadable: %.120q", x.Data)
		}
		if k, has := raw["kind"]; has && json.Unmarshal(k, &kind) != nil {
			return fmt.Sprintf("unreadable: %.120q", x.Data)
		}
		if kind != "lost" { // the store's own notes have no kind
			return ""
		}
		if json.Unmarshal(raw["stage"], &stage) != nil || json.Unmarshal(raw["count"], &count) != nil ||
			json.Unmarshal(raw["first_at"], &first) != nil || json.Unmarshal(raw["last_at"], &last) != nil {
			return fmt.Sprintf("lost, unreadable: %.120q", x.Data)
		}
		if last < from || first >= to {
			return ""
		}
		return fmt.Sprintf("lost at stage %q: %d records from %d to %d", stage, count, first, last)
	}
	return ""
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
	m.kib = max(m.kib, kib) // what was read counts also when another cgroup was not: a MISS outranks the INVALID
	m.mergeOOM(oom)
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
	if a, _, _, err := cgroupSum(root, auditd, "VmRSS"); err != nil {
		m.auditWhy = err.Error()
	} else {
		m.auditKiB = max(m.auditKiB, a)
	}
}

// mergeOOM keeps for each unit's cgroup the most OOM events a read of them, in cgroups' order, showed.
func (m *rssMax) mergeOOM(oom []uint64) {
	if len(m.oom) < len(oom) {
		m.oom = append(m.oom, make([]uint64, len(oom)-len(m.oom))...)
	}
	for i, n := range oom {
		m.oom[i] = max(m.oom[i], n)
	}
}

// final is the units' summed VmHWM at the end of the run, and adds the OOM events that read showed: one after the
// last sample counts as much as any. Both count what was read also when a cgroup was not, with why.
func (m *rssMax) final(root string, cgroups []string) (uint64, error) {
	hwm, _, oom, err := cgroupSum(root, cgroups, "VmHWM")
	m.mergeOOM(oom)
	return hwm, err
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
// memory.events, which count its children's too, both in cgroups' order. A process gone or exited before its status
// was read holds no memory and is skipped. A cgroup or its memory.events that cannot be read is an error, never a
// clean sum without it; the sum and events of the cgroups that were read still come with it, as evidence that only
// adds memory or events (a MISS) and never makes a run whole.
func cgroupSum(root string, cgroups []string, field string) (kib uint64, procs []int, oom []uint64, err error) {
	seen := map[string]bool{}
	procs, oom = make([]int, len(cgroups)), make([]uint64, len(cgroups))
	var errs []error
	for i, cg := range cgroups {
		if !strings.HasPrefix(cg, "/") || cg == "/" {
			errs = append(errs, fmt.Errorf("cgroup %q is not a unit's", cg))
			continue
		}
		dir := filepath.Join(root, "sys/fs/cgroup", cg)
		events, err := os.ReadFile(filepath.Join(dir, "memory.events")) //nolint:gosec // a unit's cgroup under /sys/fs/cgroup, or a test's
		if err == nil {
			oom[i], err = oomCount(string(events))
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("cgroup %s: %w", cg, err))
			continue
		}
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
					kib, procs[i] = kib+v, procs[i]+1
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("cgroup %s: %w", cg, err))
		}
	}
	return kib, procs, oom, errors.Join(errs...)
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
