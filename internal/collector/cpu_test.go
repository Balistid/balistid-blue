package collector

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUsageUsec(t *testing.T) {
	if n, err := UsageUsec("usage_usec 1234\nuser_usec 1000\nsystem_usec 234"); err != nil || n != 1234 {
		t.Errorf("%d, %v", n, err)
	}
	for _, s := range []string{"user_usec 1", "usage_usec x", "usage_usec -1", "error: open cpu.stat"} {
		if _, err := UsageUsec(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
	if _, err := UsageUsec("usage_usec " + strings.Repeat("9", 4000)); err == nil || len(err.Error()) > 64 {
		t.Errorf("an overlong value: %v", err)
	}
}

// Every balistid service deploy/ installs but the runner's counts in cpu_cores, so a new one is listed or
// this fails, and each stays in system.slice.
func TestCPUUnitsAreEveryFloor0Service(t *testing.T) {
	units, err := filepath.Glob("../../deploy/*/balistid-*.service")
	if err != nil || len(units) == 0 {
		t.Fatalf("%v %v", units, err)
	}
	for _, u := range units {
		name := filepath.Base(u)
		if !strings.HasPrefix(name, "balistid-runner") && !slices.Contains(CPUUnits, name) {
			t.Errorf("%s is not in CPUUnits", name)
		}
		b, err := os.ReadFile(u) //nolint:gosec // a glob of the repository's deploy/
		if err != nil || strings.Contains(string(b), "\nSlice=") {
			t.Errorf("%s: %v, or it leaves system.slice, where the collector reads it", name, err)
		}
	}
	if !slices.Contains(CPUUnits, "auditd.service") {
		t.Error("auditd, which holds Laurel, is not counted")
	}
}

// cgroups is a fake cgroup root: one directory per unit with its cpu.stat.
type cgroups struct {
	t    *testing.T
	root string
}

func (c cgroups) set(unit, stat string) {
	c.t.Helper()
	dir := filepath.Join(c.root, unit)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		c.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte(stat), 0o644); err != nil { //nolint:gosec // test cgroup
		c.t.Fatal(err)
	}
}

// replace is a unit's next invocation: systemd makes a new cgroup, so a new directory. The old one is moved
// aside, not removed, so the new one cannot take its inode.
func (c cgroups) replace(unit, stat string) {
	c.t.Helper()
	dir := filepath.Join(c.root, unit)
	if err := os.Rename(dir, filepath.Join(c.t.TempDir(), "old")); err != nil {
		c.t.Fatal(err)
	}
	c.set(unit, stat)
}

func cpuRig(t *testing.T) (*rig, cgroups) {
	t.Helper()
	r := newRig(t)
	cg := cgroups{t: t, root: t.TempDir()}
	r.w.CgroupRoot = cg.root
	r.w.Boottime = func() (uint64, error) { return 7e9, nil }
	r.w.Monotonic = func() (uint64, error) { return uint64(r.clock().UnixNano()), nil }
	cg.set("balistid-collector.service", "usage_usec 1")
	return r, cg
}

// unitOf is one unit's counters in a record's cpu field.
func unitOf(t *testing.T, rec map[string]any, unit string) map[string]any {
	t.Helper()
	c, ok := rec["cpu"].(map[string]any)
	if !ok {
		t.Fatalf("no cpu in %v", rec)
	}
	u, ok := c["units"].(map[string]any)[unit].(map[string]any)
	if !ok {
		t.Fatalf("no %s in %v", unit, c)
	}
	return u
}

func last(t *testing.T, r *rig, kind string) map[string]any {
	t.Helper()
	recs := r.st.kinds(kind)
	if len(recs) == 0 {
		t.Fatalf("no %s record", kind)
	}
	return recs[len(recs)-1]
}

// statsAfter steps d and one more tick, which commits the stats record d's tick noted.
func statsAfter(t *testing.T, r *rig, d time.Duration) map[string]any {
	t.Helper()
	r.step(d)
	r.step(0)
	return last(t, r, "stats")
}

// started holds each unit's counters at the start, stats every minute with both clocks, and a unit not installed
// is absent, never zero.
func TestCPUStartedAndStats(t *testing.T) {
	r, cg := cpuRig(t)
	cg.set("auditd.service", "usage_usec 500\nuser_usec 400")
	r.start(nil)
	r.settle()
	if u := unitOf(t, last(t, r, "started"), "auditd.service"); u["usec"] != 500.0 || u["absent"] != nil {
		t.Fatalf("started: %v", u)
	}
	cg.set("auditd.service", "usage_usec 900")
	stats := statsAfter(t, r, statsEvery)
	if u := unitOf(t, stats, "auditd.service"); u["usec"] != 900.0 || u["gone"] != 0.0 {
		t.Fatalf("stats: %v", u)
	}
	if u := unitOf(t, stats, "balistid-ledger.service"); u["absent"] != true || u["usec"] != nil {
		t.Fatalf("a missing unit: %v", u)
	}
	c := stats["cpu"].(map[string]any)
	if c["mono_ns"] != float64(time.Unix(0, noon).Add(statsEvery).UnixNano()) || c["boot_ns"] != 7e9 ||
		c["ncpu"].(float64) < 1 || c["err"] != nil {
		t.Fatalf("clocks: %v", c)
	}
}

// Without the collector's own cgroup the root is wrong, so the record says so instead of a zero for every unit.
func TestCPUOwnCgroupAbsentIsAnError(t *testing.T) {
	r, cg := cpuRig(t)
	if err := os.RemoveAll(filepath.Join(cg.root, "balistid-collector.service")); err != nil {
		t.Fatal(err)
	}
	r.start(nil)
	r.settle()
	if c := last(t, r, "started")["cpu"].(map[string]any); !strings.Contains(fmt.Sprint(c["err"]), "own cgroup") {
		t.Fatalf("%v", c)
	}
}

// An invocation ends with its cgroup gone, replaced or counting less; its last read moves to gone_usec, so the
// unit's CPU over the run is gone_usec plus usec.
func TestCPUInvocationEnds(t *testing.T) {
	for _, tc := range []struct {
		name string
		next func(cgroups)
		usec any
	}{
		{"replaced", func(c cgroups) { c.replace("auditd.service", "usage_usec 900") }, 900.0},
		{"counter back", func(c cgroups) { c.set("auditd.service", "usage_usec 30") }, 30.0},
		{"gone", func(c cgroups) {
			if err := os.RemoveAll(filepath.Join(c.root, "auditd.service")); err != nil {
				c.t.Fatal(err)
			}
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, cg := cpuRig(t)
			cg.set("auditd.service", "usage_usec 500")
			r.start(nil)
			r.settle()
			cg.set("auditd.service", "usage_usec 800")
			r.step(cpuEvery)
			tc.next(cg)
			u := unitOf(t, statsAfter(t, r, statsEvery), "auditd.service")
			if u["gone"] != 1.0 || u["gone_usec"] != 800.0 || u["usec"] != tc.usec ||
				u["gone_unread_ms"] != float64(statsEvery.Milliseconds()) {
				t.Fatalf("%v", u)
			}
		})
	}
}

// Every invocation that ends adds its last read and its unread time, across restarts.
func TestCPUInvocationsAddUp(t *testing.T) {
	r, cg := cpuRig(t)
	cg.set("auditd.service", "usage_usec 500")
	r.start(nil)
	r.settle()
	cg.replace("auditd.service", "usage_usec 40")
	r.step(cpuEvery)
	cg.replace("auditd.service", "usage_usec 70")
	r.step(2 * cpuEvery)
	u := unitOf(t, statsAfter(t, r, statsEvery), "auditd.service")
	if u["gone"] != 2.0 || u["gone_usec"] != 540.0 || u["usec"] != 70.0 || u["gone_unread_ms"] != 3000.0 {
		t.Fatalf("%v", u)
	}
}

// A read that fails but for an absent cgroup keeps the last good one and names the failure, in the record and
// once in the journal: the invocation may still run, so it does not end.
func TestCPUReadFailureKeepsTheLastRead(t *testing.T) {
	r, cg := cpuRig(t)
	var journal bytes.Buffer
	r.w.Log = slog.New(slog.NewTextHandler(&journal, nil))
	cg.set("auditd.service", "usage_usec 500")
	r.start(nil)
	r.settle()
	cg.set("auditd.service", "usage_usec x")
	r.step(cpuEvery)
	u := unitOf(t, statsAfter(t, r, statsEvery), "auditd.service")
	if u["usec"] != 500.0 || u["gone"] != 0.0 || !strings.Contains(u["err"].(string), "usage_usec") {
		t.Fatalf("%v", u)
	}
	if n := strings.Count(journal.String(), "unit CPU not read"); n != 1 {
		t.Fatalf("journaled %d times over two reads:\n%s", n, journal.String())
	}
	cg.set("auditd.service", "usage_usec 700")
	if u := unitOf(t, statsAfter(t, r, statsEvery), "auditd.service"); u["usec"] != 700.0 || u["err"] != nil || u["gone"] != 0.0 {
		t.Fatalf("after the failure: %v", u)
	}
}

// Units are read once a second, not on every tick: within a second a changed counter is not read yet.
func TestCPUReadsOncePerSecond(t *testing.T) {
	r, cg := cpuRig(t)
	cg.set("auditd.service", "usage_usec 500")
	r.start(nil)
	r.settle()
	cg.replace("auditd.service", "usage_usec 10")
	r.step(cpuEvery / 2)
	if u := r.w.cpu["auditd.service"]; u.gone != 0 || u.cur.usec != 500 {
		t.Fatalf("read before a second: %+v", u)
	}
	r.step(cpuEvery / 2)
	if u := r.w.cpu["auditd.service"]; u.gone != 1 || u.cur.usec != 10 {
		t.Fatalf("not read after a second: %+v", u)
	}
}

// stopping reads every unit again, however recent the last read, so the run's final counts are stored.
func TestCPUStoppingReadsAgain(t *testing.T) {
	r, cg := cpuRig(t)
	cg.set("auditd.service", "usage_usec 500")
	r.start(nil)
	r.settle()
	cg.set("auditd.service", "usage_usec 650")
	close(r.stop)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	if u := unitOf(t, last(t, r, "stopping"), "auditd.service"); u["usec"] != 650.0 {
		t.Fatalf("%v", u)
	}
}

// The largest cpu field, every unit at its largest counters and failing with the longest reason a read gives,
// fits a stats record in what the store takes, and a started record with every unit at its largest counter.
func TestCPURecordsFit(t *testing.T) {
	r, cg := cpuRig(t)
	for _, name := range CPUUnits {
		cg.set(name, "usage_usec 18446744073709551615")
	}
	r.start(nil)
	r.settle()
	if len(r.st.kinds("started")) != 1 {
		t.Fatal("started not stored")
	}
	long := func() (uint64, error) { return 0, errors.New("collector: CLOCK_BOOTTIME: " + strings.Repeat("x", 40)) }
	w := newRig(t).w
	w.CgroupRoot, w.Boottime, w.Monotonic, w.cpu = cg.root, long, long, map[string]*unitCPU{}
	for _, name := range CPUUnits {
		w.cpu[name] = &unitCPU{cur: cgroupUsage{math.MaxUint64, math.MaxUint64}, present: true,
			err: "cpu.stat: read cpu.stat: " + strings.Repeat("x", 64), gone: math.MaxUint64, goneUsec: math.MaxUint64,
			unreadMS: math.MaxUint64}
	}
	w.stats(time.Unix(0, noon))
	if len(w.notes) != 1 || w.lostNotes != 0 {
		t.Fatalf("%d stats noted, %d too large", len(w.notes), w.lostNotes)
	}
}
