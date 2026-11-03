package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/collector"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// fakeRoot writes files, path relative to a new root and its content, and returns the root.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, data := range files {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	collectorCG = "/system.slice/balistid-collector.service"
	ledgerCG    = "/system.slice/balistid-ledger.service"
	auditdCG    = "/system.slice/auditd.service"
)

// rssTree is a collector with a child cgroup, a pid gone since the listing and a zombie, a ledger, and auditd
// with Laurel, each cgroup with its memory.events.
func rssTree() map[string]string {
	cg := "sys/fs/cgroup"
	events := "low 0\nhigh 0\nmax 7\noom 0\noom_kill 0\noom_group_kill 0\n"
	return map[string]string{
		cg + collectorCG + "/cgroup.procs":     "10\n11\n13\n",
		cg + collectorCG + "/memory.events":    events,
		cg + collectorCG + "/sub/cgroup.procs": "12\n",
		cg + ledgerCG + "/cgroup.procs":        "20\n",
		cg + ledgerCG + "/memory.events":       events,
		cg + auditdCG + "/cgroup.procs":        "30\n31\n",
		cg + auditdCG + "/memory.events":       events,
		"proc/10/status":                       "Name:\tbalistid-collec\nVmPeak:\t  900000 kB\nVmHWM:\t  150000 kB\nVmRSS:\t  100000 kB\n",
		"proc/12/status":                       "Name:\thelper\nVmHWM:\t       9 kB\nVmRSS:\t       5 kB\n",
		"proc/13/status":                       "Name:\tbalistid-collec\nState:\tZ (zombie)\n",
		"proc/20/status":                       "Name:\tbalistid-ledger\nVmHWM:\t   40000 kB\nVmRSS:\t   30000 kB\n",
		"proc/30/status":                       "Name:\tauditd\nVmRSS:\t    2000 kB\n",
		"proc/31/status":                       "Name:\tlaurel\nVmRSS:\t    7000 kB\n",
	}
}

// The sum is every live process of each unit's cgroup tree, each once; a pid gone or a zombie adds nothing, and
// Laurel, auditd's plugin and so in its cgroup, counts with it. The peaks sum VmHWM the same way.
func TestCgroupSumSumsEachUnitsProcesses(t *testing.T) {
	root := fakeRoot(t, rssTree())
	kib, procs, oom, err := cgroupSum(root, []string{collectorCG, ledgerCG}, "VmRSS")
	if err != nil || kib != 130005 || !slices.Equal(procs, []int{2, 1}) || !slices.Equal(oom, []uint64{0, 0}) {
		t.Errorf("product: %d KiB, procs %v, oom %v, %v; want 130005, [2 1], [0 0]", kib, procs, oom, err)
	}
	if kib, _, _, err := cgroupSum(root, []string{collectorCG, ledgerCG}, "VmHWM"); err != nil || kib != 190009 {
		t.Errorf("peaks: %d KiB, %v; want 190009", kib, err)
	}
	kib, procs, _, err = cgroupSum(root, []string{auditdCG}, "VmRSS")
	if err != nil || kib != 9000 || !slices.Equal(procs, []int{2}) {
		t.Errorf("auditd: %d KiB, procs %v, %v; want 9000, [2]", kib, procs, err)
	}
	if kib, _, _, err := cgroupSum(root, []string{collectorCG, collectorCG}, "VmRSS"); err != nil || kib != 100005 {
		t.Errorf("a cgroup twice: %d KiB, %v", kib, err)
	}
}

// Each cgroup's OOM events are its memory.events' oom and oom_kill, its children's included.
func TestCgroupSumReadsOOMEvents(t *testing.T) {
	files := rssTree()
	files["sys/fs/cgroup"+ledgerCG+"/memory.events"] = "low 0\nhigh 0\nmax 9\noom 2\noom_kill 1\noom_group_kill 0\n"
	_, _, oom, err := cgroupSum(fakeRoot(t, files), []string{collectorCG, ledgerCG}, "VmRSS")
	if err != nil || !slices.Equal(oom, []uint64{0, 3}) {
		t.Errorf("oom %v, %v; want [0 3]", oom, err)
	}
}

// A cgroup or its memory.events that cannot be read, a line of cgroup.procs that is no pid, or a VmRSS not in kB
// is an error, never a sum without it.
func TestCgroupSumFailsOnWhatItCannotRead(t *testing.T) {
	cg := "sys/fs/cgroup"
	for name, c := range map[string]struct {
		change  map[string]string
		cgroups []string
	}{
		"cgroup gone":           {nil, []string{collectorCG, "/system.slice/balistid-relay.service"}},
		"no cgroup":             {nil, []string{""}},
		"the root cgroup":       {nil, []string{"/"}},
		"relative":              {nil, []string{"system.slice/balistid-ledger.service"}},
		"not a pid":             {map[string]string{cg + ledgerCG + "/cgroup.procs": "20\n../10\n"}, []string{ledgerCG}},
		"VmRSS in pages":        {map[string]string{"proc/20/status": "VmRSS:\t30000\n"}, []string{ledgerCG}},
		"VmRSS not a number":    {map[string]string{"proc/20/status": "VmRSS:\t-1 kB\n"}, []string{ledgerCG}},
		"VmRSS over 64 bits":    {map[string]string{"proc/20/status": "VmRSS:\t18446744073709551616 kB\n"}, []string{ledgerCG}},
		"no oom_kill":           {map[string]string{cg + ledgerCG + "/memory.events": "oom 0\n"}, []string{ledgerCG}},
		"no oom":                {map[string]string{cg + ledgerCG + "/memory.events": "oom_kill 0\n"}, []string{ledgerCG}},
		"oom not a number":      {map[string]string{cg + ledgerCG + "/memory.events": "oom x\noom_kill 0\n"}, []string{ledgerCG}},
		"oom_kill not a number": {map[string]string{cg + ledgerCG + "/memory.events": "oom 0\noom_kill -1\n"}, []string{ledgerCG}},
		"oom twice":             {map[string]string{cg + ledgerCG + "/memory.events": "oom 0\noom 0\n"}, []string{ledgerCG}},
	} {
		files := rssTree()
		for k, v := range c.change {
			files[k] = v
		}
		if kib, procs, _, err := cgroupSum(fakeRoot(t, files), c.cgroups, "VmRSS"); err == nil {
			t.Errorf("%s: %d KiB, procs %v, no error", name, kib, procs)
		}
	}
	files := rssTree()
	delete(files, "sys/fs/cgroup"+ledgerCG+"/memory.events")
	if _, _, _, err := cgroupSum(fakeRoot(t, files), []string{ledgerCG}, "VmRSS"); err == nil {
		t.Error("no memory.events: no error")
	}
	if _, _, _, err := cgroupSum(fakeRoot(t, rssTree()), []string{ledgerCG}, "VmRSS"); err != nil {
		t.Errorf("the sound tree: %v", err)
	}
}

// A sample keeps the largest sums, the fewest processes of any unit and the most OOM events of each cgroup; a
// recorder's cgroup not read ends the samples, auditd's leaves only its trend without a number.
func TestRSSSamples(t *testing.T) {
	files := rssTree()
	root := fakeRoot(t, files)
	write := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var m rssMax
	m.sample(root, []string{collectorCG, ledgerCG}, []string{auditdCG})
	write("proc/10/status", "VmRSS:\t300000 kB\n")
	write("sys/fs/cgroup"+ledgerCG+"/memory.events", "oom 1\noom_kill 1\n")
	if err := os.Remove(filepath.Join(root, "proc/20/status")); err != nil {
		t.Fatal(err)
	}
	m.sample(root, []string{collectorCG, ledgerCG}, []string{"/system.slice/gone.service"})
	write("sys/fs/cgroup"+ledgerCG+"/memory.events", "oom 0\noom_kill 0\n") // a cgroup made again counts from 0
	m.sample(root, []string{collectorCG, ledgerCG}, []string{auditdCG})
	if m.err != nil || m.samples != 3 || m.kib != 300005 || m.procsMin != 0 || m.auditKiB != 9000 || m.auditWhy == "" ||
		m.oomEvents() != 2 {
		t.Errorf("samples %+v", m)
	}
	m.sample(root, []string{"/system.slice/gone.service"}, nil)
	if m.err == nil || m.samples != 3 || m.oomEvents() != 2 {
		t.Errorf("a recorder's cgroup gone: %+v", m)
	}
}

// The sampler takes its first sample before it returns, then samples until stopped, noting when each began, and
// stops at the first error.
func TestSampleRSSRunsUntilStopped(t *testing.T) {
	calls := 0
	stop := sampleRSS(t.Context(), time.Millisecond, time.Now, func(m *rssMax) { calls++; m.samples++ })
	if calls != 1 {
		t.Fatalf("%d samples when sampleRSS returned, want 1", calls)
	}
	time.Sleep(20 * time.Millisecond)
	if m := stop(); m.samples < 2 || m.samples != uint64(calls) || len(m.at) != calls ||
		!slices.IsSortedFunc(m.at, func(a, b time.Time) int { return a.Compare(b) }) {
		t.Errorf("%d samples of %d calls at %v", m.samples, calls, m.at)
	}
	stop = sampleRSS(t.Context(), time.Millisecond, time.Now, func(m *rssMax) {
		if m.samples++; m.samples == 3 {
			m.err = errors.New("gone")
		}
	})
	time.Sleep(20 * time.Millisecond)
	if m := stop(); m.err == nil || m.samples != 3 || len(m.at) != 3 {
		t.Errorf("after an error: %+v", m)
	}
	stop = sampleRSS(t.Context(), time.Hour, time.Now, func(m *rssMax) { m.err = errors.New("gone") })
	if m := stop(); m.err == nil || len(m.at) != 1 {
		t.Errorf("an error in the first sample: %+v", m)
	}
}

// The load is covered from a sample at or before its start to one at or after its end; the longest step between
// two samples around any moment of it counts, and samples of the drain cover only up to its end.
func TestLoadGap(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(ms ...int64) []time.Time {
		out := make([]time.Time, len(ms))
		for i, v := range ms {
			out[i] = t0.Add(time.Duration(v) * time.Millisecond)
		}
		return out
	}
	from, to := t0.Add(time.Second), t0.Add(11*time.Second)
	for _, c := range []struct {
		name string
		at   []time.Time
		want string
	}{
		{"every second", at(0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11000, 12000), "1000"},
		{"a step of 3 s in the load", at(500, 1500, 4500, 5500, 6500, 7500, 8500, 9500, 10500, 11500), "3000"},
		{"the step across the end", at(900, 2900, 4900, 6900, 8900, 10500, 13700), "3200"},
		{"none during the load, dense drain", at(0, 11000, 11100, 11200, 11300), "11000"},
		{"the first after the start", at(1001, 2000, 3000), "no sample before the load"},
		{"none at the end", at(0, 1000, 2000, 10999), "no sample after the load"},
		{"none", nil, "no sample before the load"},
		{"steps before the load do not count", at(-9000, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11000), "1000"},
	} {
		if got := loadGap(c.at, from, to); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The collector's queue is the -queue-bytes of its argv in each form the flag package takes, the default without
// one, and why not when it cannot be told.
func TestQueueFlag(t *testing.T) {
	argv := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	bin := "/usr/local/lib/balistid/balistid-collector"
	for _, c := range []struct{ cmdline, want string }{
		{argv(bin, "-store", "/s", "-log-commits", "-queue-bytes", "8388608"), "8388608"},
		{argv(bin, "-queue-bytes=8388608", "-log-commits"), "8388608"},
		{argv(bin, "--queue-bytes", "4096"), "4096"},
		{argv(bin, "--queue-bytes=0x800000"), "0x800000"},
		{argv(bin, "-store", "/s", "-canary", "/c"), strconv.Itoa(64 << 20)},
		{argv(bin, "-store", "/s", "--", "-queue-bytes", "1"), strconv.Itoa(64 << 20)},
		{argv(bin), strconv.Itoa(64 << 20)},
		{argv(bin, "-queue-bytes"), "-queue-bytes without a value"},
		{argv(bin, "-queue-bytes", "1", "-queue-bytes=2"), "-queue-bytes given 2 times"},
		{argv(bin, "-queue-bytes-x", "1"), strconv.Itoa(64 << 20)},
	} {
		if got := queueFlag(c.cmdline); got != c.want {
			t.Errorf("%q: %q, want %q", c.cmdline, got, c.want)
		}
	}
	if rangevm.CollectorQueueBytes != collector.QueueBytes {
		t.Errorf("the default %d is not the collector's %d", rangevm.CollectorQueueBytes, collector.QueueBytes)
	}
}

// A drop after the kernel is a loss record of the store, a "lost" record of the collector, or a stats record with
// a loss since start; a health record that does not read may be one. Laurel's records and the rest are not.
func TestRSSLoss(t *testing.T) {
	h := func(body string) rawrecord.Record { return rawrecord.New(1, store.HealthProvider, 0, 1, []byte(body)) }
	for name, c := range map[string]struct {
		x    rawrecord.Record
		loss bool
	}{
		"a store's loss record":     {rawrecord.New(1, store.LossProvider, 0, 1, []byte(`{}`)), true},
		"a collector's lost record": {h(`{"schema_version":1,"kind":"lost","stage":"queue","count":3}`), true},
		"stats with a loss":         {h(`{"schema_version":1,"kind":"stats","lost":1,"lost_health":0}`), true},
		"stats with a lost health":  {h(`{"schema_version":1,"kind":"stats","lost":0,"lost_health":2}`), true},
		"stats with a null loss":    {h(`{"schema_version":1,"kind":"stats","lost":null,"lost_health":0}`), true},
		"an unreadable health":      {h(`{"schema_version":9,"kind":"stats"}`), true},
		"stats without loss":        {h(`{"schema_version":1,"kind":"stats","lost":0,"lost_health":0}`), false},
		"a health record":           {h(`{"schema_version":1,"kind":"health","state":"OK"}`), false},
		"Laurel's record":           {rawrecord.New(1, store.SensorProvider, 1, 1, []byte(`{"kind":"lost"}`)), false},
	} {
		if got := rssLoss(c.x); got != c.loss {
			t.Errorf("%s: loss %v, want %v", name, got, c.loss)
		}
	}
}

// rss_mib sums the image's long-running balistid services and the range's litewitness and agent (ADR 0043):
// not a socket, another range unit or a oneshot.
func TestLongRunningUnits(t *testing.T) {
	types := map[string]string{"balistid-net.service": "oneshot", "balistid-announce.service": "oneshot",
		"balistid-collector.service": "notify", "balistid-auditstat.service": "exec", "balistid-range-witness.service": "simple",
		"balistid-range-witness-agent.service": "notify", "balistid-range-ntfy.service": "simple"}
	units := "balistid-announce.service,balistid-auditstat.service,balistid-collector.service,balistid-collector.socket," +
		"balistid-net.service,balistid-range-ntfy.service,balistid-range-witness.service,balistid-range-witness-agent.service"
	got := longRunning(units, func(u string) string { return types[u] })
	if want := []string{"balistid-auditstat.service", "balistid-collector.service", "balistid-range-witness.service",
		"balistid-range-witness-agent.service"}; !slices.Equal(got, want) {
		t.Errorf("long-running %v, want %v", got, want)
	}
	if got := longRunning("", func(string) string { return "" }); len(got) != 0 || strings.Join(got, "") != "" {
		t.Errorf("no units: %v", got)
	}
}
