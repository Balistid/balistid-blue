package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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
// with Laurel.
func rssTree() map[string]string {
	cg := "sys/fs/cgroup"
	return map[string]string{
		cg + collectorCG + "/cgroup.procs":     "10\n11\n13\n",
		cg + collectorCG + "/memory.peak":      "999999\n",
		cg + collectorCG + "/sub/cgroup.procs": "12\n",
		cg + ledgerCG + "/cgroup.procs":        "20\n",
		cg + auditdCG + "/cgroup.procs":        "30\n31\n",
		"proc/10/status":                       "Name:\tbalistid-collec\nVmPeak:\t  900000 kB\nVmRSS:\t  100000 kB\n",
		"proc/12/status":                       "Name:\thelper\nVmRSS:\t       5 kB\n",
		"proc/13/status":                       "Name:\tbalistid-collec\nState:\tZ (zombie)\n",
		"proc/20/status":                       "Name:\tbalistid-ledger\nVmRSS:\t   30000 kB\n",
		"proc/30/status":                       "Name:\tauditd\nVmRSS:\t    2000 kB\n",
		"proc/31/status":                       "Name:\tlaurel\nVmRSS:\t    7000 kB\n",
	}
}

// The sum is every live process of each unit's cgroup tree, each once; a pid gone or a zombie adds nothing, and
// Laurel, listed in auditd's cgroup too, counts once.
func TestRSSKiBSumsEachUnitsProcesses(t *testing.T) {
	root := fakeRoot(t, rssTree())
	kib, procs, err := rssKiB(root, []string{collectorCG, ledgerCG}, nil)
	if err != nil || kib != 130005 || !slices.Equal(procs, []int{2, 1}) {
		t.Errorf("product: %d KiB, procs %v, %v; want 130005, [2 1]", kib, procs, err)
	}
	kib, procs, err = rssKiB(root, []string{auditdCG}, []string{"31"})
	if err != nil || kib != 9000 || !slices.Equal(procs, []int{2}) {
		t.Errorf("auditd: %d KiB, procs %v, %v; want 9000, [2]", kib, procs, err)
	}
	if kib, _, err := rssKiB(root, []string{auditdCG}, []string{"10"}); err != nil || kib != 109000 {
		t.Errorf("auditd and a pid outside it: %d KiB, %v", kib, err)
	}
}

// A cgroup that cannot be read, a line of cgroup.procs that is no pid, or a VmRSS not in kB is an error, never a
// sum without it.
func TestRSSKiBFailsOnWhatItCannotRead(t *testing.T) {
	for name, c := range map[string]struct {
		change  map[string]string
		cgroups []string
		pids    []string
	}{
		"cgroup gone":        {nil, []string{collectorCG, "/system.slice/balistid-relay.service"}, nil},
		"no cgroup":          {nil, []string{""}, nil},
		"the root cgroup":    {nil, []string{"/"}, nil},
		"relative":           {nil, []string{"system.slice/balistid-ledger.service"}, nil},
		"not a pid":          {map[string]string{"sys/fs/cgroup" + ledgerCG + "/cgroup.procs": "20\n../10\n"}, []string{ledgerCG}, nil},
		"no laurel":          {nil, []string{auditdCG}, []string{""}},
		"VmRSS in pages":     {map[string]string{"proc/20/status": "VmRSS:\t30000\n"}, []string{ledgerCG}, nil},
		"VmRSS not a number": {map[string]string{"proc/20/status": "VmRSS:\t-1 kB\n"}, []string{ledgerCG}, nil},
		"VmRSS over 64 bits": {map[string]string{"proc/20/status": "VmRSS:\t18446744073709551616 kB\n"}, []string{ledgerCG}, nil},
	} {
		files := rssTree()
		for k, v := range c.change {
			files[k] = v
		}
		if kib, procs, err := rssKiB(fakeRoot(t, files), c.cgroups, c.pids); err == nil {
			t.Errorf("%s: %d KiB, procs %v, no error", name, kib, procs)
		}
	}
	if _, _, err := rssKiB(fakeRoot(t, rssTree()), []string{ledgerCG}, nil); err != nil {
		t.Errorf("the sound tree: %v", err)
	}
}

// A sample keeps the largest sums and the fewest processes of any unit; a recorder's cgroup not read ends the
// samples, auditd's leaves only its trend without a number.
func TestRSSSamples(t *testing.T) {
	files := rssTree()
	root := fakeRoot(t, files)
	var m rssMax
	m.sample(root, []string{collectorCG, ledgerCG}, []string{auditdCG}, []string{"31"})
	if err := os.WriteFile(filepath.Join(root, "proc/10/status"), []byte("VmRSS:\t300000 kB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "proc/20/status")); err != nil {
		t.Fatal(err)
	}
	m.sample(root, []string{collectorCG, ledgerCG}, []string{"/system.slice/gone.service"}, nil)
	if m.err != nil || m.samples != 2 || m.kib != 300005 || m.procsMin != 0 || m.auditKiB != 9000 || m.auditWhy == "" {
		t.Errorf("samples %+v", m)
	}
	m.sample(root, []string{"/system.slice/gone.service"}, nil, nil)
	if m.err == nil || m.samples != 2 {
		t.Errorf("a recorder's cgroup gone: %+v", m)
	}
}

// The sampler samples at once and until stopped, and stops at the first error.
func TestSampleRSSRunsUntilStopped(t *testing.T) {
	calls := 0
	stop := sampleRSS(t.Context(), time.Millisecond, func(m *rssMax) { calls++; m.samples++ })
	time.Sleep(20 * time.Millisecond)
	if m := stop(); m.samples < 2 || m.samples != uint64(calls) {
		t.Errorf("%d samples of %d calls", m.samples, calls)
	}
	stop = sampleRSS(t.Context(), time.Millisecond, func(m *rssMax) {
		if m.samples++; m.samples == 3 {
			m.err = errors.New("gone")
		}
	})
	time.Sleep(20 * time.Millisecond)
	if m := stop(); m.err == nil || m.samples != 3 {
		t.Errorf("after an error: %+v", m)
	}
}

// rss_mib sums the image's long-running balistid services: not a socket, a range unit or a oneshot.
func TestLongRunningUnits(t *testing.T) {
	types := map[string]string{"balistid-net.service": "oneshot", "balistid-announce.service": "oneshot",
		"balistid-collector.service": "notify", "balistid-auditstat.service": "exec", "balistid-range-witness.service": "simple"}
	units := "balistid-announce.service,balistid-auditstat.service,balistid-collector.service,balistid-collector.socket," +
		"balistid-net.service,balistid-range-witness.service"
	got := longRunning(units, func(u string) string { return types[u] })
	if want := []string{"balistid-auditstat.service", "balistid-collector.service"}; !slices.Equal(got, want) {
		t.Errorf("long-running %v, want %v", got, want)
	}
	if got := longRunning("", func(string) string { return "" }); len(got) != 0 || strings.Join(got, "") != "" {
		t.Errorf("no units: %v", got)
	}
}
