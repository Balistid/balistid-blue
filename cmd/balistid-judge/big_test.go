package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/shard"
)

// TestBigStore reads a store of at least BALISTID_JUDGE_BIG_GIB GiB (1 by default) built under the directory
// BALISTID_JUDGE_BIG, on a disk rather than a tmpfs, and reports the judge's rate; it runs only when that is set.
// The store's shards are copied into the same directory, as the unit copies them into its own /tmp.
func TestBigStore(t *testing.T) {
	dir := os.Getenv("BALISTID_JUDGE_BIG")
	if dir == "" {
		t.Skip("BALISTID_JUDGE_BIG is not set")
	}
	gib := 1.0
	if v := os.Getenv("BALISTID_JUDGE_BIG_GIB"); v != "" {
		var err error
		if gib, err = strconv.ParseFloat(v, 64); err != nil {
			t.Fatal(err)
		}
	}
	work, err := os.MkdirTemp(dir, "judge-big-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) }) //nolint:gosec // the test's own directory under BALISTID_JUDGE_BIG
	storeDir := filepath.Join(work, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil { //nolint:gosec // under the directory the maintainer names
		t.Fatal(err)
	}
	ts := &testStore{t: t, dir: storeDir, max: 256 << 20}
	ts.open(ts.max)
	ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b1"}})
	ts.own("health", map[string]any{"state": "OK"})
	want := int64(gib * (1 << 30))
	built := time.Now()
	var written int64
	for serial := uint64(1); written < want; serial++ {
		line := otherLine(serial, "balistid-open")
		if serial%3 == 0 {
			line = execSpec{serial: serial, pid: 4000, ppid: 3999, uid: 1000, exe: "/usr/bin/make", ok: true,
				spawner: `"EVENT_ID":"` + eventOf(serial-3) + `"`, spawnPID: 3999, spawnExe: "/usr/bin/bash"}.line()
		}
		ts.laurel(serial, line)
		written += int64(len(line))
		if serial%100000 == 0 {
			ts.own("stats", map[string]any{"max_lag_ms": 3})
		}
	}
	ts.seal(true)
	t.Logf("built %.2f GiB of records in %s", float64(written)/(1<<30), time.Since(built).Round(time.Second))
	out := filepath.Join(work, "out")
	if err := os.Mkdir(out, 0o755); err != nil { //nolint:gosec // the results directory, as the unit's StateDirectoryMode
		t.Fatal(err)
	}
	scratch := filepath.Join(work, "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil { //nolint:gosec // under the directory the maintainer names
		t.Fatal(err)
	}
	start := time.Now()
	status, err := judge(t.Context(), config{Store: storeDir, Out: out,
		Scratch: shard.Scratch{Dir: scratch, Max: 512<<20 + shard.WALMaxBytes}, Now: time.Now, Limit: readLimit})
	took := time.Since(start)
	if status != statusComplete || err != nil {
		t.Fatalf("status %s, %v", status, err)
	}
	d := readStateDoc(t, out)
	mib := float64(d.Store.Bytes) / (1 << 20)
	rate := mib / took.Seconds()
	t.Logf("judged %d shards, %.0f MiB, in %s: %.1f MiB/s, 100 GiB in about %.0f min; %d runs listed",
		len(d.Read), mib, took.Round(time.Second), rate, 100*1024/rate/60, totalOf(d.Days).Exec.Listed)
	if took > readLimit {
		t.Errorf("took %s, over the read limit", took)
	}
	checkSums(t, storeDir, out)
}
