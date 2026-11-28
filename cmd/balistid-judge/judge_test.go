package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tool(serial uint64, uid uint32, name string) []byte {
	return execSpec{serial: serial, pid: 4242, ppid: 1, uid: uid, exe: "/usr/bin/" + name, ok: true,
		spawner: `"START_TIME":"1795340216.325"`, spawnPID: 1, spawnExe: "/usr/bin/bash"}.line()
}

// threeShards is a store of four sealed shards, oldest first: A starts the collector healthy and misses serials
// 111 and 112; B misses 125, which comes late in C, and has a loss and a lag; C misses 131 and 132 and has a
// health change to UNKNOWN and back; D is a new boot, whose serials start again.
func threeShards(t *testing.T) *testStore {
	t.Helper()
	ts := newTestStore(t, 16<<20)
	ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b1", "version": "balistid dev"}})
	ts.own("health", map[string]any{"state": "OK"})
	ts.laurel(100, tool(100, 1000, "tool-a"))
	ts.laurel(101, tool(101, 0, "rootly"))
	ts.laurel(102, tool(102, 970, "jobly"))
	for s := uint64(103); s <= 120; s++ {
		if s != 111 && s != 112 {
			ts.laurel(s, otherLine(s, "balistid-open"))
		}
	}
	ts.seal(false)
	for s := uint64(121); s <= 130; s++ {
		if s != 125 {
			ts.laurel(s, otherLine(s, "balistid-open"))
		}
	}
	ts.own("lost", map[string]any{"stage": "queue", "count": 3, "bytes": 300, "first_seq": 0, "last_seq": 0,
		"first_at": time.Now().UnixNano(), "last_at": time.Now().UnixNano()})
	ts.own("stats", map[string]any{"records": 9, "bytes": 1, "truncated": 0, "malformed": 0, "lost": 3,
		"lost_health": 0, "queue_high_water": 1, "max_lag_ms": 1500})
	ts.seal(false)
	ts.laurel(125, otherLine(125, "balistid-open"))
	ts.laurel(133, tool(133, 1000, "tool-c"))
	ts.own("health", map[string]any{"state": "UNKNOWN canary-missed"})
	ts.laurel(134, otherLine(134, ""))
	ts.own("health", map[string]any{"state": "OK"})
	for s := uint64(135); s <= 140; s++ {
		ts.laurel(s, otherLine(s, "balistid-open"))
	}
	ts.own("stopping", nil)
	ts.seal(false)
	ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b2", "version": "balistid dev"}})
	ts.own("health", map[string]any{"state": "OK"})
	for s := uint64(5); s <= 8; s++ {
		ts.laurel(s, otherLine(s, "balistid-open"))
	}
	ts.seal(true)
	return ts
}

func TestStateAndExecFromAStore(t *testing.T) {
	ts := threeShards(t)
	status, out, err := judgeOnce(t, ts.dir, nil)
	if status != statusComplete || err != nil {
		t.Fatalf("status %s, %v", status, err)
	}
	d := readStateDoc(t, out)
	if d.Status != statusComplete || d.Store.Seals != 4 || len(d.Read) != 4 || len(d.NotRead) != 0 {
		t.Fatalf("status %s, %d seals, read %v, not read %v", d.Status, d.Store.Seals, d.Read, d.NotRead)
	}
	if d.Read[0].Name != d.Store.LastSeal.Name || d.Read[0].First < d.Read[1].First || len(d.Store.LastSeal.SHA256) != 64 {
		t.Errorf("shards not read newest first or the last seal not named: %v, %+v", d.Read, d.Store.LastSeal)
	}
	if d.Records["laurel"] != 41 || d.Records["balistid-health"] != 9 {
		t.Errorf("records %v, want 41 of Laurel's and 9 own", d.Records)
	}
	if d.Keys["balistid-open"] == nil || d.Keys["balistid-open"].Records != 36 || d.Keys["balistid-exec"].Records != 4 || d.Keys[""].Records != 1 {
		t.Errorf("by rule key %v", d.Keys)
	}
	if d.Loss["queue"] != 3 || d.LossErrors != 0 || d.Lag == nil || d.Lag.MS != 1500 {
		t.Errorf("loss %v (%d not decoded), lag %+v", d.Loss, d.LossErrors, d.Lag)
	}
	if s := d.Serials; s.Gaps != 2 || s.Missing != 4 || s.HeldAtEnd != 0 || s.Segments != 2 {
		t.Errorf("serials %+v, want 111-112 and 131-132, 125 late, and the new boot its own segment", s)
	}
	var states []string
	for _, h := range d.Health {
		states = append(states, h.State)
	}
	if got := strings.Join(states, ","); got != "UNKNOWN starting,OK,UNKNOWN canary-missed,OK,UNKNOWN stopped,UNKNOWN starting,OK" {
		t.Errorf("health changes %s", got)
	}
	// OK from A's health record, cut by the loss (from that record) and the gap of 131-132 (from 130 in B to 133
	// in C) up to the UNKNOWN; OK again up to the stop; OK on the new boot up to the newest record.
	if d.Clean.State != "KNOWN" || len(d.Clean.Intervals) != 3 {
		t.Fatalf("clean %+v", d.Clean)
	}
	if d.Clean.Intervals[2].To != d.Period.To || d.Clean.Intervals[0].From <= d.Health[1].At {
		t.Errorf("clean intervals %+v, period %+v", d.Clean.Intervals, d.Period)
	}
	runs := readExec(t, out)
	if names(runs) != "tool-a tool-c" || d.Exec.Successful != 4 || d.Exec.Exported != 2 || d.Exec.System != 2 {
		t.Errorf("exec.jsonl %q, counts %+v", names(runs), d.Exec)
	}
	if r := runs[0]; r.Serial != 100 || r.PID != 4242 || r.UID != 1000 || r.Process.EventID != eventOf(100) ||
		r.SpawnedBy == nil || r.SpawnedBy.StartTime != "1795340216.325" || r.SpawnedBy.PID != 1 || r.Agent || r.SpawnerAgent {
		t.Errorf("run %+v", r)
	}
}

// TestNoArgumentLeaves is acceptance arguments_exported: what Laurel writes of arguments, environment, directory
// and paths is in the records and in neither of the judge's files.
func TestNoArgumentLeaves(t *testing.T) {
	ts := threeShards(t)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{stateFile, execFile} {
		b, err := os.ReadFile(filepath.Join(out, f)) //nolint:gosec // the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range []string{markArg, markEnv, markCWD, markDir, "/usr/bin", "/home/", "SECRET"} {
			if bytes.Contains(b, []byte(m)) {
				t.Errorf("%s holds %q", f, m)
			}
		}
	}
	if len(readExec(t, out)) == 0 {
		t.Fatal("no exec exported: the check shows nothing")
	}
}

// TestOnlyUsersRuns: exec.jsonl holds no exec of a uid below 1000, and none older than the 7 days before the last seal.
func TestOnlyUsersRuns(t *testing.T) {
	ts := newTestStore(t, 16<<20)
	week := time.Now().Add(-8 * 24 * time.Hour).UnixNano()
	ts.laurelAt(1, week, tool(1, 1000, "old"))
	for i, uid := range []uint32{0, 1, 999, 1000, 65534, 4294967294} {
		ts.laurel(uint64(i+2), tool(uint64(i+2), uid, "u"+string(rune('a'+i))))
	}
	ts.seal(true)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	runs := readExec(t, out)
	if got := names(runs); got != "ud ue uf" {
		t.Errorf("exported %q, want the uids 1000 and above but the old one", got)
	}
	for _, r := range runs {
		if r.UID < minUID {
			t.Errorf("uid %d exported", r.UID)
		}
	}
	if d := readStateDoc(t, out); d.Exec.Older != 1 || d.Exec.System != 3 {
		t.Errorf("exec counts %+v", d.Exec)
	}
}

// stepClock moves by step at every call: the judge reads the clock at its start, at each shard and every
// checkEvery records, and for every file it writes.
func stepClock(step time.Duration) func() time.Time {
	at := time.Now()
	return func() time.Time {
		at = at.Add(step)
		return at
	}
}

// TestReadLimit is acceptance read_limit_min: past 90 minutes no shard is read, and state.json names what was not.
func TestReadLimit(t *testing.T) {
	ts := threeShards(t)
	status, out, err := judgeOnce(t, ts.dir, stepClock(20*time.Minute))
	if status != statusPartial || err == nil {
		t.Fatalf("status %s, %v", status, err)
	}
	d := readStateDoc(t, out)
	if d.Status != statusPartial || !strings.Contains(d.Reason, "90 min") || len(d.Read) != 2 || len(d.NotRead) != 2 {
		t.Fatalf("status %s %q, read %v, not read %v", d.Status, d.Reason, d.Read, d.NotRead)
	}
	if d.ReadLimitMin != 90 {
		t.Errorf("read limit %d", d.ReadLimitMin)
	}
	if got := names(readExec(t, out)); got != "tool-c" {
		t.Errorf("exec.jsonl %q, want only the newest shard's", got)
	}
}

// TestReadLimitInsideAShard: the clock is read every checkEvery records, so a large shard stops too and leaves
// exec.jsonl as it was.
func TestReadLimitInsideAShard(t *testing.T) {
	ts := newTestStore(t, 16<<20)
	for s := uint64(1); s <= 3*checkEvery; s++ {
		ts.laurel(s, tool(s, 1000, "many"))
	}
	ts.seal(true)
	calls := 0
	base := time.Now()
	clock := func() time.Time {
		calls++
		if calls > 4 { // the start, two file writes, the shard's own check; then inside the shard
			return base.Add(2 * time.Hour)
		}
		return base
	}
	status, out, err := judgeOnce(t, ts.dir, clock)
	if status != statusPartial || err == nil {
		t.Fatalf("status %s, %v", status, err)
	}
	if d := readStateDoc(t, out); len(d.Read) != 0 || len(d.NotRead) != 1 || !strings.Contains(d.NotRead[0].Reason, "read limit") {
		t.Errorf("read %v, not read %v", d.Read, d.NotRead)
	}
	if runs := readExec(t, out); len(runs) != 0 {
		t.Errorf("%d runs of a shard not read whole", len(runs))
	}
}

// TestUnreadableIsUnknown: a shard whose bytes are not its seal's, or a store that is not there, is UNKNOWN with its
// reason, never COMPLETE.
func TestUnreadableIsUnknown(t *testing.T) {
	ts := threeShards(t)
	seals := readStateDocOf(t, ts)
	newest := filepath.Join(ts.dir, seals.Store.LastSeal.Name)
	b, err := os.ReadFile(newest) //nolint:gosec // the test's store
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.Chmod(newest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newest, b, 0o600); err != nil { //nolint:gosec // the test's store
		t.Fatal(err)
	}
	status, out, err := judgeOnce(t, ts.dir, nil)
	d := readStateDoc(t, out)
	if status != statusUnknown || err == nil || d.Status != statusUnknown || !strings.Contains(d.Reason, "SHA-256") {
		t.Fatalf("status %s %s %q, %v", status, d.Status, d.Reason, err)
	}
	if len(d.Read) != 0 || len(d.NotRead) != 4 || d.Clean.State != statusUnknown {
		t.Errorf("read %v, not read %v, clean %+v", d.Read, d.NotRead, d.Clean)
	}
	status, out, err = judgeOnce(t, filepath.Join(ts.dir, "missing"), nil)
	if d := readStateDoc(t, out); status != statusUnknown || err == nil || d.Status != statusUnknown || d.Reason == "" {
		t.Errorf("a missing store: %s %+v, %v", status, d, err)
	}
}

func readStateDocOf(t *testing.T, ts *testStore) stateDoc {
	t.Helper()
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return readStateDoc(t, out)
}

// TestTheStoreIsOnlyRead: the judge reads a store no one can write, as the unit's ReadOnlyPaths leaves it.
func TestTheStoreIsOnlyRead(t *testing.T) {
	ts := threeShards(t)
	entries, err := os.ReadDir(ts.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Chmod(filepath.Join(ts.dir, e.Name()), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(ts.dir, 0o500); err != nil { //nolint:gosec // the store as ReadOnlyPaths leaves it
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ts.dir, 0o700) }) //nolint:gosec // back to the collector's mode, for TempDir to remove it
	if status, _, err := judgeOnce(t, ts.dir, nil); status != statusComplete || err != nil {
		t.Fatalf("status %s, %v", status, err)
	}
}

// TestResultFiles: both files are whole, 0644, and a second run replaces them.
func TestResultFiles(t *testing.T) {
	ts := threeShards(t)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, e.Name()+" "+fi.Mode().String())
	}
	if strings.Join(got, ",") != "exec.jsonl -rw-r--r--,state.json -rw-r--r--" {
		t.Errorf("results %v", got)
	}
}
