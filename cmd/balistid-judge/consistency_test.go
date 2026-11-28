package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// TestAFailedLastWriteIsNotComplete: when the last state.json cannot be written, the one on disk still says READING,
// so the judge says UNKNOWN and exits 2, never COMPLETE and 0.
func TestAFailedLastWriteIsNotComplete(t *testing.T) {
	ts := newTestStore(t, 16<<20)
	ts.laurel(1, otherLine(1, "k"))
	ts.seal(true)
	out := t.TempDir()
	calls := 0
	clock := func() time.Time {
		calls++
		if calls == 5 { // the start, the first files, the shard's check, its state.json, the check after the last
			if err := os.Chmod(out, 0o500); err != nil { //nolint:gosec // a results directory no one can write to
				t.Fatal(err)
			}
		}
		return time.Now()
	}
	t.Cleanup(func() { _ = os.Chmod(out, 0o700) }) //nolint:gosec // back, for TempDir to remove it
	status, err := judge(t.Context(), config{Store: ts.dir, Out: out, Scratch: scratchOf(t), Now: clock, Limit: readLimit})
	if status == statusComplete || err == nil || exitCode(status, err) != 2 {
		t.Errorf("status %s, %v, exit %d", status, err, exitCode(status, err))
	}
	if exitCode(statusComplete, errors.New("x")) != 2 || exitCode(statusComplete, nil) != 0 {
		t.Error("exitCode")
	}
}

// TestStateGoesFirst: a run that cannot empty exec.jsonl has already replaced an earlier COMPLETE state.json, so no
// COMPLETE state stands beside a file of another run.
func TestStateGoesFirst(t *testing.T) {
	ts := threeShards(t)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(out, execFile), filepath.Join(t.TempDir(), "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(out, execFile), 0o700); err != nil { // the rename over it fails
		t.Fatal(err)
	}
	status, err := judge(t.Context(), config{Store: ts.dir, Out: out, Scratch: scratchOf(t), Now: time.Now, Limit: readLimit})
	if d := readStateDoc(t, out); err == nil || status == statusComplete || d.Status == statusComplete {
		t.Errorf("status %s, on disk %s, %v", status, d.Status, err)
	}
}

// TestViewNeedsOneRunsFiles: a state.json beside an exec.jsonl of fewer runs than a day lists is UNKNOWN, PARTIAL too;
// a READING one is refused, and one that changed while exec.jsonl was read is UNKNOWN.
func TestViewNeedsOneRunsFiles(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	orig, err := os.ReadFile(filepath.Join(out, execFile)) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, execFile), orig[:bytes.IndexByte(orig, '\n')+1], 0o644); err != nil { //nolint:gosec // as the judge writes it
		t.Fatal(err)
	}
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not one run's") {
		t.Errorf("a COMPLETE state beside one run: %v", err)
	}
	editState(t, out, func(d *stateDoc) { d.Status = statusPartial })
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not one run's") {
		t.Errorf("a PARTIAL state beside one run: %v", err)
	}
	editState(t, out, func(d *stateDoc) { d.Status, d.Days = statusPartial, nil })
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not one run's") {
		t.Errorf("a run of no day the state holds: %v", err)
	}
	editState(t, out, func(d *stateDoc) { d.Status = statusReading })
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "still writing") {
		t.Errorf("a READING state: %v", err)
	}
	if code := run(t.Context(), []string{"view", out}); code != 2 {
		t.Errorf("view of a READING state: exit %d", code)
	}
	root, err := os.OpenRoot(out)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // read-only
	_, before, err := readState(root, mine())
	if err != nil {
		t.Fatal(err)
	}
	if err := unchanged(root, before); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, stateFile)) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	if err := wholefile.WriteIn(root, stateFile, b, 0o644); err != nil { // the same bytes, another file
		t.Fatal(err)
	}
	if err := unchanged(root, before); err == nil {
		t.Error("a new state.json passed for the old")
	}
}

// TestViewCapsWhatItHolds: an exec.jsonl over its byte cap is refused before a line of it is read.
func TestViewCapsWhatItHolds(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	if err := os.Truncate(filepath.Join(out, execFile), execMax+1); err != nil { // sparse: no disk is used
		t.Fatal(err)
	}
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bytes, over") {
		t.Errorf("too many bytes: %v", err)
	}
}

// TestTheJudgeListsNoMoreThanViewReads: past maxRuns a run is counted as not listed, on its day; and the longest
// line the judge can write fits the bytes view allows a run.
func TestTheJudgeListsNoMoreThanViewReads(t *testing.T) {
	rd := newReader(math.MinInt64)
	var b bytes.Buffer
	rd.out = bufio.NewWriter(&b)
	rd.listed = maxRuns - 1
	for s := uint64(1); s <= 3; s++ {
		if err := rd.add(rawrecord.New(s, store.SensorProvider, s, base, tool(s, 1000, "x"))); err != nil {
			t.Fatal(err)
		}
	}
	if e := rowsOf(rd)[0].Exec; e.Listed != 1 || e.OverCap != 2 || rd.listed != maxRuns {
		t.Errorf("exec %+v, %d listed", e, rd.listed)
	}
	long := execRun{Schema: 1, EventTime: timeText(-1), Received: timeText(-1), Serial: math.MaxUint64, PID: math.MaxUint32,
		PPID: math.MaxUint32, UID: math.MaxUint32, Process: procKey{EventID: strings.Repeat("9", 20) + ".999:" + strings.Repeat("9", 20)},
		SpawnedBy: &spawner{procKey: procKey{EventID: strings.Repeat("9", 20) + ".999:" + strings.Repeat("9", 20)}, PID: math.MaxUint32},
		Name:      strings.Repeat("x", 64), Agent: true, SpawnerAgent: true}
	if line, err := json.Marshal(long); err != nil || len(line)+1 > execMax/maxRuns {
		t.Errorf("the longest line is %d bytes, %v", len(line)+1, err)
	}
}

// TestHealthChangesAreAList: none read is an empty list, and a list past the cap is empty with the reason.
func TestHealthChangesAreAList(t *testing.T) {
	st := newState(nil, 0, 0, 90)
	rd := newReader(math.MinInt64)
	b, err := json.Marshal(st.render(rd, 0))
	if err != nil || !bytes.Contains(b, []byte(`"health_changes":[]`)) || bytes.Contains(b, []byte("withheld")) ||
		!bytes.Contains(b, []byte(`"days":[]`)) {
		t.Errorf("%s %v", b, err)
	}
	rd.over = true
	if d := st.render(rd, 0); d.Health == nil || len(d.Health) != 0 || d.HealthHeld == "" {
		t.Errorf("over the cap: %+v %q", d.Health, d.HealthHeld)
	}
}

// TestASilenceAcrossShards: two shards 190 s apart are a silence, counted on the day of the later record.
func TestASilenceAcrossShards(t *testing.T) {
	ts := newTestStore(t, 16<<20)
	at := time.Now().Add(-time.Hour).UnixNano()
	ts.laurelAt(1, at, otherLine(1, "k"))
	ts.seal(false)
	ts.laurelAt(2, at+190*int64(time.Second), otherLine(2, "k"))
	ts.seal(true)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if all := totalOf(readStateDoc(t, out).Days); all.Silences != 1 {
		t.Errorf("silences %d", all.Silences)
	}
}
