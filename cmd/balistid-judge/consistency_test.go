package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
		if calls == 5 { // the start, the first files, the shard's check, its state.json; then the last one
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

// TestViewNeedsOneRunsFiles: a COMPLETE state.json beside an exec.jsonl of fewer runs is UNKNOWN; any other status
// gives the runs as partial and no clean count; a state.json that changed while exec.jsonl was read is UNKNOWN.
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
	editState(t, out, func(d *stateDoc) { d.Status = statusReading })
	v := viewOf(t, out)
	if v.Covers.Partial == "" || v.Clean.State != statusUnknown || v.Clean.Runs != 0 || v.Covers.Runs != 1 {
		t.Errorf("a READING state: %+v", v)
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

// TestViewCapsWhatItHolds: more runs than view holds are refused before exec.jsonl is read, and a file over its
// byte cap before a line of it is.
func TestViewCapsWhatItHolds(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	editState(t, out, func(d *stateDoc) { d.Exec.Exported = runsMax + 1 })
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "4194305 runs") {
		t.Errorf("too many runs: %v", err)
	}
	_, out, _ = judgeOnce(t, ts.dir, nil)
	if err := os.Truncate(filepath.Join(out, execFile), execMax+1); err != nil { // sparse: no disk is used
		t.Fatal(err)
	}
	if err := view(out, nil, mine(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bytes, over") {
		t.Errorf("too many bytes: %v", err)
	}
}

// TestHealthChangesAreAList: none read is an empty list, and a list past the cap is empty with the reason.
func TestHealthChangesAreAList(t *testing.T) {
	st := newState(nil, 0, 0, 90)
	b, err := json.Marshal(st.render(0))
	if err != nil || !bytes.Contains(b, []byte(`"health_changes":[]`)) || bytes.Contains(b, []byte("withheld")) {
		t.Errorf("%s %v", b, err)
	}
	st.over = true
	if d := st.render(0); d.Health == nil || len(d.Health) != 0 || d.HealthHeld == "" {
		t.Errorf("over the cap: %+v %q", d.Health, d.HealthHeld)
	}
}

// TestAnEmptyShardIsNoNeighbour: two shards 190 s apart with an empty one between them are a silence.
func TestAnEmptyShardIsNoNeighbour(t *testing.T) {
	sec := int64(time.Second)
	newer := accOf(t, rawrecord.New(0, store.SensorProvider, 2, 200*sec, otherLine(2, "k")))
	empty := accOf(t)
	older := accOf(t, own(store.HealthProvider, 5*sec, `{"schema_version":1,"kind":"health","state":"OK"}`),
		rawrecord.New(0, store.SensorProvider, 1, 10*sec, otherLine(1, "k")))
	st := newState([]store.Seal{{Name: "older"}, {Name: "empty"}, {Name: "newer"}}, 0, 0, 90)
	st.merge("newer", newer)
	st.merge("empty", empty)
	st.merge("older", older)
	d := st.render(0)
	for _, iv := range d.Clean.Intervals {
		if iv.From <= timeText(10*sec) && iv.To >= timeText(200*sec) {
			t.Errorf("clean %s to %s spans the silence", iv.From, iv.To)
		}
	}
	if d.Silences != 1 {
		t.Errorf("silences %d", d.Silences)
	}
}

// TestProbesOutsideThePeriod: a probe timed outside what the judge read is not assigned, and counted apart.
func TestProbesOutsideThePeriod(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	from, err := time.Parse(time.RFC3339Nano, readStateDoc(t, out).Period.From)
	if err != nil {
		t.Fatal(err)
	}
	m := writeManifest(t, manifestOf("t", false, from.Add(-time.Hour), [2]string{"s1p-t-d00", kindDirect}))
	v := viewOf(t, out, m)
	if v.Probes.Direct != (kindCount{Count: 1, Found: 1, OutOfPeriod: 1}) {
		t.Errorf("probes %+v", v.Probes.Direct)
	}
}
