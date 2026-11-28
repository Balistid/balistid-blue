package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// agentTree is a store whose runs need SPAWNED_BY to be told apart: the agent, a shell it spawned and three
// runs under that shell, one with pid 300; another process that reuses pid 300 and its child; a run whose spawner
// is not in the store, one whose spawner is root's, a detached probe that systemd spawned, and a probe a subshell
// of the agent's shell ran, a fork without an exec that Laurel names by its start time only.
func agentTree(t *testing.T) *testStore {
	t.Helper()
	ts := newTestStore(t, 16<<20)
	ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b1"}})
	ts.own("health", map[string]any{"state": "OK"})
	ev := func(s uint64) string { return `"EVENT_ID":"` + eventOf(s) + `"` }
	before := `"START_TIME":"1795340000.000"`
	for _, e := range []execSpec{
		{serial: 10, pid: 100, ppid: 50, exe: agentExe, spawner: before, spawnPID: 50, spawnExe: "/usr/bin/bash"},
		{serial: 11, pid: 101, ppid: 100, exe: "/usr/bin/bash", spawner: ev(10), spawnPID: 100, spawnExe: agentExe},
		{serial: 12, pid: 102, ppid: 101, exe: "/tmp/p/s1p-t-d00", spawner: ev(11), spawnPID: 101, spawnExe: "/usr/bin/bash"},
		{serial: 13, pid: 300, ppid: 101, exe: "/usr/bin/make", spawner: ev(11), spawnPID: 101, spawnExe: "/usr/bin/bash"},
		{serial: 14, pid: 300, ppid: 77, exe: "/usr/bin/vim", spawner: before, spawnPID: 77, spawnExe: "/usr/bin/bash"},
		{serial: 15, pid: 301, ppid: 300, exe: "/usr/bin/less", spawner: ev(14), spawnPID: 300, spawnExe: "/usr/bin/vim"},
		{serial: 16, pid: 302, ppid: 9, exe: "/usr/bin/orphan", spawner: ev(999), spawnPID: 9, spawnExe: "/usr/bin/bash"},
		{serial: 17, pid: 303, ppid: 1, uid: 0, exe: "/usr/bin/sudo", spawner: before, spawnPID: 1, spawnExe: "/usr/bin/bash"},
		{serial: 18, pid: 304, ppid: 303, exe: "/usr/bin/id", spawner: ev(17), spawnPID: 303, spawnExe: "/usr/bin/sudo"},
		{serial: 19, pid: 305, ppid: 1, exe: "/tmp/p/s1p-t-x00", spawner: `"START_TIME":"1795340001.000"`, spawnPID: 1,
			spawnExe: "/usr/lib/systemd/systemd"},
		{serial: 20, pid: 307, ppid: 306, exe: "/tmp/p/s1p-t-s00", spawner: `"START_TIME":"1795340002.000"`, spawnPID: 306,
			spawnExe: "/usr/bin/bash"},
	} {
		if e.uid == 0 && e.serial != 17 {
			e.uid = 1000
		}
		e.ok = true
		ts.laurel(e.serial, e.line())
	}
	ts.seal(true)
	return ts
}

func writeManifest(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "probes.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// manifestOf is a manifest as the probes' runner writes one: its tag, a session id, whether the unit ran probes,
// and every probe with its time in RFC 3339 with an offset.
func manifestOf(tag string, void bool, probes ...[2]string) string {
	var list []string
	for i, p := range probes {
		at := time.Date(2026, 11, 28, 10, 59, i, 189e6, time.UTC).Format("2006-01-02T15:04:05.000-07:00")
		list = append(list, fmt.Sprintf(`{"name":%q,"kind":%q,"at":%q,"ran":true}`, p[0], p[1], at))
	}
	extra := ""
	if void {
		extra = ` "void": "the probes ran twice",`
	}
	return fmt.Sprintf(`{%s "tag": %q, "session": "00000000-0000-4000-8000-000000000000", "unit_probes": false,`+
		` "probes": [%s]}`, extra, tag, strings.Join(list, ","))
}

func treeManifests(t *testing.T, void bool) []string {
	t.Helper()
	return []string{
		writeManifest(t, manifestOf("t", false, [2]string{"s1p-t-d00", kindDirect}, [2]string{"s1p-t-d01", kindDirect},
			[2]string{"s1p-t-x00", kindDetached})),
		writeManifest(t, manifestOf("u", void, [2]string{"s1p-t-s00", kindSubshell})),
	}
}

func viewOf(t *testing.T, out string, manifests ...string) viewDoc {
	t.Helper()
	var b bytes.Buffer
	if err := view(out, manifests, owners(), &b); err != nil {
		t.Fatal(err)
	}
	var v viewDoc
	if err := strictDecode(b.Bytes(), &v); err != nil {
		t.Fatalf("view output: %v\n%s", err, b.Bytes())
	}
	return v
}

func TestViewAssignsThroughSpawnedBy(t *testing.T) {
	ts := agentTree(t)
	status, out, err := judgeOnce(t, ts.dir, nil)
	if status != statusComplete || err != nil {
		t.Fatal(status, err)
	}
	v := viewOf(t, out, treeManifests(t, false)...)
	if v.Covers.Status != statusComplete || v.Covers.Runs != 10 || v.Covers.Clean != "KNOWN" {
		t.Errorf("covers %+v", v.Covers)
	}
	var programs []string
	for _, p := range v.Programs.Names {
		programs = append(programs, fmt.Sprintf("%s:%d", p.Name, p.Count))
	}
	if got := strings.Join(programs, " "); got != "bash:1 make:1 s1p-t-d00:1" || v.Programs.Total != 3 {
		t.Errorf("programs under agents %s of %d", got, v.Programs.Total)
	}
	c := v.Clean
	if c.Runs != 10 || c.UnderAgent != 3 || c.EndedObserved != 5 || c.Broken != 2 || c.BrokenShown != 2 {
		t.Errorf("clean %+v", c)
	}
	var brokenNames []string
	for _, r := range c.BrokenRuns {
		brokenNames = append(brokenNames, r.Name)
	}
	if got := strings.Join(brokenNames, " "); got != "orphan id" {
		t.Errorf("broken chains %s, want the run whose spawner is missing and the one whose spawner is root's", got)
	}
	if len(c.Top) != 3 || c.Once.Total != 3 {
		t.Errorf("top %v, once %v", c.Top, c.Once)
	}
	p := v.Probes
	if p == nil || p.Direct != (kindCount{Count: 2, Found: 1, Assigned: 1}) ||
		p.Detached != (kindCount{Count: 1, Found: 1}) || p.Subshell != (kindCount{Count: 1, Found: 1}) {
		t.Fatalf("probes %+v", p)
	}
	for _, e := range p.Each {
		if e.Name == "s1p-t-d01" && (e.Runs != 0 || e.Assigned) {
			t.Errorf("a probe the store lacks: %+v", e)
		}
	}
}

// TestRecycledPIDIsNotTheParent: by pid and ppid alone less would be under the agent, through make's pid 300; and
// the subshell's probe is not called outside an agent, only a chain that ended at a process Laurel observed.
func TestRecycledPIDIsNotTheParent(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	runs := readExec(t, out)
	where := assign(runs)
	want := map[string]string{"less": endedObserved, "make": underAgent, "s1p-t-s00": endedObserved,
		"orphan": broken}
	for i, r := range runs {
		if w, ok := want[r.Name]; ok && where[i] != w {
			t.Errorf("%s is %s, want %s", r.Name, where[i], w)
		}
	}
}

func TestViewRefusesAVoidManifest(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	var b bytes.Buffer
	err := view(out, treeManifests(t, true), owners(), &b)
	if err == nil || !strings.Contains(err.Error(), "the manifest is void") || b.Len() != 0 {
		t.Errorf("a void manifest: %v, %q", err, b.String())
	}
	if code := run(t.Context(), append([]string{"view", out}, treeManifests(t, true)...)); code != 2 {
		t.Errorf("exit %d", code)
	}
}

// TestManifestsAsTheProbesWriteThem: the two manifests of step S1 as written (direct and detached; subshell), with
// the same shape and kinds, decode; a name in both is refused.
func TestManifestsAsTheProbesWriteThem(t *testing.T) {
	var first, second [][2]string
	for i := range 30 {
		first = append(first, [2]string{fmt.Sprintf("s1p-9c9aec54-d%02d", i), kindDirect})
	}
	for i := range 10 {
		first = append(first, [2]string{fmt.Sprintf("s1p-9c9aec54-x%02d", i), kindDetached})
		second = append(second, [2]string{fmt.Sprintf("s1p-98357f1c-s%02d", i), kindSubshell})
	}
	a := writeManifest(t, manifestOf("9c9aec54", false, first...))
	b := writeManifest(t, manifestOf("98357f1c", false, second...))
	probes, err := readManifests([]string{a, b})
	if err != nil || len(probes) != 50 {
		t.Fatalf("%d probes, %v", len(probes), err)
	}
	if _, err := readManifests([]string{a, a}); err == nil || !strings.Contains(err.Error(), "two manifests") {
		t.Errorf("a name in two manifests: %v", err)
	}
}

// TestRealManifests decodes the manifests named in BALISTID_JUDGE_MANIFESTS, separated by colons; they stay off the
// repository, as they name the session that ran them.
func TestRealManifests(t *testing.T) {
	list := os.Getenv("BALISTID_JUDGE_MANIFESTS")
	if list == "" {
		t.Skip("BALISTID_JUDGE_MANIFESTS is not set")
	}
	probes, err := readManifests(strings.Split(list, ":"))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, p := range probes {
		kinds[p.Kind]++
	}
	t.Logf("%d probes: %v", len(probes), kinds)
}

func TestManifestIsDecodedStrictly(t *testing.T) {
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for name, body := range map[string]string{
		"unknown field":   `{"tag":"t","session":"s","unit_probes":false,"probes":[],"extra":1}`,
		"no probe":        `{"tag":"t","session":"s","unit_probes":false,"probes":[]}`,
		"repeated name":   `{"tag":"t","session":"s","unit_probes":false,"probes":[{"name":"a","kind":"direct","at":"` + at + `","ran":true},{"name":"a","kind":"direct","at":"` + at + `","ran":true}]}`,
		"name outside":    `{"tag":"t","session":"s","unit_probes":false,"probes":[{"name":"a b","kind":"direct","at":"` + at + `","ran":true}]}`,
		"kind":            `{"tag":"t","session":"s","unit_probes":false,"probes":[{"name":"a","kind":"other","at":"` + at + `","ran":true}]}`,
		"time":            `{"tag":"t","session":"s","unit_probes":false,"probes":[{"name":"a","kind":"direct","at":"now","ran":true}]}`,
		"void null":       `{"void":null,"tag":"t","session":"s","unit_probes":false,"probes":[{"name":"a","kind":"direct","at":"` + at + `","ran":true}]}`,
		"trailing object": `{"tag":"t","session":"s","unit_probes":false,"probes":[{"name":"a","kind":"direct","at":"` + at + `","ran":true}]}{}`,
	} {
		if _, err := decodeManifest([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestViewReadsOnlyTheJudgesFiles: a run whose name is outside the alphabet, an unknown field, a torn last line, a
// file others can write or a link is refused, so view never prints what the judge did not write.
func TestViewReadsOnlyTheJudgesFiles(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	execPath := filepath.Join(out, execFile)
	orig, err := os.ReadFile(execPath) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	line := orig[:bytes.IndexByte(orig, '\n')+1]
	for name, bad := range map[string][]byte{
		"name outside": append(append([]byte(nil), orig...), bytes.Replace(line, []byte(`"name":"`), []byte(`"name":"/`), 1)...),
		"argument":     append(append([]byte(nil), orig...), bytes.Replace(line, []byte(`"name":`), []byte(`"argv":["x"],"name":`), 1)...),
		"schema":       append(append([]byte(nil), orig...), bytes.Replace(line, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)...),
		"torn":         orig[:len(orig)-1],
	} {
		if bytes.Equal(bad, orig) {
			t.Fatalf("%s: the edit does not apply", name)
		}
		if err := os.WriteFile(execPath, bad, 0o644); err != nil { //nolint:gosec // as the judge writes it
			t.Fatal(err)
		}
		err := view(out, nil, owners(), &bytes.Buffer{})
		if err == nil || strings.Contains(err.Error(), "%!") {
			t.Errorf("%s: %v", name, err)
		}
		if name == "torn" && (err == nil || !strings.Contains(err.Error(), "torn")) {
			t.Errorf("a torn line: %v", err)
		}
	}
	if err := os.WriteFile(execPath, orig, 0o644); err != nil { //nolint:gosec // as the judge writes it
		t.Fatal(err)
	}
	if err := os.Chmod(execPath, 0o666); err != nil { //nolint:gosec // a file others can write, refused
		t.Fatal(err)
	}
	if err := view(out, nil, owners(), &bytes.Buffer{}); err == nil {
		t.Error("a file others can write: accepted")
	}
	link := t.TempDir()
	for _, f := range []string{stateFile, execFile} {
		if err := os.Symlink(filepath.Join(out, f), filepath.Join(link, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := view(link, nil, owners(), &bytes.Buffer{}); err == nil {
		t.Error("links: accepted")
	}
}

// TestViewReadsOnlyItsOwnersFiles: a file of a uid neither the collector's nor the caller's is UNKNOWN.
func TestViewReadsOnlyItsOwnersFiles(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	me := uint32(os.Getuid()) //nolint:gosec // a uid is 32 bits on Linux
	if err := view(out, nil, []uint32{me + 1}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("another uid's files: %v", err)
	}
	if err := view(out, nil, []uint32{me + 1, me}, &bytes.Buffer{}); err != nil {
		t.Errorf("the caller's files: %v", err)
	}
	if got := owners(); got[0] != me {
		t.Errorf("owners %v do not start with the caller", got)
	}
}

// editState rewrites state.json through f, as a file of the judge's.
func editState(t *testing.T, out string, f func(*stateDoc)) {
	t.Helper()
	d := readStateDoc(t, out)
	f(&d)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, stateFile), b, 0o644); err != nil { //nolint:gosec // as the judge writes it
		t.Fatal(err)
	}
}

// TestViewRefusesAStateItCannotSearch: clean intervals out of order, or another schema, are refused with a reason
// that reads.
func TestViewRefusesAStateItCannotSearch(t *testing.T) {
	ts := threeShards(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	if d := readStateDoc(t, out); len(d.Clean.Intervals) < 2 {
		t.Fatalf("clean %+v", d.Clean)
	}
	editState(t, out, func(d *stateDoc) {
		iv := d.Clean.Intervals
		iv[0], iv[1] = iv[1], iv[0]
	})
	if err := view(out, nil, owners(), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "clean interval") {
		t.Errorf("intervals out of order: %v", err)
	}
	editState(t, out, func(d *stateDoc) {
		iv := d.Clean.Intervals
		iv[0], iv[1] = iv[1], iv[0]
		d.Schema = 2
	})
	err := view(out, nil, owners(), &bytes.Buffer{})
	if err == nil || strings.Contains(err.Error(), "%!") || !strings.Contains(err.Error(), "schema 1") {
		t.Errorf("schema 2: %v", err)
	}
}

// TestViewOfAnUnknownState prints what it covers, the reason and no clean count when the judge could not read.
func TestViewOfAnUnknownState(t *testing.T) {
	_, out, err := judgeOnce(t, filepath.Join(t.TempDir(), "missing"), nil)
	if err == nil {
		t.Fatal("a missing store read")
	}
	v := viewOf(t, out)
	if v.Covers.Status != statusUnknown || v.Covers.Reason == "" || v.Clean.State != statusUnknown ||
		v.Clean.Reason == "" || v.Clean.Runs != 0 {
		t.Errorf("%+v", v)
	}
}

// TestListsAreCapped: past listMax names a list shows listMax of them and says how many there are.
func TestListsAreCapped(t *testing.T) {
	var runs []execRun
	var where []string
	for i := range listMax + 5 {
		runs = append(runs, execRun{Schema: 1, Time: timeText(int64(i)), Name: fmt.Sprintf("p%d", i)})
		where = append(where, underAgent)
	}
	p := programs(runs, where)
	c := cleanView(cleanDoc{State: "KNOWN", Intervals: []interval{{From: timeText(0), To: timeText(int64(listMax + 5))}}}, runs, where)
	if p.Shown != listMax || p.Total != listMax+5 || len(p.Names) != listMax || c.Once.Shown != listMax ||
		c.Once.Total != listMax+5 || len(c.Top) != topN {
		t.Errorf("programs %d of %d, once %d of %d, top %d", p.Shown, p.Total, c.Once.Shown, c.Once.Total, len(c.Top))
	}
}

func FuzzDecodeManifest(f *testing.F) {
	f.Add([]byte(manifestOf("t", false, [2]string{"a", kindDirect})))
	f.Add([]byte(manifestOf("t", true, [2]string{"a", kindSubshell})))
	f.Fuzz(func(t *testing.T, data []byte) {
		probes, err := decodeManifest(data)
		if err != nil {
			return
		}
		var top map[string]json.RawMessage
		if json.Unmarshal(data, &top) == nil {
			if _, void := top["void"]; void {
				t.Fatal("a void manifest decoded")
			}
		}
		for _, p := range probes {
			if !nameAlphabet.MatchString(p.Name) {
				t.Fatalf("probe name %q", p.Name)
			}
		}
	})
}

func FuzzDecodeRuns(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"time":"2026-11-28T10:59:26.189Z","serial":1,"pid":2,"ppid":1,"uid":1000,` +
		`"process":{"event_id":"1.000:1"},"spawned_by":{"start_time":"1.000","pid":1},"name":"true","agent":false,` +
		`"spawner_agent":true}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		runs, err := decodeRuns(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, r := range runs {
			if !nameAlphabet.MatchString(r.Name) {
				t.Fatalf("name %q", r.Name)
			}
		}
		_ = assign(runs)
	})
}
