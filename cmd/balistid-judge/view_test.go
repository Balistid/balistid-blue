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
// is not in the store, one whose spawner is root's, and a detached probe that systemd spawned.
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

func probesJSON(void bool) string {
	at := time.Now().UTC().Format(time.RFC3339Nano)
	extra := ""
	if void {
		extra = `"void": "the probes ran twice",`
	}
	return fmt.Sprintf(`{%s"tag":"t","session":"s","unit_probes":false,"probes":[`+
		`{"name":"s1p-t-d00","kind":"direct","at":%q,"ran":true},{"name":"s1p-t-d01","kind":"direct","at":%q,"ran":true},`+
		`{"name":"s1p-t-x00","kind":"detached","at":%q,"ran":true}]}`, extra, at, at, at)
}

func viewOf(t *testing.T, out, manifest string) viewDoc {
	t.Helper()
	var b bytes.Buffer
	if err := view(out, manifest, &b); err != nil {
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
	v := viewOf(t, out, writeManifest(t, probesJSON(false)))
	if v.Covers.Status != statusComplete || v.Covers.Runs != 9 || v.Covers.Clean != "KNOWN" {
		t.Errorf("covers %+v", v.Covers)
	}
	var programs []string
	for _, p := range v.Programs {
		programs = append(programs, fmt.Sprintf("%s:%d", p.Name, p.Count))
	}
	if got := strings.Join(programs, " "); got != "bash:1 make:1 s1p-t-d00:1" {
		t.Errorf("programs under agents %s", got)
	}
	c := v.Clean
	if c.Runs != 9 || c.UnderAgent != 3 || c.Outside != 4 || c.NotAssigned != 2 || c.Shown != 2 {
		t.Errorf("clean %+v", c)
	}
	var unassigned []string
	for _, r := range c.NotAssignedRun {
		unassigned = append(unassigned, r.Name)
	}
	if got := strings.Join(unassigned, " "); got != "orphan id" {
		t.Errorf("not assigned %s, want the run whose spawner is missing and the one whose spawner is root's", got)
	}
	if len(c.Top) != 3 || len(c.Once) != 3 {
		t.Errorf("top %v, once %v", c.Top, c.Once)
	}
	p := v.Probes
	if p == nil || p.Direct != 2 || p.DirectFound != 1 || p.DirectAssigned != 1 || p.Detached != 1 ||
		p.DetachedFound != 1 || p.DetachedAssigned != 0 {
		t.Fatalf("probes %+v", p)
	}
	for _, e := range p.Each {
		if e.Name == "s1p-t-d01" && (e.Runs != 0 || e.Assigned) {
			t.Errorf("a probe the store lacks: %+v", e)
		}
	}
}

// TestRecycledPIDIsNotTheParent: by pid and ppid alone less would be under the agent, through make's pid 300.
func TestRecycledPIDIsNotTheParent(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	runs := readExec(t, out)
	where := assign(runs)
	for i, r := range runs {
		if r.Name == "less" && where[i] != outside {
			t.Errorf("less is %s", where[i])
		}
		if r.Name == "make" && where[i] != underAgent {
			t.Errorf("make is %s", where[i])
		}
	}
}

func TestViewRefusesAVoidManifest(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	var b bytes.Buffer
	err := view(out, writeManifest(t, probesJSON(true)), &b)
	if err == nil || !strings.Contains(err.Error(), "the manifest is void") || b.Len() != 0 {
		t.Errorf("a void manifest: %v, %q", err, b.String())
	}
	if code := run(t.Context(), []string{"view", out, writeManifest(t, probesJSON(true))}); code != 2 {
		t.Errorf("exit %d", code)
	}
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

// TestViewReadsOnlyTheJudgesFiles: a run whose name is outside the alphabet, an unknown field, a file others can
// write or a link is refused, so view never prints what the judge did not write.
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
		"name outside": bytes.Replace(line, []byte(`"name":"`), []byte(`"name":"/`), 1),
		"argument":     bytes.Replace(line, []byte(`"name":`), []byte(`"argv":["x"],"name":`), 1),
		"schema":       bytes.Replace(line, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
	} {
		if bytes.Equal(bad, line) {
			t.Fatalf("%s: the edit does not apply to %s", name, line)
		}
		if err := os.WriteFile(execPath, append(append([]byte(nil), orig...), bad...), 0o644); err != nil { //nolint:gosec // as the judge writes it
			t.Fatal(err)
		}
		if err := view(out, "", &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := os.WriteFile(execPath, orig, 0o644); err != nil { //nolint:gosec // as the judge writes it
		t.Fatal(err)
	}
	if err := os.Chmod(execPath, 0o666); err != nil { //nolint:gosec // a file others can write, refused
		t.Fatal(err)
	}
	if err := view(out, "", &bytes.Buffer{}); err == nil {
		t.Error("a file others can write: accepted")
	}
	link := t.TempDir()
	for _, f := range []string{stateFile, execFile} {
		if err := os.Symlink(filepath.Join(out, f), filepath.Join(link, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := view(link, "", &bytes.Buffer{}); err == nil {
		t.Error("links: accepted")
	}
}

// TestViewOfAnUnknownState prints what it covers and no clean count when the judge could not read the store.
func TestViewOfAnUnknownState(t *testing.T) {
	_, out, err := judgeOnce(t, filepath.Join(t.TempDir(), "missing"), nil)
	if err == nil {
		t.Fatal("a missing store read")
	}
	v := viewOf(t, out, "")
	if v.Covers.Status != statusUnknown || v.Covers.Reason == "" || v.Clean.State != statusUnknown || v.Clean.Runs != 0 {
		t.Errorf("%+v", v)
	}
}

func FuzzDecodeManifest(f *testing.F) {
	f.Add([]byte(probesJSON(false)))
	f.Add([]byte(probesJSON(true)))
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
