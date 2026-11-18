package detect

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The base window of ADR 0078 point 3: hard-exec-1's records (decoded in testdata), request and program.
const (
	baseProgram     = "#!/bin/sh\nuname -r; id -u; echo hardened-ok\n"
	baseLaurelSHA   = "499fdf58a43fcabac45125d1823e306e4a582b63bb0eccc3d6b66ebe63087801"
	baseResultSHA   = "595cfffa9175728a60fc9c16892b2619dab226534dcdf5f430a8ea9bc539131c"
	baseResultID    = "20261117T164346Z-4e1197c7-hard-exec-1"
	fixtureStamp    = "20261118T120000Z-0123abcd-" // after the anchor (ADR 0079 point 7)
	fixturePair     = "fix"
	fixtureBrief    = "a test pair"
	fixtureRuleFile = "rules/fix/opus-1.json"
)

// resultTemplate is hard-exec-1's result.json byte for byte, its job's identity left as holes.
const resultTemplate = `{
  "schema_version": 1,
  "id": "{ID}",
  "label": "agent",
  "runner_commit": "2c09799a44e766ea3b3f0597bd8c9ab32db9d31e",
  "image_commit": "2c09799a44e766ea3b3f0597bd8c9ab32db9d31e",
  "image_sha256": "693e28f3e561f5959dd1bcda486fe8ed1bbc11a6c3b120263b9634e262e933a7",
  "job": {
    "name": "{NAME}",
    "kind": "exec",
    "program": "{PROGRAM}",
    "timeout_s": {TIMEOUT},
    "content_key": "{KEY}",
    "program_sha256": "{PSHA}",
    "job_disk_sha256": "99fdacc8e11e13ec8d1d6c94125205a99769a0cab0c01656170cc54c27f315d8"
  },
  "limits": {
    "run_timeout_s": 600,
    "serial_budget": 1048576,
    "job_out_cap": 2097152,
    "job_laurel_cap": 6291456,
    "mem_reserve": 4294967296,
    "job_memory": 2684354560,
    "disk_reserve": 5368709120
  },
  "verdict": "RAN",
  "reason": "the job ran; its output and Laurel records are the agent's to judge",
  "runs": [
    {
      "verdict": "RAN",
      "reason": "the job ran; its output and Laurel records are the agent's to judge",
      "guest_kernel": "7.2.8-arch1-2",
      "job_result": "success",
      "job_exit": 0,
      "out_bytes": 30,
      "laurel_bytes": {BYTES}
    }
  ]
}`

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// hardExec1 is embedded, not read by path: a test binary run outside the package directory (go-mutesting's
// per-test coverage map runs it from the repository root) would fail a relative read and cover nothing.
//
//go:embed testdata/hard-exec-1.jsonl
var hardExec1 []byte

func baseRecords(testing.TB) []byte { return bytes.Clone(hardExec1) }

func resultFor(id, name, program string, timeout int64, text []byte, laurelBytes int) []byte {
	return []byte(strings.NewReplacer(
		"{ID}", id, "{NAME}", name, "{PROGRAM}", program, "{TIMEOUT}", strconv.FormatInt(timeout, 10),
		"{KEY}", contentKey(execRequest(program, timeout), text), "{PSHA}", sha(text),
		"{BYTES}", strconv.Itoa(laurelBytes),
	).Replace(resultTemplate))
}

// TestTheBaseIsHardExec1 pins the runner's contract to its real bytes (ADR 0078 point 3, ADR 0079 point 1):
// the decoded records escape back to the runner's file, and the template with the real job gives its result.
func TestTheBaseIsHardExec1(t *testing.T) {
	raw := baseRecords(t)
	if got := sha(escape(raw)); got != baseLaurelSHA {
		t.Fatalf("escaped testdata sha256 %s, want hard-exec-1's %s", got, baseLaurelSHA)
	}
	if back, ok := unescape(escape(raw)); !ok || string(back) != string(raw) {
		t.Fatal("unescape does not invert escape on the base")
	}
	got := resultFor(baseResultID, "hard-exec-1", "prog.sh", 60, []byte(baseProgram), len(raw))
	if sha(got) != baseResultSHA {
		t.Fatalf("rebuilt result sha256 %s, want hard-exec-1's %s", sha(got), baseResultSHA)
	}
	r, err := decodeResult(got)
	if err != nil || !r.HasExec || r.ID != baseResultID {
		t.Fatalf("the real result does not decode: %v %+v", err, r)
	}
}

func TestEscapeRoundTrip(t *testing.T) {
	for _, c := range []struct {
		file string
		ok   bool
	}{
		{`a\x0ab`, true},
		{`\x5c\x22`, true},
		{``, true},
		{`\x0A`, false},
		{`\x41`, false},
		{"a\n", false},
		{`"`, false},
		{`\`, false},
		{`\x`, false},
		{`\x0`, false},
		{`\xzz`, false},
		{"\x7f", false},
		{"é", false},
	} {
		if _, ok := unescape([]byte(c.file)); ok != c.ok {
			t.Errorf("unescape(%q) ok %v, want %v", c.file, ok, c.ok)
		}
	}
	if got := string(escape([]byte("\x1f \x80\xff"))); got != `\x1f \x80\xff` {
		t.Fatalf("escape bounds: %s", got)
	}
	if raw, ok := unescape([]byte(`\xff\x80`)); !ok || string(raw) != "\xff\x80" {
		t.Fatalf("unescape high bytes: %q %v", raw, ok)
	}
	if got := string(escape([]byte("a\"\\\n\x7f\x00 ~"))); got != `a\x22\x5c\x0a\x7f\x00 ~` {
		t.Fatalf("escape: %s", got)
	}
	if raw, _ := unescape([]byte(`a\x0ab`)); string(raw) != "a\nb" {
		t.Fatalf("unescape decoded %q", raw)
	}
}

func FuzzUnescape(f *testing.F) {
	f.Add([]byte(`a\x0ab`))
	f.Add([]byte(`\x0A`))
	f.Add(escape(baseRecords(f)))
	f.Fuzz(func(t *testing.T, file []byte) {
		raw, ok := unescape(file)
		if ok && !bytes.Equal(escape(raw), file) {
			t.Fatal("unescape accepted a file that does not escape back to itself")
		}
		if back, ok := unescape(escape(file)); !ok || !bytes.Equal(back, file) {
			t.Fatal("escape does not round-trip")
		}
	})
}

// TestResultsOfAnotherShape: each refusal is errNotResult or the decoder's own error and names its cause, so a
// check that silently passes on to a later one is seen.
func TestResultsOfAnotherShape(t *testing.T) {
	good := resultFor(fixtureStamp+"x", "x", "prog.sh", 60, []byte(baseProgram), 1)
	if _, err := decodeResult(good); err != nil {
		t.Fatalf("base: %v", err)
	}
	for _, c := range []struct{ name, old, repl string }{
		{"a limit missing", `"run_timeout_s": 600,`, ``},
		{"a limit added", `"run_timeout_s": 600,`, `"run_timeout_s": 600, "x": 1,`},
		{"trials as a string", `"timeout_s": 60,`, `"timeout_s": 60, "trials": "1",`},
		{"disk sha not hex", `"job_disk_sha256": "99fd`, `"job_disk_sha256": "99FD`},
		{"content key short", `"content_key": "`, `"content_key": "0`},
		{"runner commit short", `"runner_commit": "2c09799a44e766ea3b3f0597bd8c9ab32db9d31e"`, `"runner_commit": "2c09799"`},
		{"out_truncated a string", `"out_bytes": 30,`, `"out_bytes": 30, "out_truncated": "no",`},
		{"measures not counts", `"out_bytes": 30,`, `"out_bytes": 30, "measures": {"a": -1},`},
		{"measures a list", `"out_bytes": 30,`, `"out_bytes": 30, "measures": [1],`},
		{"job_exit a float", `"job_exit": 0`, `"job_exit": 0.0`},
		{"job_exit -0", `"job_exit": 0`, `"job_exit": -0`},
		{"id without the job's name", `"id": "` + fixtureStamp + `x"`, `"id": "` + fixtureStamp + `y"`},
		{"a job name of another grammar", `"name": "x"`, `"name": "X"`},
		{"runs not a list", `"runs": [`, `"runs": {"a": [`},
		{"a run's reason a number", `"reason": "the job ran; its output and Laurel records are the agent's to judge",
      "guest_kernel"`, `"reason": 1,
      "guest_kernel"`},
		{"schema a string", `"schema_version": 1`, `"schema_version": "1"`},
		{"job a list", `"job": {`, `"job": [{`},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := bytes.Replace(good, []byte(c.old), []byte(c.repl), 1)
			if bytes.Equal(bad, good) {
				t.Fatalf("%q not found", c.old)
			}
			if _, err := decodeResult(bad); err == nil {
				t.Fatal("decoded")
			}
		})
	}
}

// TestEachRefusalNamesItsCause: a check that let its case through to a later check would fail with another cause.
func TestEachRefusalNamesItsCause(t *testing.T) {
	good := resultFor(fixtureStamp+"x", "x", "prog.sh", 60, []byte(baseProgram), 1)
	for _, c := range []struct {
		name, old, repl, why string
		notResult            bool
	}{
		{"a top key added", `"label": "agent",`, `"label": "agent", "x": 1,`, `key "x" not allowed`, true},
		{"a top key missing", `"label": "agent",`, ``, `key "label" missing`, true},
		{"a top key of another type", `"verdict": "RAN",
  "reason"`, `"verdict": 1,
  "reason"`, `key "verdict" has another type`, true},
		{"a top key repeated, same value", `"label": "agent",`, `"label": "agent", "label": "agent",`, "repeated key", false},
		{"not JSON", `"label": "agent",`, `"label": "agent"`, "not one valid JSON value", false},
		{"a limit added", `"run_timeout_s": 600,`, `"run_timeout_s": 600, "x": 1,`, `key "x" not allowed`, true},
		{"a job key added", `"kind": "exec",`, `"kind": "exec", "x": 1,`, `key "x" not allowed`, true},
		{"a job name of another grammar", `"name": "x"`, `"name": "X"`, "job name", true},
		{"the id not ending in the job's name", `"id": "` + fixtureStamp + `x"`, `"id": "` + fixtureStamp + `y"`, "id does not end", true},
		{"a run key added", `"out_bytes": 30,`, `"out_bytes": 30, "x": 1,`, `key "x" not allowed`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := bytes.Replace(good, []byte(c.old), []byte(c.repl), 1)
			if bytes.Equal(bad, good) {
				t.Fatalf("%q not found", c.old)
			}
			_, err := decodeResult(bad)
			if err == nil || !strings.Contains(err.Error(), c.why) || errors.Is(err, errNotResult) != c.notResult {
				t.Fatalf("err %v, want %q (not a result: %v)", err, c.why, c.notResult)
			}
		})
	}
	// A name the grammar refuses with an id that does end in it: only the name check refuses it.
	odd := resultFor(fixtureStamp+"X", "X", "prog.sh", 60, []byte(baseProgram), 1)
	if _, err := decodeResult(odd); err == nil || !strings.Contains(err.Error(), "job name") {
		t.Fatalf("a job name of another grammar: %v", err)
	}
}

// TestEveryOptionalKeyDecodes: the runner writes each optional key on some result; each must decode.
func TestEveryOptionalKeyDecodes(t *testing.T) {
	good := resultFor(fixtureStamp+"x", "x", "prog.sh", 60, []byte(baseProgram), 1)
	for _, c := range []struct{ name, old, repl string }{
		{"trials and trial", `"kind": "exec",`, `"kind": "exec", "trials": 2, "trial": "a",`},
		{"a run's label, truncation and measures", `"out_bytes": 30,`,
			`"out_bytes": 30, "label": "a", "out_truncated": true, "measures": {"a": 0, "b": 1},`},
		{"out_truncated false", `"out_bytes": 30,`, `"out_bytes": 30, "out_truncated": false,`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeResult(bytes.Replace(good, []byte(c.old), []byte(c.repl), 1)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestAnExecJobNeedsItsThreeKeys: a job is exec only with its program, timeout and program hash all present.
func TestAnExecJobNeedsItsThreeKeys(t *testing.T) {
	good := resultFor(fixtureStamp+"x", "x", "prog.sh", 60, []byte(baseProgram), 1)
	for _, key := range []string{`"program": "prog.sh",`, `"timeout_s": 60,`, `"program_sha256": "` + sha([]byte(baseProgram)) + `",`} {
		bad := bytes.Replace(good, []byte(key), nil, 1)
		if bytes.Equal(bad, good) {
			t.Fatalf("%q not found", key)
		}
		r, err := decodeResult(bad)
		if err != nil || r.HasExec || r.Name != "x" {
			t.Fatalf("without %s: %v exec %v job %q", key, err, r.HasExec, r.Name)
		}
	}
}

// TestTheCaps pins ADR 0077 point 3 and ADR 0079 point 8.
func TestTheCaps(t *testing.T) {
	if LaurelCap != 6291456 || LabCap != 16777216 {
		t.Fatalf("LaurelCap %d LabCap %d", LaurelCap, LabCap)
	}
}

func FuzzDecodeResult(f *testing.F) {
	f.Add(resultFor(fixtureStamp+"x", "x", "prog.sh", 60, []byte(baseProgram), 1))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := decodeResult(data)
		if err == nil && r.Name != "" && !strings.HasSuffix(r.ID, "-"+r.Name) {
			t.Fatal("a result whose id does not end in its job's name decoded")
		}
	})
}

// fixture is a lab/ tree of one pair, one rule and one window, written to a temporary directory.
type fixture struct {
	pair   string            // pairs/fix.json
	rules  map[string]string // path under lab/ -> bytes
	window map[string][]byte // the window's files
	dir    string            // the window's directory name
	extra  map[string]map[string][]byte
}

func ruleJSON(rule, brief string) string {
	return `{"rule":` + rule + `,"model":"test","sample":1,"params":{},"brief_sha256":"` + sha([]byte(brief)) + `"}` + "\n"
}

const reference = `{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"}]}`

var fixtureRule = ruleJSON(reference, fixtureBrief)

func pairJSON(reference string, programs map[string]string) string {
	var runs []string
	for _, rn := range RunNames {
		prog := rn + ".sh"
		if rn == "tech-a" {
			prog = "prog.sh"
		}
		runs = append(runs, `"`+rn+`":{"program":"`+prog+`","timeout_s":60,"text":`+strconv.Quote(programs[rn])+`}`)
	}
	return `{"attack":"T0000","author":"test","brief":"` + fixtureBrief + `","reference":` + reference + `,"runs":{` +
		strings.Join(runs, ",") + "}}\n"
}

func programsFor() map[string]string {
	return map[string]string{
		"tech-a": baseProgram,
		"tech-b": "#!/bin/sh\nuname -a\n",
		"twin-a": "#!/bin/sh\nid -u\n",
		"twin-b": "#!/bin/sh\nid -g\n",
	}
}

// baseFixture is the base window as tech-a of pair fix: valid as it stands.
func baseFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		pair:  pairJSON(reference, programsFor()),
		rules: map[string]string{fixtureRuleFile: fixtureRule},
		extra: map[string]map[string][]byte{},
	}
	f.window = f.windowFor(t, "tech-a", baseRecords(t))
	return f
}

// windowFor builds the files of run's window from records, its job named from the fixture's current content.
func (f *fixture) windowFor(t *testing.T, run string, raw []byte) map[string][]byte {
	t.Helper()
	p, err := decodePair(fixturePair, []byte(f.pair))
	if err != nil {
		t.Fatal(err)
	}
	content := map[string][]byte{"pairs/" + fixturePair + ".json": []byte(f.pair)}
	for k, v := range f.rules {
		content[k] = []byte(v)
	}
	name := jobName(fixturePair, run, contentHash(content))
	id := fixtureStamp + name
	r := p.Runs[run]
	if run == "tech-a" {
		f.dir = strings.ToLower(id)
	}
	return map[string][]byte{
		ResultFile: resultFor(id, name, r.Program, r.TimeoutS, r.Text, len(raw)),
		LaurelFile: escape(raw),
	}
}

func put(t *testing.T, lab, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(lab, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) write(t *testing.T) string {
	t.Helper()
	lab := t.TempDir()
	put(t, lab, "pairs/"+fixturePair+".json", []byte(f.pair))
	for k, v := range f.rules {
		put(t, lab, k, []byte(v))
	}
	for name, data := range f.window {
		put(t, lab, "windows/"+f.dir+"/"+name, data)
	}
	for dir, files := range f.extra {
		for name, data := range files {
			put(t, lab, "windows/"+dir+"/"+name, data)
		}
	}
	return lab
}

// judge loads the fixture and returns its base window.
func (f *fixture) judge(t *testing.T) Window {
	t.Helper()
	lab, err := Load(f.write(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range lab.Windows {
		if w.Dir == f.dir {
			return w
		}
	}
	t.Fatalf("window %s not found", f.dir)
	return Window{}
}
