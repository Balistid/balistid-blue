package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fourWindows is pair fix with a window for each run: the techniques run uname, the twins' records have it
// renamed, so the reference rule gives CAUGHT twice and QUIET twice.
func fourWindows(t *testing.T) *fixture {
	t.Helper()
	f := baseFixture(t)
	for i, run := range RunNames[1:] {
		raw := baseRecords(t)
		if !technique(run) {
			raw = bytes.ReplaceAll(raw, []byte(`"uname"`), []byte(`"unamf"`))
		}
		files := f.windowFor(t, run, raw)
		var id string
		for _, line := range strings.Split(string(files[ResultFile]), "\n") {
			if v, ok := strings.CutPrefix(line, `  "id": "`); ok {
				id = strings.TrimSuffix(v, `",`)
			}
		}
		stamp := "T12000" + string(rune('1'+i)) + "Z"
		files[ResultFile] = bytes.Replace(files[ResultFile], []byte("T120000Z"), []byte(stamp), 1)
		f.extra[strings.ToLower(strings.Replace(id, "T120000Z", stamp, 1))] = files
	}
	return f
}

func load(t *testing.T, dir string) *Lab {
	t.Helper()
	lab, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return lab
}

func TestAPairCountsOnlyWithAllFourRuns(t *testing.T) {
	f := fourWindows(t)
	out := load(t, f.write(t)).Table()
	if len(out.Pairs) != 1 || !out.Pairs[0].Counted {
		t.Fatalf("pairs: %+v (windows %+v)", out.Pairs, out.Windows)
	}
	if got := out.Rules[0].Verdicts; got["tech-a"] != Caught || got["tech-b"] != Caught || got["twin-a"] != Quiet || got["twin-b"] != Quiet {
		t.Fatalf("rule verdicts: %v", got)
	}
	for _, c := range out.Controls {
		if c.Windows != 4 || c.Wrong != 0 {
			t.Fatalf("control %+v, want 4 windows and none wrong", c)
		}
	}
	// One run left out: the pair is excluded, with the run named, and no rule verdict is given.
	g := fourWindows(t)
	for dir := range g.extra {
		if strings.Contains(dir, "-twin-b-") {
			delete(g.extra, dir)
		}
	}
	out = load(t, g.write(t)).Table()
	if out.Pairs[0].Counted || out.Pairs[0].Reason != "twin-b has no valid window" || out.Rules[0].Verdicts != nil {
		t.Fatalf("pair with three runs: %+v %+v", out.Pairs[0], out.Rules[0])
	}
	// A reference rule that misses excludes the pair.
	h := fourWindows(t)
	h.pair = pairJSON(`{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"nothing"}]}`, programsFor())
	h.window = h.windowFor(t, "tech-a", baseRecords(t))
	h.extra = map[string]map[string][]byte{}
	out = load(t, h.write(t)).Table()
	if out.Pairs[0].Counted {
		t.Fatal("a pair whose reference rule misses counts")
	}
}

func TestInvalidWindowsCountNowhere(t *testing.T) {
	f := fourWindows(t)
	f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], `"job_exit": 0`, `"job_exit": 1`)
	out := load(t, f.write(t)).Table()
	if out.Pairs[0].Counted || out.Controls[0].Windows != 3 {
		t.Fatalf("an INVALID window counted: %+v %+v", out.Pairs[0], out.Controls)
	}
}

func TestTableIsReproducible(t *testing.T) {
	f := fourWindows(t)
	a := load(t, f.write(t)).Table().Encode()
	b := load(t, f.write(t)).Table().Encode()
	if !bytes.Equal(a, b) || bytes.Contains(a, []byte(os.TempDir())) {
		t.Fatal("table differs between two runs over the same lab, or names a path")
	}
}

// results writes a runner results directory: the anchor, then the given results, each a window's files.
func results(t *testing.T, windows map[string]map[string][]byte, withAnchor bool) string {
	t.Helper()
	dir := t.TempDir()
	if withAnchor {
		if err := os.MkdirAll(filepath.Join(dir, Anchor), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, Anchor, ResultFile), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for id, files := range windows {
		if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		for n, d := range files {
			if err := os.WriteFile(filepath.Join(dir, id, n), d, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func idOf(t *testing.T, f *fixture) string {
	t.Helper()
	r, err := decodeResult(f.window[ResultFile])
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestVerify(t *testing.T) {
	f := baseFixture(t)
	id := idOf(t, f)
	orig := map[string][]byte{ResultFile: f.window[ResultFile], LaurelFile: f.window[LaurelFile], "serial.txt": []byte("x")}
	f.window["serial.txt"] = []byte("x")
	lab := f.write(t)
	good := results(t, map[string]map[string][]byte{id: orig}, true)
	if findings, err := Verify(lab, good); err != nil || len(findings) != 0 {
		t.Fatalf("verify of a true copy: %v %v", findings, err)
	}
	for _, c := range []struct {
		name    string
		results string
		want    string
	}{
		{"anchor gone", results(t, map[string]map[string][]byte{id: orig}, false), "no longer kept"},
		{"a result hidden", results(t, map[string]map[string][]byte{id: orig, "20261118T130000Z-00000000-x": {ResultFile: []byte("{}")}}, true), "windows/20261118t130000z-00000000-x"},
		{"a file changed", results(t, map[string]map[string][]byte{id: {ResultFile: orig[ResultFile], LaurelFile: orig[LaurelFile], "serial.txt": []byte("y")}}, true), "serial.txt is not the runner's"},
		{"a file the runner never wrote", results(t, map[string]map[string][]byte{id: {ResultFile: orig[ResultFile], LaurelFile: orig[LaurelFile]}}, true), "is not in the runner's result"},
		{"a window with no result", results(t, nil, true), "matches no runner result"},
	} {
		t.Run(c.name, func(t *testing.T) {
			findings, err := Verify(lab, c.results)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(findings, func(s string) bool { return strings.Contains(s, c.want) }) {
				t.Fatalf("findings %v, want one with %q", findings, c.want)
			}
		})
	}
}

func TestImportCopiesEveryFileOnce(t *testing.T) {
	f := baseFixture(t)
	id := idOf(t, f)
	res := results(t, map[string]map[string][]byte{id: f.window}, true)
	lab := t.TempDir()
	if _, err := Import(lab, res, id); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(lab, res, id); err == nil {
		t.Fatal("a second import over the window succeeded")
	}
	if findings, err := Verify(lab, res); err != nil || len(findings) != 0 {
		t.Fatalf("verify after import: %v %v", findings, err)
	}
	if _, err := Import(lab, res, Anchor); err == nil {
		t.Fatal("the anchor itself was imported")
	}
}

func TestJobWritesTheRunTheRunnerKeys(t *testing.T) {
	f := baseFixture(t)
	lab := f.write(t)
	target := t.TempDir()
	out, err := Job(lab, fixturePair, "tech-a", target)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Fields(out)[0]
	r, _ := decodeResult(f.window[ResultFile])
	if name != r.Name || strings.Fields(out)[1] != r.ContentKey {
		t.Fatalf("job %s, want the window's name %s and key", out, r.Name)
	}
	req, err := os.ReadFile(filepath.Join(target, name, "job.json"))
	if err != nil || string(req) != `{"schema_version":1,"kind":"exec","program":"prog.sh","timeout_s":60}` {
		t.Fatalf("job.json %q %v", req, err)
	}
	if prog, err := os.ReadFile(filepath.Join(target, name, "prog.sh")); err != nil || string(prog) != baseProgram {
		t.Fatalf("program %q %v", prog, err)
	}
	// A pair in CRLF never becomes a job.
	f.pair = strings.ReplaceAll(f.pair, "\n", "\r\n")
	if _, err := Job(f.write(t), fixturePair, "tech-a", t.TempDir()); err == nil {
		t.Fatal("a CRLF pair became a job")
	}
}
