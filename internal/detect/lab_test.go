package detect

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T, dir string) *Lab {
	t.Helper()
	lab, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return lab
}

// results writes a runner results directory: the anchor (unless left out), then the given results.
func results(t *testing.T, windows map[string]map[string][]byte, withAnchor bool) string {
	t.Helper()
	dir := t.TempDir()
	if withAnchor {
		put(t, dir, Anchor+"/"+ResultFile, []byte("{}"))
	}
	for id, files := range windows {
		if err := os.MkdirAll(filepath.Join(dir, id), 0o750); err != nil {
			t.Fatal(err)
		}
		for n, d := range files {
			put(t, dir, id+"/"+n, d)
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

func findingWith(findings []string, want string) bool {
	return slices.ContainsFunc(findings, func(s string) bool { return strings.Contains(s, want) })
}

func TestVerify(t *testing.T) {
	f := baseFixture(t)
	id := idOf(t, f)
	f.window["serial.txt"] = []byte("x")
	orig := map[string][]byte{ResultFile: f.window[ResultFile], LaurelFile: f.window[LaurelFile], "serial.txt": []byte("x")}
	lab := f.write(t)
	good := results(t, map[string]map[string][]byte{id: orig, "20261116T000000Z-00000000-old": {ResultFile: []byte("{}")}}, true)
	findings, digest, err := Verify(lab, good)
	if err != nil || len(findings) != 0 || len(digest) != 64 {
		t.Fatalf("verify of a true copy: %v %q %v", findings, digest, err)
	}
	// The digest covers the bytes compared: another byte, another digest.
	other := results(t, map[string]map[string][]byte{id: {ResultFile: orig[ResultFile], LaurelFile: orig[LaurelFile], "serial.txt": []byte("y")}}, true)
	if _, d2, _ := Verify(lab, other); d2 == digest {
		t.Fatal("the digest does not change with the runner's bytes")
	}
	emptyResult := results(t, map[string]map[string][]byte{"20261118T130000Z-00000000-x": {}}, true)
	for _, c := range []struct {
		name    string
		lab     string
		results string
		want    string
	}{
		{"anchor gone", lab, results(t, map[string]map[string][]byte{id: orig}, false), "no longer kept"},
		{"a result hidden", lab, results(t, map[string]map[string][]byte{id: orig, "20261118T130000Z-00000000-x": {ResultFile: []byte("{}")}}, true), "windows/20261118t130000z-00000000-x is missing"},
		{"an empty result with no window", lab, emptyResult, "windows/20261118t130000z-00000000-x is missing"},
		{"no windows at all", t.TempDir(), results(t, map[string]map[string][]byte{id: orig}, true), "is missing"},
		{"a file changed", lab, other, "serial.txt is not the runner's"},
		{"a file the runner never wrote", lab, results(t, map[string]map[string][]byte{id: {ResultFile: orig[ResultFile], LaurelFile: orig[LaurelFile]}}, true), "is not in the runner's result"},
		{"a window with no result", lab, results(t, nil, true), "matches no runner result"},
		{"a name the runner never writes", lab, results(t, map[string]map[string][]byte{id: orig, "junk": {}}, true), "junk is not a result's name"},
	} {
		t.Run(c.name, func(t *testing.T) {
			findings, _, err := Verify(c.lab, c.results)
			if err != nil {
				t.Fatal(err)
			}
			if !findingWith(findings, c.want) {
				t.Fatalf("findings %v, want one with %q", findings, c.want)
			}
		})
	}
	// A link in place of windows/ fails the read rather than being followed.
	g := baseFixture(t)
	glab := g.write(t)
	if err := os.Rename(filepath.Join(glab, "windows"), filepath.Join(glab, "w2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("w2", filepath.Join(glab, "windows")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(glab, results(t, map[string]map[string][]byte{idOf(t, g): g.window}, true)); err == nil {
		t.Fatal("verify followed a link at windows/")
	}
}

func TestImport(t *testing.T) {
	f := baseFixture(t)
	id := idOf(t, f)
	res := results(t, map[string]map[string][]byte{id: f.window, "20261118T130000Z-00000000-big": {ResultFile: make([]byte, LabCap)}}, true)
	lab := t.TempDir()
	n, err := Import(lab, res, id)
	if err != nil || n != int64(len(f.window[ResultFile])+len(f.window[LaurelFile])) {
		t.Fatalf("import: %d %v", n, err)
	}
	if _, err := Import(lab, res, id); err == nil {
		t.Fatal("a second import over the window succeeded")
	}
	if findings, _, err := Verify(lab, results(t, map[string]map[string][]byte{id: f.window}, true)); err != nil || len(findings) != 0 {
		t.Fatalf("verify after import: %v %v", findings, err)
	}
	for _, c := range []struct{ name, id string }{
		{"the anchor itself", Anchor},
		{"a name that is not a result's", "nope"},
		{"a result the runner does not hold", "20261118T140000Z-00000000-none"},
		{"a result that would pass the cap", "20261118T130000Z-00000000-big"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Import(lab, res, c.id); err == nil {
				t.Fatal("imported")
			}
		})
	}
	// windows/ as a link to a sibling: import must not write through it.
	l2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(l2, "pairs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("pairs", filepath.Join(l2, "windows")); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(l2, res, id); err == nil {
		t.Fatal("import wrote through a link at windows/")
	}
	if entries, _ := os.ReadDir(filepath.Join(l2, "pairs")); len(entries) != 0 {
		t.Fatalf("import wrote %v into pairs/", entries)
	}
}

func TestJob(t *testing.T) {
	f := baseFixture(t)
	f.extra["junk"] = map[string][]byte{"x": []byte("an unrelated window never stops a job")}
	lab := f.write(t)
	target := t.TempDir()
	out, err := Job(lab, fixturePair, "tech-a", target)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Fields(out)[0]
	r, _ := decodeResult(f.window[ResultFile])
	if name != r.Name || strings.Fields(out)[1] != r.ContentKey || strings.Fields(out)[2] != sha([]byte(baseProgram)) {
		t.Fatalf("job %s, want the window's name %s, key and program sha", out, r.Name)
	}
	req, err := os.ReadFile(filepath.Join(target, name, "job.json")) //nolint:gosec // the test's own temp dir
	if err != nil || string(req) != `{"schema_version":1,"kind":"exec","program":"prog.sh","timeout_s":60}` {
		t.Fatalf("job.json %q %v", req, err)
	}
	prog, err := os.ReadFile(filepath.Join(target, name, "prog.sh")) //nolint:gosec // the test's own temp dir
	if err != nil || string(prog) != baseProgram {
		t.Fatalf("program %q %v", prog, err)
	}
	if entries, _ := os.ReadDir(target); len(entries) != 1 {
		t.Fatalf("job left %v in its target", entries)
	}
	if _, err := Job(lab, fixturePair, "tech-a", target); err == nil {
		t.Fatal("a second job over the first succeeded")
	}
	for _, c := range []struct{ name, pair, run string }{
		{"no such pair", "nope", "tech-a"},
		{"no such run", fixturePair, "tech-c"},
	} {
		if _, err := Job(lab, c.pair, c.run, t.TempDir()); err == nil {
			t.Errorf("%s: a job was written", c.name)
		}
	}
	inbox := t.TempDir()
	if _, err := jobIn(lab, fixturePair, "tech-b", inbox, inbox); err == nil {
		t.Fatal("job wrote into the runner's inbox")
	}
	if err := os.Mkdir(filepath.Join(inbox, "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := jobIn(lab, fixturePair, "tech-b", filepath.Join(inbox, "x"), inbox); err == nil {
		t.Fatal("job wrote into a directory inside the runner's inbox")
	}
	if _, err := jobIn(lab, fixturePair, "tech-b", t.TempDir(), inbox); err != nil {
		t.Fatalf("a target outside the inbox: %v", err)
	}
	g := baseFixture(t)
	g.pair = strings.ReplaceAll(g.pair, "\n", "\r\n")
	if _, err := Job(g.write(t), fixturePair, "tech-a", t.TempDir()); err == nil {
		t.Fatal("a CRLF pair became a job")
	}
	h := baseFixture(t)
	h.rules[fixtureRuleFile] = strings.Replace(fixtureRule, `"op":"eq"`, `"op":"regex"`, 1)
	if _, err := Job(h.write(t), fixturePair, "tech-a", t.TempDir()); err == nil {
		t.Fatal("a pair with a broken rule became a job")
	}
}

func TestLoadRefusesWhatIsNotLab(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, lab string)
	}{
		{"rules without a pair", func(t *testing.T, lab string) { put(t, lab, "rules/orphan/x.json", []byte("{}")) }},
		{"a pair file not .json", func(t *testing.T, lab string) { put(t, lab, "pairs/x.txt", []byte("{}")) }},
		{"a file in windows/", func(t *testing.T, lab string) { put(t, lab, "windows/x", []byte("{}")) }},
		{"a window file of another name", func(t *testing.T, lab string) { put(t, lab, "windows/d/Weird", []byte("{}")) }},
		{"a window file a link", func(t *testing.T, lab string) {
			put(t, lab, "pairs/x.json", []byte("{}"))
			if err := os.MkdirAll(filepath.Join(lab, "windows", "d"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../../pairs/x.json", filepath.Join(lab, "windows", "d", LaurelFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"pairs/ a link", func(t *testing.T, lab string) {
			if err := os.Symlink("/", filepath.Join(lab, "pairs")); err != nil {
				t.Fatal(err)
			}
		}},
		{"lab/ over its cap", func(t *testing.T, lab string) {
			put(t, lab, "windows/a/serial.txt", make([]byte, LabCap/2+1))
			put(t, lab, "windows/b/serial.txt", make([]byte, LabCap/2+1))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			lab := t.TempDir()
			c.setup(t, lab)
			if _, err := Load(lab); err == nil {
				t.Fatal("loaded")
			}
		})
	}
	if lab, err := Load(t.TempDir()); err != nil || len(lab.Windows) != 0 {
		t.Fatalf("an empty lab: %v", err)
	}
}

func TestRunnerOwned(t *testing.T) {
	if err := RunnerOwned(t.TempDir()); err == nil {
		t.Fatal("the caller's own directory passed as the runner's")
	}
	if err := RunnerOwned("/tmp"); err == nil && os.Getuid() != 0 {
		t.Fatal("a world-writable directory passed")
	}
	if err := RunnerOwned("/usr"); err != nil && os.Getuid() != 0 {
		t.Fatalf("root's /usr: %v", err)
	}
	link := filepath.Join(t.TempDir(), "l")
	if err := os.Symlink("/usr", link); err != nil {
		t.Fatal(err)
	}
	if err := RunnerOwned(link); err == nil {
		t.Fatal("a link passed")
	}
	if err := RunnerOwned(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("a missing directory passed")
	}
}

// TestTheDigestCoversTheComparedSet: an empty window and no window give different digests.
func TestTheDigestCoversTheComparedSet(t *testing.T) {
	id := "20261118T130000Z-00000000-x"
	none := results(t, nil, true)
	empty := results(t, map[string]map[string][]byte{id: {}}, true)
	lab := t.TempDir()
	if err := os.MkdirAll(filepath.Join(lab, "windows", strings.ToLower(id)), 0o750); err != nil {
		t.Fatal(err)
	}
	f1, d1, err1 := Verify(t.TempDir(), none)
	f2, d2, err2 := Verify(lab, empty)
	if err1 != nil || err2 != nil || len(f1) != 0 || len(f2) != 0 || d1 == d2 {
		t.Fatalf("no window %v %s, an empty one %v %s", f1, d1, f2, d2)
	}
}
