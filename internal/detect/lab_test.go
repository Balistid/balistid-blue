package detect

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
		name, why string
		setup     func(t *testing.T, lab string)
	}{
		{"rules without a pair", "rules/orphan has no pair", func(t *testing.T, lab string) { put(t, lab, "rules/orphan/x.json", []byte("{}")) }},
		{"a pair file not .json", "pairs/x.txt is not a pair's file", func(t *testing.T, lab string) { put(t, lab, "pairs/x.txt", []byte("{}")) }},
		{"a file in windows/", "lab: windows: x is not a directory", func(t *testing.T, lab string) { put(t, lab, "windows/x", []byte("{}")) }},
		{"a window file of another name", "windows/d/Weird is not a runner's file name", func(t *testing.T, lab string) { put(t, lab, "windows/d/Weird", []byte("{}")) }},
		{"a directory in a window", "lab: windows/d: sub is not a regular file", func(t *testing.T, lab string) { put(t, lab, "windows/d/sub/x", nil) }},
		{"a directory in pairs/", "lab: pairs: d is not a regular file", func(t *testing.T, lab string) { put(t, lab, "pairs/d/x", nil) }},
		{"a file in rules/", "lab: rules: f is not a directory", func(t *testing.T, lab string) { put(t, lab, "rules/f", nil) }},
		{"a directory in a pair's rules", "lab: rules/x: d is not a regular file", func(t *testing.T, lab string) {
			put(t, lab, "pairs/x.json", []byte("{}"))
			put(t, lab, "rules/x/d/y", nil)
		}},
		{"pairs/ a file", "lab: pairs is not a directory", func(t *testing.T, lab string) { put(t, lab, "pairs", nil) }},
		{"rules/ a file", "lab: rules is not a directory", func(t *testing.T, lab string) { put(t, lab, "rules", nil) }},
		{"windows/ a file", "lab: windows is not a directory", func(t *testing.T, lab string) { put(t, lab, "windows", nil) }},
		{"pairs over lab/'s cap", "lab: over", func(t *testing.T, lab string) {
			for _, p := range []string{"a", "b", "c", "d"} {
				put(t, lab, "pairs/"+p+".json", make([]byte, pairCap-1))
			}
		}},
		{"rules over lab/'s cap", "lab: over", func(t *testing.T, lab string) {
			for _, p := range []string{"a", "b", "c"} {
				put(t, lab, "pairs/"+p+".json", make([]byte, pairCap))
			}
			for i := range 17 {
				put(t, lab, "rules/c/r"+strconv.Itoa(i)+".json", make([]byte, ruleCap))
			}
		}},
		{"a window file a link", "lab: windows/d: ", func(t *testing.T, lab string) {
			put(t, lab, "pairs/x.json", []byte("{}"))
			if err := os.MkdirAll(filepath.Join(lab, "windows", "d"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../../pairs/x.json", filepath.Join(lab, "windows", "d", LaurelFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"pairs/ a link", "lab: pairs is not a directory", func(t *testing.T, lab string) {
			if err := os.Symlink("/", filepath.Join(lab, "pairs")); err != nil {
				t.Fatal(err)
			}
		}},
		{"lab/ over its cap", "lab: over", func(t *testing.T, lab string) {
			put(t, lab, "windows/a/serial.txt", make([]byte, LabCap/2+1))
			put(t, lab, "windows/b/serial.txt", make([]byte, LabCap/2+1))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			lab := t.TempDir()
			c.setup(t, lab)
			if _, err := Load(lab); err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("err %v, want %q", err, c.why)
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "none")); err == nil || errors.Unwrap(err) == nil {
		t.Fatalf("a missing lab: %v", err)
	}
	for _, dir := range []string{"windows/d", "rules/x"} {
		lab := t.TempDir()
		put(t, lab, "pairs/x.json", []byte("{}"))
		put(t, lab, dir+"/f", nil)
		locked(t, filepath.Join(lab, dir), 0o300)
		if _, err := Load(lab); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("an unreadable %s: %v", dir, err)
		}
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

// TestEachFileAtItsCap: a result, a pair and a rule of exactly their cap are read; one byte more is not.
func TestEachFileAtItsCap(t *testing.T) {
	pad := func(data []byte, size int) []byte { // trailing spaces, then the LF a pair or rule must end in: the same JSON
		body := bytes.TrimSuffix(data, []byte("\n"))
		end := []byte{}
		if len(body) < len(data) {
			end = []byte("\n")
		}
		return append(append(append([]byte{}, body...), bytes.Repeat([]byte(" "), size-len(data))...), end...)
	}
	for _, c := range []struct {
		name string
		cap  int
		want Reason
		set  func(t *testing.T, f *fixture, size int)
	}{
		{"result", resultCap, ReasonResultDecode, func(_ *testing.T, f *fixture, size int) { f.window[ResultFile] = pad(f.window[ResultFile], size) }},
		{"pair", pairCap, ReasonPair, func(t *testing.T, f *fixture, size int) {
			f.pair = string(pad([]byte(f.pair), size))
			f.window = f.windowFor(t, "tech-a", baseRecords(t)) // the job name binds the content
		}},
		{"rule", ruleCap, ReasonRule, func(t *testing.T, f *fixture, size int) {
			f.rules[fixtureRuleFile] = string(pad([]byte(f.rules[fixtureRuleFile]), size))
			f.window = f.windowFor(t, "tech-a", baseRecords(t))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := baseFixture(t)
			c.set(t, f, c.cap)
			if w := f.judge(t); !w.Valid() {
				t.Fatalf("at the cap: %+v", w)
			}
			g := baseFixture(t)
			c.set(t, g, c.cap+1)
			if w := g.judge(t); w.Reason != c.want {
				t.Fatalf("over the cap: %+v", w)
			}
		})
	}
}

// TestARecordsFileThatCannotBeReadIsMissing: a hard link to the records is not read, so the window has none.
func TestARecordsFileThatCannotBeReadIsMissing(t *testing.T) {
	f := baseFixture(t)
	lab := f.write(t)
	if err := os.Link(filepath.Join(lab, "windows", f.dir, LaurelFile), filepath.Join(t.TempDir(), "l")); err != nil {
		t.Fatal(err)
	}
	if w := load(t, lab).Windows[0]; w.Reason != ReasonLaurelFile {
		t.Fatalf("%+v", w)
	}
}

// TestOnlyExecResultsCountTheirProgram: a result that is no exec job does not make another's program repeated.
func TestOnlyExecResultsCountTheirProgram(t *testing.T) {
	f := baseFixture(t)
	other := bytes.Replace(f.window[ResultFile], []byte(`"program": "prog.sh",`), nil, 1)
	if bytes.Equal(other, f.window[ResultFile]) {
		t.Fatal("no program key")
	}
	f.extra["20261118t110000z-0123abcd-other"] = map[string][]byte{ResultFile: other}
	for _, w := range load(t, f.write(t)).Windows {
		if w.Dir == f.dir && !w.Valid() {
			t.Fatalf("the base: %+v", w)
		}
	}
}

// TestARuleOfABrokenPairIsListed: a pair that does not decode keeps its rules' rows, uncounted.
func TestARuleOfABrokenPairIsListed(t *testing.T) {
	f := baseFixture(t)
	f.pair = strings.Replace(f.pair, `"attack":"T0000"`, `"attack":1`, 1)
	out := load(t, f.write(t)).Table()
	if len(out.Rules) != 1 || out.Rules[0].Rule != fixtureRuleFile || out.Rules[0].Counted {
		t.Fatalf("rules %+v", out.Rules)
	}
}

// TestEachJobRefusalNamesItsCause, and a job reads only its own pair.
func TestEachJobRefusalNamesItsCause(t *testing.T) {
	old := syscall.Umask(0) // the modes the judge asks for, not the session's umask
	t.Cleanup(func() { syscall.Umask(old) })
	repeated := func(s, key string) string { return strings.Replace(s, key, key+","+key, 1) }
	for _, c := range []struct {
		name, pair, run, why string
		edit                 func(f *fixture)
		cause                error
	}{
		{"no such pair", "nope", "tech-a", `no pair "nope"`, nil, nil},
		{"no such run", fixturePair, "tech-c", `run "tech-c" is not one of`, nil, nil},
		{"a pair with a repeated key", fixturePair, "tech-a", "pair: ", func(f *fixture) { f.pair = repeated(f.pair, `"attack":"T0000"`) }, errRepeated},
		{"a rule with a repeated key", fixturePair, "tech-a", "rules: ", func(f *fixture) {
			f.rules[fixtureRuleFile] = repeated(f.rules[fixtureRuleFile], `"model":"test"`)
		}, errRepeated},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := baseFixture(t)
			if c.edit != nil {
				c.edit(f)
			}
			_, err := Job(f.write(t), c.pair, c.run, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), c.why) || (c.cause != nil && !errors.Is(err, c.cause)) {
				t.Fatalf("err %v, want %q", err, c.why)
			}
		})
	}
	f := baseFixture(t)
	lab := f.write(t)
	for path, why := range map[string]string{"": "lab: ", "pairs": "lab: pairs is not a directory", "rules": "lab: rules is not a directory", "pairs/d/x": "lab: pairs: "} {
		dir := t.TempDir()
		if path != "" {
			put(t, dir, path, nil)
		} else {
			dir = filepath.Join(dir, "none")
		}
		if _, err := Job(dir, fixturePair, "tech-a", t.TempDir()); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("lab %q: %v, want %q", path, err, why)
		}
	}
	if _, err := Job(lab, fixturePair, "tech-a", filepath.Join(t.TempDir(), "none")); err == nil || !strings.Contains(err.Error(), "target: ") {
		t.Fatalf("a missing target: %v", err)
	}
	// Another pair sorted first whose rules do not read, and rules without a pair: neither stops this pair's job.
	put(t, lab, "pairs/aaa.json", []byte("{}"))
	put(t, lab, "rules/aaa/d/x", nil)
	put(t, lab, "rules/orphan/x.json", []byte("{}"))
	target := t.TempDir()
	out, err := Job(lab, fixturePair, "tech-a", target)
	if err != nil {
		t.Fatalf("a job beside other pairs: %v", err)
	}
	name := strings.Fields(out)[0]
	for path, want := range map[string]os.FileMode{name: 0o750 | os.ModeDir, name + "/job.json": 0o640, name + "/prog.sh": 0o640} {
		if fi, err := os.Stat(filepath.Join(target, path)); err != nil || fi.Mode() != want {
			t.Errorf("%s: %v %v, want %v", path, fi.Mode(), err, want)
		}
	}
}

// TestEachImportRefusalNamesItsCause: every refused import returns 0 and why.
func TestEachImportRefusalNamesItsCause(t *testing.T) {
	f := baseFixture(t)
	id := idOf(t, f)
	sub := "20261118T130000Z-00000000-sub"
	res := results(t, map[string]map[string][]byte{id: f.window, sub: {ResultFile: []byte("{}")}}, true)
	put(t, res, sub+"/d/x", nil)
	linked := t.TempDir()
	if err := os.Symlink("x", filepath.Join(linked, "l")); err != nil {
		t.Fatal(err)
	}
	deep := t.TempDir()
	put(t, deep, "windows/w/sub/x", nil)
	missing := filepath.Join(t.TempDir(), "none")
	for _, c := range []struct {
		name, lab, results, id, why string
	}{
		{"the anchor itself", t.TempDir(), res, Anchor, "is not a result after the anchor"},
		{"a name after the anchor but not a result's", t.TempDir(), res, "zzz", "zzz is not a result after the anchor"},
		{"a result the runner does not hold", t.TempDir(), res, "20261118T140000Z-00000000-none", "no result 20261118T140000Z-00000000-none"},
		{"a result that does not read", t.TempDir(), res, sub, "result " + sub + ": "},
		{"no results", t.TempDir(), missing, id, "results: "},
		{"no lab", missing, res, id, "lab: "},
		{"a link in lab/", linked, res, id, "neither a regular file"},
		{"a directory too deep in lab/", deep, res, id, "within depth"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, err := Import(c.lab, c.results, c.id)
			if err == nil || n != 0 || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("%d %v, want %q", n, err, c.why)
			}
		})
	}
}

// TestImportsOneAfterAnother: a second result goes into the existing windows/, each with the runner's modes.
func TestImportsOneAfterAnother(t *testing.T) {
	old := syscall.Umask(0) // the modes the judge asks for, not the session's umask; no test here runs in parallel
	t.Cleanup(func() { syscall.Umask(old) })
	f := baseFixture(t)
	id := idOf(t, f)
	other := "20261118T130000Z-00000000-other"
	res := results(t, map[string]map[string][]byte{id: f.window, other: {ResultFile: []byte("{}")}}, true)
	lab := t.TempDir()
	for _, r := range []string{id, other} {
		if _, err := Import(lab, res, r); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
	for path, want := range map[string]os.FileMode{
		"windows":                           0o755 | os.ModeDir,
		"windows/" + strings.ToLower(other): 0o755 | os.ModeDir,
		"windows/" + strings.ToLower(other) + "/" + ResultFile: 0o644,
	} {
		if fi, err := os.Stat(filepath.Join(lab, path)); err != nil || fi.Mode() != want {
			t.Errorf("%s: %v %v, want %v", path, fi.Mode(), err, want)
		}
	}
	big := "20261118T150000Z-00000000-big"
	full := results(t, map[string]map[string][]byte{big: {ResultFile: make([]byte, LabCap)}}, true)
	if n, err := Import(t.TempDir(), full, big); err != nil || n != LabCap {
		t.Fatalf("a result of exactly lab/'s cap: %d %v", n, err)
	}
}

// TestEachVerifyFailureNamesItsCause: an error for what verify cannot read, a finding for a window it cannot.
func TestEachVerifyFailureNamesItsCause(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "none")
	fileIn := func(path string) string {
		d := t.TempDir()
		put(t, d, path, nil)
		return d
	}
	for _, c := range []struct{ name, lab, results, why string }{
		{"no results", t.TempDir(), missing, "results: "},
		{"no lab", missing, results(t, nil, true), "lab: "},
		{"a file among the results", t.TempDir(), fileIn(Anchor + "x"), "results: "},
		{"a file in windows/", fileIn("windows/x"), results(t, nil, true), "lab: windows: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := Verify(c.lab, c.results); err == nil || !strings.Contains(err.Error(), c.why) || errors.Unwrap(err) == nil {
				t.Fatalf("err %v, want %q", err, c.why)
			}
		})
	}
	id := "20261118T130000Z-00000000-x"
	res := results(t, map[string]map[string][]byte{id: {ResultFile: []byte("{}")}}, true)
	put(t, res, id+"/d/x", nil)
	if findings, _, err := Verify(t.TempDir(), res); err != nil || !findingWith(findings, "result "+id+": ") {
		t.Fatalf("a result that does not read: %v %v", findings, err)
	}
	lab := t.TempDir()
	put(t, lab, "windows/"+strings.ToLower(id)+"/d/x", nil)
	good := results(t, map[string]map[string][]byte{id: {ResultFile: []byte("{}")}}, true)
	if findings, _, err := Verify(lab, good); err != nil || !findingWith(findings, "windows/"+strings.ToLower(id)+": ") {
		t.Fatalf("a window that does not read: %v %v", findings, err)
	}
}
