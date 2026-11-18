package detect

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTheAnchorIsPinned keeps the anchor of ADR 0078 point 1: changing it changes this test, which is code-owned
// once the judge is locked (ADR 0077 point 7).
func TestTheAnchorIsPinned(t *testing.T) {
	if Anchor != "20261117T222824Z-cf92a4e6-pr13-run-d4" || ResultsDir != "/var/lib/balistid/results/agent" {
		t.Fatalf("anchor %s, results %s", Anchor, ResultsDir)
	}
	if !resultID.MatchString(Anchor) {
		t.Fatal("the anchor is not a result's name")
	}
}

// TestOnlyTheStandardLibrary checks the judge and its command import the standard library and, of this
// repository, only internal/detect and internal/wholefile (ADR 0077 point 6, ADR 0079 point 1).
func TestOnlyTheStandardLibrary(t *testing.T) {
	allowed := map[string]bool{
		"github.com/Balistid/balistid-blue/internal/detect":    true,
		"github.com/Balistid/balistid-blue/internal/wholefile": true,
	}
	for _, dir := range []string{".", "../../cmd/balistid-lab"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, name := range files {
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if !allowed[p] && strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
					t.Errorf("%s imports %s", name, p)
				}
			}
		}
	}
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data := ""
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			data = string(b)
		}
		files[p] = info.Mode().String() + info.ModTime().String() + data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestTableAndVerifyWriteNothing is acceptance judge_writes for the two read-only subcommands.
func TestTableAndVerifyWriteNothing(t *testing.T) {
	f := fourWindows(t)
	lab := f.write(t)
	res := results(t, map[string]map[string][]byte{idOf(t, f): f.window}, true)
	before, beforeRes := snapshot(t, lab), snapshot(t, res)
	load(t, lab).Table().Encode()
	if _, err := Verify(lab, res); err != nil {
		t.Fatal(err)
	}
	after, afterRes := snapshot(t, lab), snapshot(t, res)
	for _, pair := range [][2]map[string]string{{before, after}, {beforeRes, afterRes}} {
		if len(pair[0]) != len(pair[1]) {
			t.Fatal("a file was created")
		}
		for p, v := range pair[0] {
			if pair[1][p] != v {
				t.Fatalf("%s changed", p)
			}
		}
	}
}

// TestImportAndJobWriteOnlyTheirPlace is acceptance judge_writes for the two writing subcommands.
func TestImportAndJobWriteOnlyTheirPlace(t *testing.T) {
	f := baseFixture(t)
	lab := f.write(t)
	id := idOf(t, f)
	res := results(t, map[string]map[string][]byte{id: f.window}, true)
	if err := os.RemoveAll(filepath.Join(lab, "windows")); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, lab)
	if _, err := Import(lab, res, id); err != nil {
		t.Fatal(err)
	}
	for p := range snapshot(t, lab) {
		if _, old := before[p]; !old && !strings.HasPrefix(p, filepath.Join(lab, "windows")) {
			t.Fatalf("import wrote %s outside lab/windows", p)
		}
	}
	target := t.TempDir()
	labBefore := snapshot(t, lab)
	name, err := Job(lab, fixturePair, "tech-b", target)
	if err != nil {
		t.Fatal(err)
	}
	for p := range snapshot(t, target) {
		if p != target && !strings.HasPrefix(p, filepath.Join(target, strings.Fields(name)[0])) {
			t.Fatalf("job wrote %s outside its directory", p)
		}
	}
	if len(snapshot(t, lab)) != len(labBefore) {
		t.Fatal("job wrote into lab/")
	}
}
