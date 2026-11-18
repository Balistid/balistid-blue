package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/detect"
)

func TestUsageIsExit2(t *testing.T) {
	for _, args := range [][]string{nil, {"table"}, {"verify", "a", "b"}, {"nope", "x"}, {"job", "a"},
		{"job", "a", "b", "c"}, {"import", "a"}, {"import", "a", "b", "c", "d"}, {"table", "a", "b", "c", "d"}} {
		var out, errb bytes.Buffer
		if code := run(args, t.TempDir(), &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errb.String())
		}
	}
}

func TestTableOfAnEmptyLab(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"table", t.TempDir()}, t.TempDir(), &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"not_measured"`) {
		t.Fatalf("table: %s", out.String())
	}
}

func TestVerifyFailsWithoutTheAnchor(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"verify", t.TempDir()}, t.TempDir(), &out, &errb); code != 1 || !strings.Contains(errb.String(), "no longer kept") ||
		!strings.HasSuffix(errb.String(), "\nbalistid-lab: verify failed, 1 findings\n") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	results := t.TempDir()
	if err := os.Mkdir(filepath.Join(results, detect.Anchor), 0o750); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := run([]string{"verify", t.TempDir()}, results, &out, &errb); code != 0 || !strings.Contains(out.String(), "byte for byte") {
		t.Fatalf("verify with the anchor kept and nothing after it: exit %d", code)
	}
}

func TestErrorsAreExit1(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{
		{"table", filepath.Join(t.TempDir(), "missing")},
		{"import", t.TempDir(), "not-an-id"},
		{"job", t.TempDir(), "nopair", "tech-a", t.TempDir()},
	} {
		if code := run(args, t.TempDir(), &out, &errb); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestPrintableEscapesWhatCouldForgeALine(t *testing.T) {
	if got := printable("a\nb\x1b[31m\x00é~"); got != `a\x0ab\x1b[31m\x00\xc3\xa9~` {
		t.Fatalf("printable: %q", got)
	}
	if got := printable("\x1f \x7f"); got != `\x1f \x7f` {
		t.Fatalf("printable's bounds: %q", got)
	}
}

func TestUsageBeforeTheRunner(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"verify"}, filepath.Join(t.TempDir(), "none"), &out, &errb); code != 2 {
		t.Fatalf("verify without its lab: exit %d", code)
	}
}

func TestWriteFailureIsExit1(t *testing.T) {
	var errb bytes.Buffer
	if code := run([]string{"table", t.TempDir()}, t.TempDir(), failing{}, &errb); code != 1 || !strings.Contains(errb.String(), "write") {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
}

type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, errors.New("closed") }

// testPair is a pair the judge decodes, its runs short programs.
const testPair = `{"attack":"T0000","author":"test","brief":"a test pair",` +
	`"reference":{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"}]},"runs":{` +
	`"tech-a":{"program":"a.sh","timeout_s":60,"text":"#!/bin/sh\nuname -r\n"},` +
	`"tech-b":{"program":"b.sh","timeout_s":60,"text":"#!/bin/sh\nuname -a\n"},` +
	`"twin-a":{"program":"c.sh","timeout_s":60,"text":"#!/bin/sh\nid -u\n"},` +
	`"twin-b":{"program":"d.sh","timeout_s":60,"text":"#!/bin/sh\nid -g\n"}}}` + "\n"

func TestJobWritesTheRunNamed(t *testing.T) {
	lab, target := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(lab, "pairs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lab, "pairs", "p.json"), []byte(testPair), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"job", lab, "p", "tech-b", target}, t.TempDir(), &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	name := strings.Fields(out.String())[0]
	if !strings.HasPrefix(name, "p-tech-b-") {
		t.Fatalf("job %q", out.String())
	}
	got, err := os.ReadFile(filepath.Join(target, name, "b.sh")) //nolint:gosec // the test's own temp dir
	if err != nil || string(got) != "#!/bin/sh\nuname -a\n" {
		t.Fatalf("program %q %v", got, err)
	}
	errb.Reset()
	if code := run([]string{"job", lab, "nopair", "tech-a", target}, t.TempDir(), &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), `balistid-lab: job: no pair "nopair"`) {
		t.Fatalf("a missing pair: exit %d, %q", code, errb.String())
	}
}

func TestEachFailureNamesItsSubcommand(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, c := range []struct {
		args    []string
		results string
		want    string
	}{
		{[]string{"table", missing}, t.TempDir(), "balistid-lab: table: lab: "},
		{[]string{"verify", t.TempDir()}, missing, "balistid-lab: verify: results: "},
		{[]string{"import", t.TempDir(), "not-an-id"}, t.TempDir(), "balistid-lab: import: not-an-id is not a result after the anchor"},
	} {
		var out, errb bytes.Buffer
		if code := run(c.args, c.results, &out, &errb); code != 1 || !strings.Contains(errb.String(), c.want) || out.Len() != 0 {
			t.Errorf("%v: exit %d, stderr %q, stdout %q", c.args, code, errb.String(), out.String())
		}
	}
}

func TestImportCopiesTheResultNamed(t *testing.T) {
	id := "20261118T130000Z-00000000-x"
	lab, results := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(results, id), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(results, id, "result.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"import", lab, id}, results, &out, &errb); code != 0 ||
		out.String() != fmt.Sprintf("imported %s; lab/ holds 3 bytes of %d\n", id, detect.LabCap) {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	got, err := os.ReadFile(filepath.Join(lab, "windows", strings.ToLower(id), "result.json")) //nolint:gosec // the test's own temp dir
	if err != nil || string(got) != "{}\n" {
		t.Fatalf("imported %q %v", got, err)
	}
}

// TestVerifyAndImportReadOnlyTheRunnersResults: the caller's own directory is refused before either reads it.
func TestVerifyAndImportReadOnlyTheRunnersResults(t *testing.T) {
	own := t.TempDir()
	for _, args := range [][]string{{"verify", t.TempDir()}, {"import", t.TempDir(), "20261118T130000Z-00000000-x"}} {
		var out, errb bytes.Buffer
		if code := entry(args, own, &out, &errb); code != 1 || !strings.Contains(errb.String(), "is the caller's, not the runner's") {
			t.Errorf("%v on the caller's directory: exit %d, %q", args, code, errb.String())
		}
	}
	if os.Getuid() == 0 {
		t.Skip("root owns /usr")
	}
	// root's /usr passes the check; verify then reads it and fails on what it holds, which differs by host
	var out, errb bytes.Buffer
	if code := entry([]string{"verify", t.TempDir()}, "/usr", &out, &errb); code != 1 ||
		strings.Contains(errb.String(), "not the runner's") || !strings.Contains(errb.String(), "balistid-lab: verify") {
		t.Fatalf("verify past the check: exit %d, %q", code, errb.String())
	}
	errb.Reset()
	if code := entry([]string{"table", t.TempDir()}, own, &out, &errb); code != 0 {
		t.Fatalf("table needs no runner: exit %d, %q", code, errb.String())
	}
	errb.Reset()
	for _, args := range [][]string{{"verify", "a", "b"}, {"import", "a"}, {"import", "a", "b", "c"}} {
		errb.Reset()
		if code := entry(args, own, &out, &errb); code != 2 {
			t.Fatalf("%v: a usage error before the check: exit %d, %q", args, code, errb.String())
		}
	}
}
