package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/detect"
)

func TestUsageIsExit2(t *testing.T) {
	for _, args := range [][]string{nil, {"table"}, {"verify", "a", "b"}, {"nope", "x"}} {
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
	if code := run([]string{"verify", t.TempDir()}, t.TempDir(), &out, &errb); code != 1 || !strings.Contains(errb.String(), "no longer kept") {
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
