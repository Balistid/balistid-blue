package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Laurel renames a full log and starts a new one; the job's records span both files.
func TestLaurelWindowFollowsARotation(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.log")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	appendTo := func(path, s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		must(err)
		_, err = f.WriteString(s)
		must(err)
		must(f.Close())
	}
	appendTo(log, "old\n")
	before, err := os.Open(log)
	must(err)
	defer before.Close() //nolint:errcheck // test
	offset, err := before.Seek(0, io.SeekEnd)
	must(err)

	appendTo(log, "job-a\n")
	if w, cut := laurelWindow(before, log, offset, 1<<20); string(w) != "job-a\n" || cut != "no" {
		t.Fatalf("no rotation: %q %s", w, cut)
	}
	must(os.Rename(log, log+".1"))
	appendTo(log, "job-b and more than the old offset\n")
	w, cut := laurelWindow(before, log, offset, 1<<20)
	if string(w) != "job-a\njob-b and more than the old offset\n" || cut != "rotated" {
		t.Fatalf("after a rotation: %q %s", w, cut)
	}
	if w, cut := laurelWindow(before, log, offset, 8); len(w) != 8 || cut != "yes" {
		t.Fatalf("over the cap: %q %s", w, cut)
	}
}

// A log Laurel creates only during the job is read whole; a missing one is an error, not empty.
func TestLaurelWindowWithoutALogBefore(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.log")
	if _, cut := laurelWindow(nil, log, 0, 1<<20); cut != "error" {
		t.Fatalf("no log at all: %s", cut)
	}
	if err := os.WriteFile(log, []byte("job\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w, cut := laurelWindow(nil, log, 0, 1<<20); string(w) != "job\n" || cut != "no" {
		t.Fatalf("log created during the job: %q %s", w, cut)
	}
}
