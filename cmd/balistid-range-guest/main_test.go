package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Laurel renames a full log and starts a new one; any rotation during the job means records may
// sit in a file the window never reads, so it is never reported complete.
func TestLaurelWindowIsCompleteOnlyWithoutARotation(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.log")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	appendTo := func(path, s string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // test temp dir
		must(err)
		_, err = f.WriteString(s)
		must(err)
		must(f.Close())
	}
	appendTo(log, "old\n")
	before, err := os.Open(log) //nolint:gosec // test temp dir
	must(err)
	defer before.Close() //nolint:errcheck // test
	offset, err := before.Seek(0, io.SeekEnd)
	must(err)

	appendTo(log, "job-a\n")
	if w, cut := laurelWindow(before, log, offset, 1<<20); string(w) != "job-a\n" || cut != "no" {
		t.Fatalf("no rotation: %q %s", w, cut)
	}
	if w, cut := laurelWindow(before, log, offset, 3); len(w) != 3 || cut != "yes" {
		t.Fatalf("over the cap: %q %s", w, cut)
	}
	must(os.Rename(log, log+".1"))
	appendTo(log, "job-b, longer than the old offset\n")
	for _, limit := range []int64{1 << 20, 3} {
		if _, cut := laurelWindow(before, log, offset, limit); cut != "rotated" {
			t.Fatalf("rotation with cap %d reported %s", limit, cut)
		}
	}
	must(os.Remove(log))
	if _, cut := laurelWindow(before, log, offset, 1<<20); cut != "rotated" {
		t.Fatalf("log removed: %s", cut)
	}
}
