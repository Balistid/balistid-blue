package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/shard"
)

// TestLeftoverTempFilesGo: a .tmp- file a crashed run left in the results directory is gone after the next run;
// a link or a directory of that name is neither followed nor removed.
func TestLeftoverTempFilesGo(t *testing.T) {
	ts := threeShards(t)
	out := t.TempDir()
	outside := filepath.Join(t.TempDir(), "kept")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, create := range map[string]func(string) error{
		".tmp-0123456789abcdef": func(p string) error { return os.WriteFile(p, []byte("half a shard"), 0o600) },
		".tmp-link":             func(p string) error { return os.Symlink(outside, p) },
		".tmp-x":                func(p string) error { return os.Mkdir(p, 0o700) },
	} {
		if err := create(filepath.Join(out, name)); err != nil {
			t.Fatal(err)
		}
	}
	status, err := judge(t.Context(), config{Store: ts.dir, Out: out, Scratch: scratchOf(t), Now: time.Now, Limit: readLimit})
	if status != statusComplete || err != nil {
		t.Fatal(status, err)
	}
	if _, err := os.Lstat(filepath.Join(out, ".tmp-0123456789abcdef")); !os.IsNotExist(err) {
		t.Errorf("the leftover is still there: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(out, ".tmp-link")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link: %v %v", fi, err)
	}
	if fi, err := os.Lstat(filepath.Join(out, ".tmp-x")); err != nil || !fi.IsDir() {
		t.Errorf("the directory: %v %v", fi, err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "x" { //nolint:gosec // the test's own file
		t.Errorf("the link's target: %q %v", b, err)
	}
}

func scratchOf(t *testing.T) shard.Scratch {
	t.Helper()
	return shard.Scratch{Dir: t.TempDir(), Max: 64 << 20}
}
