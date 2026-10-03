package rangevm

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	return got
}

func TestPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"20261003T100000Z-c", "20261001T100000Z-a", "20261002T100000Z-b"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := prune(dir, 2); err != nil {
		t.Fatal(err)
	}
	if got, want := names(t, dir), []string{"20261002T100000Z-b", "20261003T100000Z-c"}; !slices.Equal(got, want) {
		t.Fatalf("kept %q, want %q", got, want)
	}
}

func TestLockRemovesStaleDirectoriesAndExcludesASecondHolder(t *testing.T) {
	cache := t.TempDir()
	for _, d := range []string{"stage-1", "build-2", "runs/run-3", "images/20261003T100000Z-x"} {
		if err := os.MkdirAll(filepath.Join(cache, d, "big"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	unlock, err := lock(cache)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := names(t, cache), []string{"images", "lock", "runs"}; !slices.Equal(got, want) {
		t.Fatalf("cache holds %q, want %q", got, want)
	}
	if got := names(t, filepath.Join(cache, "runs")); len(got) != 0 {
		t.Fatalf("stale run directories left: %q", got)
	}
	if _, err := lock(cache); err == nil {
		t.Fatal("a second holder got the lock")
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	again, err := lock(cache)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := again(); err != nil {
		t.Fatal(err)
	}
}

func TestReadManifest(t *testing.T) {
	linux := `{"name":"linux","version":"` + strings.Replace(TargetKernel, "-", ".", 1) + `"}`
	cases := map[string]struct {
		body string
		ok   bool
	}{
		"target kernel":  {`{"manifest_version":1,"packages":[{"name":"systemd","version":"262-1"},` + linux + `]}`, true},
		"other kernel":   {`{"manifest_version":1,"packages":[{"name":"linux","version":"7.2.7.arch1-1"}]}`, false},
		"no kernel":      {`{"manifest_version":1,"packages":[]}`, false},
		"future version": {`{"manifest_version":2,"packages":[` + linux + `]}`, false},
		"null":           {`null`, false},
		"array":          {`[]`, false},
		"not json":       {`linux 7.2.8`, false},
		"oversized":      {`{"manifest_version":1,"packages":[` + linux + `],"x":"` + strings.Repeat("x", maxManifest) + `"}`, false},
	}
	dir := t.TempDir()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readManifest(path); (err == nil) != c.ok {
				t.Fatalf("readManifest error = %v, want ok=%v", err, c.ok)
			}
		})
	}
	if _, err := readManifest(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing manifest was accepted")
	}
}

func TestReadCommit(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]bool{
		strings.Repeat("a", 40) + "\n": true,
		strings.Repeat("a", 39):        false,
		"HEAD":                         false,
		strings.Repeat("A", 40):        false,
	}
	for body, ok := range cases {
		path := filepath.Join(dir, "commit")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCommit(path); (err == nil) != ok {
			t.Errorf("readCommit(%q) error = %v, want ok=%v", body, err, ok)
		}
	}
}

func TestImageInputsMustBeRegularFiles(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "image.raw")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSHA256(context.Background(), fifo); err == nil {
		t.Fatal("hashed a FIFO")
	}
	if _, err := fileSHA256(context.Background(), t.TempDir()); err == nil {
		t.Fatal("hashed a directory")
	}
}

func TestHashStopsWhenCancelled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fileSHA256(ctx, path); err == nil {
		t.Fatal("hashing ignored a cancelled context")
	}
}

func TestWriteFileAtomicIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := writeFileAtomic(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
}
