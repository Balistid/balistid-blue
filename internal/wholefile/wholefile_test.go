package wholefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The mode is the one asked for whatever the umask: 0600 for private state, 0640 for results the
// maintainer's group reads.
func TestWriteSetsTheMode(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	for _, perm := range []os.FileMode{0o600, 0o640} {
		path := filepath.Join(t.TempDir(), "result.json")
		if err := Write(path, []byte("{}"), perm); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != perm {
			t.Fatalf("mode %v, want %v", st.Mode().Perm(), perm)
		}
	}
}

// A file another service writes is read only as that uid's regular file of its exact size: a FIFO neither
// blocks nor reads, a symlink is not followed.
func TestReadOwnedRefusesAnythingElse(t *testing.T) {
	dir := t.TempDir()
	good, fifo, link := filepath.Join(dir, "good"), filepath.Join(dir, "fifo"), filepath.Join(dir, "link")
	if err := Write(good, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwned(good, os.Getuid(), 4); err != nil || string(b) != "abcd" {
		t.Fatalf("good: %q, %v", b, err)
	}
	for name, c := range map[string]struct {
		path      string
		uid, size int
	}{
		"another owner": {good, os.Getuid() + 1, 4}, "longer": {good, os.Getuid(), 3}, "shorter": {good, os.Getuid(), 5},
		"symlink": {link, os.Getuid(), 4}, "fifo": {fifo, os.Getuid(), 0}, "directory": {dir, os.Getuid(), 4},
		"missing": {filepath.Join(dir, "none"), os.Getuid(), 4},
	} {
		if _, err := ReadOwned(c.path, c.uid, c.size); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func TestWriteReplacesASymlinkInsteadOfFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "keep" { //nolint:gosec // test temp dir
		t.Fatalf("target now %q, %v", b, err)
	}
	if st, err := os.Lstat(link); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("link is not a regular file: %v", err)
	}
}
