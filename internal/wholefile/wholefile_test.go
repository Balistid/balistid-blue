package wholefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// A file in a directory others write is read only as a regular file with one link within its cap: a FIFO
// neither blocks nor reads, a symlink is not followed, a hard link could be changed through its other name.
func TestReadInRefusesAnythingElse(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"good", "linked"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("abcd"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(dir, "linked"), filepath.Join(dir, "other-name")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("good", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := openRoot(t, dir)
	if b, err := ReadIn(root, "good", 4); err != nil || string(b) != "abcd" {
		t.Fatalf("good: %q, %v", b, err)
	}
	for name, limit := range map[string]int64{"good": 3, "linked": 4, "fifo": 4, "link": 4, "sub": 4, "none": 4, "../x": 4} {
		done := make(chan error, 1)
		go func() { _, err := ReadIn(root, name, limit); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: read", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: ReadIn blocked", name)
		}
	}
}

// WriteIn sets the mode asked for whatever the umask, replaces a symlink at the name instead of following it,
// writes nothing outside the root and leaves no temp file behind, written or not.
func TestWriteInWritesWholeInsideTheRoot(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "etc"), 0o755); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "etc", "unit")); err != nil {
		t.Fatal(err)
	}
	root := openRoot(t, dir)
	if err := WriteIn(root, "etc/unit", []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "keep" { //nolint:gosec // test temp dir
		t.Fatalf("outside now %q, %v", b, err)
	}
	st, err := os.Lstat(filepath.Join(dir, "etc", "unit"))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o644 {
		t.Fatalf("etc/unit: %v, %v", st, err)
	}
	for _, name := range []string{"../escape", "missing/unit"} {
		if err := WriteIn(root, name, []byte("x"), 0o644); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "etc"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "unit" {
		t.Fatalf("etc holds %v, %v", entries, err)
	}
}
