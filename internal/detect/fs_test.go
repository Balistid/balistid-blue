package detect

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func rootOf(t *testing.T, dir string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestOpenDir(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "d/f", []byte("x"))
	put(t, dir, "file", []byte("x"))
	if err := os.Symlink("d", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := rootOf(t, dir)
	sub, err := openDir(root, "d")
	if err != nil {
		t.Fatal(err)
	}
	_ = sub.Close()
	if _, err := openDir(root, "none"); !errors.Is(err, errMissing) {
		t.Fatalf("a missing directory: %v", err)
	}
	for _, name := range []string{"link", "fifo", "file"} {
		if _, err := openDir(root, name); err == nil || errors.Is(err, errMissing) {
			t.Errorf("%s opened as a directory: %v", name, err)
		}
	}
}

func TestEntries(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "b", []byte("x"))
	put(t, dir, "a", []byte("x"))
	names, err := entries(rootOf(t, dir), false)
	if err != nil || len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("%v %v", names, err)
	}
	if _, err := entries(rootOf(t, dir), true); err == nil {
		t.Fatal("files listed as directories")
	}
	if err := os.Symlink("a", filepath.Join(dir, "c")); err != nil {
		t.Fatal(err)
	}
	if _, err := entries(rootOf(t, dir), false); err == nil {
		t.Fatal("a link listed as a regular file")
	}
	empty, err := entries(rootOf(t, t.TempDir()), true)
	if err != nil || len(empty) != 0 {
		t.Fatalf("an empty directory: %v %v", empty, err)
	}
	many := t.TempDir()
	for i := range maxEntries + 1 {
		put(t, many, strconv.Itoa(i), nil)
	}
	if _, err := entries(rootOf(t, many), false); err == nil {
		t.Fatal("a directory over maxEntries listed")
	}
}

func TestBudget(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "f", make([]byte, 10))
	root := rootOf(t, dir)
	b := &budget{left: 15}
	if _, err := b.read(root, "f", 9); !errors.Is(err, errOverCap) {
		t.Fatalf("over its cap: %v", err)
	}
	if data, err := b.read(root, "f", 10); err != nil || len(data) != 10 || b.left != 5 {
		t.Fatalf("read: %d %v left %d", len(data), err, b.left)
	}
	if _, err := b.read(root, "f", 10); !errors.Is(err, errOverBudget) {
		t.Fatalf("over the tree's cap: %v", err)
	}
	if _, err := b.read(root, "none", 10); err == nil || errors.Is(err, errOverCap) {
		t.Fatalf("a missing file: %v", err)
	}
}

func TestPublish(t *testing.T) {
	dir := t.TempDir()
	root := rootOf(t, dir)
	if err := publish(root, "out", map[string][]byte{"a": []byte("1"), "b": []byte("2")}, 0o750, 0o640); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]string{"a": "1", "b": "2"} {
		got, err := os.ReadFile(filepath.Join(dir, "out", n)) //nolint:gosec // the test's own temp dir
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", n, got, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "out", "a")); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	if err := publish(root, "out", map[string][]byte{"c": nil}, 0o750, 0o640); err == nil {
		t.Fatal("published over an existing directory")
	}
	if err := publish(root, "bad", map[string][]byte{"../escape": []byte("x")}, 0o750, 0o640); err == nil {
		t.Fatal("published a file outside its directory")
	}
	list, err := os.ReadDir(dir)
	if err != nil || len(list) != 1 || list[0].Name() != "out" {
		t.Fatalf("publish left %v", list)
	}
}
