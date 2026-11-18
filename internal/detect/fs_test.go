package detect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	if _, err := entries(rootOf(t, dir), true); err == nil || !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("a file listed as a directory: %v", err)
	}
	if _, err := entries(rootOf(t, dir), false); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Fatalf("a link listed as a regular file: %v", err)
	}
	if maxEntries != 4096 {
		t.Fatalf("maxEntries %d", maxEntries)
	}
	many := t.TempDir()
	for i := range maxEntries {
		put(t, many, strconv.Itoa(i), nil)
	}
	if names, err := entries(rootOf(t, many), false); err != nil || len(names) != maxEntries {
		t.Fatalf("a directory of exactly maxEntries: %d %v", len(names), err)
	}
	put(t, many, "last", nil)
	if _, err := entries(rootOf(t, many), false); err == nil {
		t.Fatal("a directory over maxEntries listed")
	}
}

// locked makes dir unsearchable or unreadable for the test and restores it after.
func locked(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // the test's own temp dir
}

func TestOpenDirPermissions(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "d/f", []byte("x"))
	put(t, dir, "unreadable/f", []byte("x"))
	root := rootOf(t, dir)
	locked(t, filepath.Join(dir, "unreadable"), 0o300)
	if _, err := openDir(root, "unreadable"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("an unreadable directory: %v", err)
	}
	locked(t, dir, 0o600)
	if _, err := openDir(root, "d"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("under an unsearchable directory: %v", err)
	}
}

func TestTreeBytes(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "a", make([]byte, 3))
	put(t, dir, "b", make([]byte, 5))
	put(t, dir, "s/c", make([]byte, 7))
	put(t, dir, "s/t/d", make([]byte, 11))
	if n, err := treeBytes(rootOf(t, dir), 2); err != nil || n != 26 {
		t.Fatalf("depth 2: %d %v", n, err)
	}
	if n, err := treeBytes(rootOf(t, dir), 1); err == nil || n != 0 || !strings.Contains(err.Error(), "within depth") {
		t.Fatalf("a directory below the depth: %d %v", n, err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "s", "t", "link")); err != nil {
		t.Fatal(err)
	}
	if n, err := treeBytes(rootOf(t, dir), 2); err == nil || n != 0 || !strings.Contains(err.Error(), "neither a regular file") {
		t.Fatalf("a link two levels down: %d %v", n, err)
	}
	locked(t, filepath.Join(dir, "s"), 0o300)
	if _, err := treeBytes(rootOf(t, dir), 2); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("an unreadable directory: %v", err)
	}
	many := t.TempDir()
	for i := range maxEntries {
		put(t, many, strconv.Itoa(i), []byte("x"))
	}
	if n, err := treeBytes(rootOf(t, many), 0); err != nil || n != maxEntries {
		t.Fatalf("exactly maxEntries: %d %v", n, err)
	}
	put(t, many, "last", nil)
	if _, err := treeBytes(rootOf(t, many), 0); err == nil {
		t.Fatal("over maxEntries sized")
	}
}

func TestBudget(t *testing.T) {
	dir := t.TempDir()
	put(t, dir, "f", make([]byte, 10))
	root := rootOf(t, dir)
	b := &budget{left: 25}
	if _, err := b.read(root, "f", 9); !errors.Is(err, errOverCap) || b.left != 15 {
		t.Fatalf("over its cap: %v, left %d: a refused file must still count", err, b.left)
	}
	if data, err := b.read(root, "f", 10); err != nil || len(data) != 10 || b.left != 5 {
		t.Fatalf("read: %d %v left %d", len(data), err, b.left)
	}
	if _, err := b.read(root, "f", 10); !errors.Is(err, errOverBudget) {
		t.Fatalf("over the tree's cap: %v", err)
	}
	if _, err := b.read(root, "none", 10); err == nil || errors.Unwrap(err) == nil || errors.Is(err, errOverCap) {
		t.Fatalf("a missing file: %v", err)
	}
	exact := &budget{left: 10}
	if data, err := exact.read(root, "f", 10); err != nil || len(data) != 10 || exact.left != 0 {
		t.Fatalf("a file of exactly the budget: %d %v", len(data), err)
	}
	if err := os.Symlink(strings.Repeat("x", 200), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	small := &budget{left: 10}
	if _, err := small.read(root, "link", 10); err == nil || errors.Is(err, errOverBudget) || small.left != 10 {
		t.Fatalf("a link is not sized as a file: %v, left %d", err, small.left)
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
	if err := publish(root, "nested", map[string][]byte{"a/b": []byte("x")}, 0o750, 0o640); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a write's cause: %v", err)
	}
	list, err := os.ReadDir(dir)
	if err != nil || len(list) != 1 || list[0].Name() != "out" {
		t.Fatalf("publish left %v", list)
	}
}

func TestPublishIntoAReadOnlyDirectory(t *testing.T) {
	dir := t.TempDir()
	root := rootOf(t, dir)
	locked(t, dir, 0o500)
	if err := publish(root, "out", map[string][]byte{"a": nil}, 0o750, 0o640); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("publish into a read-only directory: %v", err)
	}
}
