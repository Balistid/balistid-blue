// Trial for the judge lock: this pull request must not merge without the maintainer.
package detect

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// maxEntries bounds the names the judge lists in one directory (R5).
const maxEntries = 4096

var errMissing = errors.New("missing")

// openDir opens name, one component under root, as a directory that is not a link: Lstat must show a
// directory before the open and the opened directory must be the same file after it, so neither a link nor a
// FIFO nor a swap redirects or blocks it. A missing name is errMissing.
func openDir(root *os.Root, name string) (*os.Root, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errMissing
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if !before.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", name)
	}
	sub, err := root.OpenRoot(name + "/.") // "/." makes the open itself require a directory: a FIFO fails, not blocks
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	after, err := statOpened(sub)
	if err != nil || !os.SameFile(before, after) {
		_ = sub.Close()
		return nil, fmt.Errorf("%s changed while it was opened", name)
	}
	return sub, nil
}

// entries lists dir's names, sorted, every one a directory (dirs) or a regular file; anything else fails.
func entries(dir *os.Root, dirs bool) ([]string, error) {
	list, err := listDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for _, e := range list {
		if (dirs && !e.IsDir()) || (!dirs && !e.Type().IsRegular()) {
			return nil, fmt.Errorf("%s is not a %s", e.Name(), map[bool]string{true: "directory", false: "regular file"}[dirs])
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names, nil
}

// listDir lists dir's entries, at most maxEntries of them, or fails.
func listDir(dir *os.Root) ([]os.DirEntry, error) {
	f, err := dir.Open(".")
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	list, err := f.ReadDir(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("list: %w", err)
	}
	if len(list) > maxEntries {
		return nil, fmt.Errorf("list: over %d entries", maxEntries)
	}
	return list, nil
}

// budget counts the bytes the judge reads from one tree against a cap (R5).
type budget struct{ left int64 }

// errOverCap marks a file over its own cap, so a window can name the closed reason; errOverBudget marks a tree
// over its total, which fails the whole read.
var (
	errOverCap    = errors.New("over its cap")
	errOverBudget = errors.New("over the tree's cap")
)

// read reads the regular file name in dir under limit and the budget.
func (b *budget) read(dir *os.Root, name string, limit int64) ([]byte, error) {
	if fi, err := dir.Lstat(name); err == nil && fi.Mode().IsRegular() {
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
			return nil, fmt.Errorf("%s: must have exactly one link", name) // a link is refused before any cap
		}
		switch {
		case fi.Size() > b.left: // a file refused for its own cap still counts against the tree's
			return nil, fmt.Errorf("%s: %w", name, errOverBudget)
		case fi.Size() > limit:
			b.left -= fi.Size()
			return nil, fmt.Errorf("%s: %w", name, errOverCap)
		}
	}
	data, err := wholefile.ReadIn(dir, name, min(limit, b.left))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	b.left -= int64(len(data))
	return data, nil
}

// stagingName is a fresh name for a directory built before it is renamed into place.
func stagingName() string { return ".staging-" + strings.ToLower(rand.Text()) }

// publish writes files into a staging directory under dir and renames it to name, so a reader sees all of
// them or none; it refuses an existing name, checked just before the rename, and removes its staging on failure.
func publish(dir *os.Root, name string, files map[string][]byte, dirMode, fileMode os.FileMode) error {
	staging := stagingName()
	if err := dir.Mkdir(staging, dirMode); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	fail := func(err error) error {
		return errors.Join(err, dir.RemoveAll(staging))
	}
	if err := chmodIn(dir, staging, dirMode); err != nil { // the mode asked for, not what the umask left of it
		return fail(fmt.Errorf("staging: %w", err))
	}
	sub, err := openDir(dir, staging)
	if err != nil {
		return fail(err)
	}
	defer sub.Close() //nolint:errcheck // every write is synced by WriteIn
	for _, n := range sortedKeys(files) {
		if err := wholefile.WriteIn(sub, n, files[n], fileMode); err != nil {
			return fail(fmt.Errorf("write %s: %w", n, err))
		}
	}
	if _, err := dir.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		return fail(fmt.Errorf("%s already exists", name))
	}
	if err := rename(dir, staging, name); err != nil {
		return fail(fmt.Errorf("publish %s: %w", name, err))
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("%s is published but not durable, sync its directory: %w", name, err) // a retry refuses the name
	}
	return nil
}

// statOpened, rename, syncDir, syncFile, lstatIn and chmodIn are the calls only a racing writer or a failing disk makes
// fail; tests replace them to stand for those.
var (
	statOpened = func(sub *os.Root) (os.FileInfo, error) { return sub.Stat(".") }
	rename     = func(dir *os.Root, from, to string) error { return dir.Rename(from, to) }
	syncDir    = syncDirOf
	syncFile   = func(f *os.File) error { return errors.Join(f.Sync(), f.Close()) }
	lstatIn    = func(dir *os.Root, name string) (os.FileInfo, error) { return dir.Lstat(name) }
	chmodIn    = func(dir *os.Root, name string, mode os.FileMode) error { return dir.Chmod(name, mode) }
)

// syncDirOf makes a rename in dir durable (ENGINEERING.md 7).
func syncDirOf(dir *os.Root) error {
	f, err := dir.Open(".")
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := syncFile(f); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	return nil
}

// treeBytes is the bytes of every regular file under dir, depth levels of directories deep at most, each
// listed under maxEntries and never through a link (R5).
func treeBytes(dir *os.Root, depth int) (int64, error) {
	list, err := listDir(dir)
	if err != nil {
		return 0, fmt.Errorf("size: %w", err)
	}
	var total int64
	for _, e := range list {
		switch {
		case e.Type().IsRegular():
			fi, err := lstatIn(dir, e.Name())
			if err != nil {
				return 0, fmt.Errorf("size: %w", err)
			}
			total += fi.Size()
		case e.IsDir() && depth > 0:
			sub, err := openDir(dir, e.Name())
			if err != nil {
				return 0, err
			}
			n, err := treeBytes(sub, depth-1)
			_ = sub.Close()
			if err != nil {
				return 0, err
			}
			total += n
		default:
			return 0, fmt.Errorf("size: %s is neither a regular file nor a directory within depth", e.Name())
		}
	}
	return total, nil
}
