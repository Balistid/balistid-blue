package detect

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
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
	sub, err := root.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	after, err := sub.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = sub.Close()
		return nil, fmt.Errorf("%s changed while it was opened", name)
	}
	return sub, nil
}

// entries lists dir's names, sorted, every one a directory (dirs) or a regular file; anything else fails.
func entries(dir *os.Root, dirs bool) ([]string, error) {
	f, err := dir.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
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
func stagingName() (string, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", fmt.Errorf("staging: %w", err)
	}
	return ".staging-" + hex.EncodeToString(rnd[:]), nil
}

// publish writes files into a staging directory under dir and renames it to name, so a reader sees all of
// them or none; it refuses an existing name and removes its staging on failure.
func publish(dir *os.Root, name string, files map[string][]byte, dirMode, fileMode os.FileMode) error {
	if _, err := dir.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s already exists", name)
	}
	staging, err := stagingName()
	if err != nil {
		return err
	}
	if err := dir.Mkdir(staging, dirMode); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	fail := func(err error) error {
		return errors.Join(err, dir.RemoveAll(staging))
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
	if err := dir.Rename(staging, name); err != nil {
		return fail(fmt.Errorf("publish %s: %w", name, err))
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable (ENGINEERING.md 7).
func syncDir(dir *os.Root) error {
	f, err := dir.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	return nil
}

// treeBytes is the bytes of every regular file under dir, depth levels of directories deep at most, each
// listed under maxEntries and never through a link (R5).
func treeBytes(dir *os.Root, depth int) (int64, error) {
	f, err := dir.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, fmt.Errorf("size: %w", err)
	}
	list, err := f.ReadDir(maxEntries + 1)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("size: %w", err)
	}
	if len(list) > maxEntries {
		return 0, fmt.Errorf("size: over %d entries", maxEntries)
	}
	var total int64
	for _, e := range list {
		switch {
		case e.Type().IsRegular():
			fi, err := dir.Lstat(e.Name())
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
