// Package wholefile writes files that Balistid Blue writes whole, as ENGINEERING.md 7 asks, and reads the
// files others leave for it without following links or blocking.
package wholefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"
)

// ReadOwned reads a file another service writes whole for this one: a regular file of uid, exactly size
// bytes, opened without following a symlink or blocking on a FIFO. Its writer replaces it by rename, so a
// read never sees half of one.
func ReadOwned(path string, uid, size int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the caller names the writer's file
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("read %s: not a regular file", path)
	case !ok || int64(st.Uid) != int64(uid):
		return nil, fmt.Errorf("read %s: not its writer's file", path)
	case fi.Size() != int64(size):
		return nil, fmt.Errorf("read %s: %d bytes, not %d", path, fi.Size(), size)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return b, nil
}

// ReadIn reads at most limit bytes of the regular file name in dir, a directory someone else can write. It is
// checked with Lstat before the open (a regular file with one link, within the cap), so a symlink, hard link or
// FIFO is refused unopened; the open refuses links and must find the same file. The error names neither the
// file nor its content: the caller labels it.
func ReadIn(dir *os.Root, name string, limit int64) ([]byte, error) {
	before, err := dir.Lstat(name)
	if err != nil {
		return nil, errors.New("missing")
	}
	if err := plainFile(before, limit); err != nil {
		return nil, err
	}
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open")
	}
	defer f.Close() //nolint:errcheck // read-only
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("changed while it was opened")
	}
	if err := plainFile(after, limit); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, errors.New("cannot read")
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("over %d bytes", limit)
	}
	return data, nil
}

func plainFile(fi fs.FileInfo, limit int64) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return errors.New("not a regular file")
	case !ok || st.Nlink != 1:
		return errors.New("must have exactly one link")
	case fi.Size() > limit:
		return fmt.Errorf("over %d bytes", limit)
	}
	return nil
}

// Write writes data to path: a temp file of mode perm in the same directory, fsynced, renamed over
// path, then the directory fsynced. A crash leaves either the old file or the new one. The rename
// replaces a symlink at path rather than following it.
func Write(path string, data []byte, perm os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer root.Close() //nolint:errcheck // nothing written through the handle itself
	return WriteIn(root, filepath.Base(path), data, perm)
}

// WriteIn is Write for name inside root: the temp file gets a random name, is created exclusively without
// following a link and only then gets mode perm, so no other name or mode is ever written.
func WriteIn(root *os.Root, name string, data []byte, perm os.FileMode) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	dir := path.Dir(name)
	tmp := path.Join(dir, ".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Chmod(perm), f.Sync(), f.Close()); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", name, err), root.Remove(tmp))
	}
	if err := root.Rename(tmp, name); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", name, err), root.Remove(tmp))
	}
	d, err := root.Open(dir)
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
