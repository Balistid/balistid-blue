// Package wholefile writes files that Balistid Blue writes whole, as ENGINEERING.md 7 asks.
package wholefile

import (
	"errors"
	"fmt"
	"io"
	"os"
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

// Write writes data to path: a temp file of mode perm in the same directory, fsynced, renamed over
// path, then the directory fsynced. A crash leaves either the old file or the new one. The rename
// replaces a symlink at path rather than following it.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, werr := tmp.Write(data)
	if err := errors.Join(werr, tmp.Chmod(perm), tmp.Sync(), tmp.Close()); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), os.Remove(tmp.Name()))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), os.Remove(tmp.Name()))
	}
	d, err := os.Open(dir) //nolint:gosec // our own directory
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
