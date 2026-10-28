// Package wholefile writes files that Balistid Blue writes whole, as ENGINEERING.md 7 asks.
package wholefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
