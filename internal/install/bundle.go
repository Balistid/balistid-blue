package install

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const (
	// MaxBundleBytes caps the bundle as the root command CI prints does (release.py BUNDLE_MAX_MIB).
	MaxBundleBytes = 64 << 20
	manifestName   = "MANIFEST"
)

// entryName is the manifest's name grammar, or MANIFEST itself: no directory, no "..", nothing to resolve.
var entryName = regexp.MustCompile(`^(?:[a-z0-9][a-z0-9._-]{0,63}|MANIFEST)$`)

// ReadBundle reads the bundle tar from memory into its files by name. Only regular files of plain names, each
// once, MaxBundleBytes in all (a sparse entry cannot expand past it); a link, a directory, a device or a path is
// refused whole, so nothing in it is ever resolved on disk. archive/tar refuses a negative size and a cut entry.
func ReadBundle(b []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	total := int64(0)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		switch _, dup := files[hdr.Name]; {
		case hdr.Typeflag != tar.TypeReg || hdr.Linkname != "":
			return nil, errors.New("bundle: an entry that is not a regular file")
		case !entryName.MatchString(hdr.Name):
			return nil, errors.New("bundle: an entry name outside the manifest's grammar")
		case dup:
			return nil, errors.New("bundle: an entry name twice")
		case hdr.Size > MaxBundleBytes-total:
			return nil, fmt.Errorf("bundle: over %d bytes", MaxBundleBytes)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		total += hdr.Size
		files[hdr.Name] = data
	}
	if _, ok := files[manifestName]; !ok {
		return nil, errors.New("bundle: no MANIFEST")
	}
	return files, nil
}
