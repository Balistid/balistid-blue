// Package install is balistid-install: it installs a component from a bundle only after the maintainer's
// signature over its MANIFEST verifies, each file matches its sha256 and every check of the host passes
// (ADR 0053, 0058).
package install

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// MaxManifestBytes caps MANIFEST; a component lists a few dozen files.
const MaxManifestBytes = 64 << 10

// Manifest is MANIFEST v1 (ADR 0058, point 1): what CI built, for which component and commit.
type Manifest struct {
	Component string
	Commit    string
	Files     []File // sorted by name, each name once
}

// File is one line of a manifest: a name the component's table knows and the sha256 of its bytes.
type File struct {
	Name   string
	SHA256 [32]byte
}

var (
	componentLine = regexp.MustCompile(`^component ([a-z][a-z0-9-]{0,31})$`)
	commitLine    = regexp.MustCompile(`^commit ([0-9a-f]{40})$`)
	fileLine      = regexp.MustCompile(`^([0-9a-f]{64})  ([a-z0-9][a-z0-9._-]{0,63})$`)
)

// ParseManifest reads MANIFEST v1 strictly: the three header lines, then at least one file line, names in
// increasing order, every line ending in a newline. Anything else, another version included, is refused
// whole; the error names a line number, never its content.
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) > MaxManifestBytes || !bytes.HasSuffix(b, []byte("\n")) {
		return Manifest{}, errors.New("manifest: not a capped text ending in a newline")
	}
	lines := bytes.Split(b[:len(b)-1], []byte("\n"))
	if len(lines) < 4 {
		return Manifest{}, errors.New("manifest: needs three header lines and a file")
	}
	if string(lines[0]) != "balistid-manifest 1" {
		return Manifest{}, errors.New("manifest: not version 1")
	}
	component := componentLine.FindSubmatch(lines[1])
	commit := commitLine.FindSubmatch(lines[2])
	if component == nil || commit == nil {
		return Manifest{}, errors.New("manifest: header lines 2 and 3 must name the component and the commit")
	}
	m := Manifest{Component: string(component[1]), Commit: string(commit[1])}
	for i, line := range lines[3:] {
		f := fileLine.FindSubmatch(line)
		if f == nil {
			return Manifest{}, fmt.Errorf("manifest: line %d is not '<sha256>  <name>'", i+4)
		}
		file := File{Name: string(f[2])}
		if _, err := hex.Decode(file.SHA256[:], f[1]); err != nil {
			return Manifest{}, fmt.Errorf("manifest: line %d: %w", i+4, err)
		}
		if n := len(m.Files); n > 0 && m.Files[n-1].Name >= file.Name {
			return Manifest{}, fmt.Errorf("manifest: line %d is out of order or repeats a name", i+4)
		}
		m.Files = append(m.Files, file)
	}
	return m, nil
}
