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
	"strconv"
)

// MaxManifestBytes caps MANIFEST; a component lists a few dozen files.
const MaxManifestBytes = 64 << 10

// Manifest is MANIFEST v1 or v2 (ADR 0058, point 1; ADR 0076): what CI built, for which component and commit, and
// in v2 the release number the installer keeps so that no older release installs over it.
type Manifest struct {
	Component string
	Commit    string
	Release   uint64 // 0 in v1
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
	releaseLine   = regexp.MustCompile(`^release ([1-9][0-9]{0,9})$`)
	fileLine      = regexp.MustCompile(`^([0-9a-f]{64})  ([a-z0-9][a-z0-9._-]{0,63})$`)
)

// ParseManifest reads MANIFEST v1 or v2 strictly: the header lines (v2 adds the release after the commit), then at
// least one file line, names in increasing order, every line ending in a newline. Anything else, another version
// included, is refused whole; the error names a line number, never its content.
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) > MaxManifestBytes || !bytes.HasSuffix(b, []byte("\n")) {
		return Manifest{}, errors.New("manifest: not a capped text ending in a newline")
	}
	lines := bytes.Split(b[:len(b)-1], []byte("\n"))
	header := 3
	switch string(lines[0]) {
	case "balistid-manifest 1":
	case "balistid-manifest 2":
		header = 4
	default:
		return Manifest{}, errors.New("manifest: not version 1 or 2")
	}
	if len(lines) <= header {
		return Manifest{}, errors.New("manifest: needs its header lines and a file")
	}
	component := componentLine.FindSubmatch(lines[1])
	commit := commitLine.FindSubmatch(lines[2])
	if component == nil || commit == nil {
		return Manifest{}, errors.New("manifest: header lines 2 and 3 must name the component and the commit")
	}
	m := Manifest{Component: string(component[1]), Commit: string(commit[1])}
	if header == 4 {
		release := releaseLine.FindSubmatch(lines[3])
		if release == nil {
			return Manifest{}, errors.New("manifest: header line 4 must give the release")
		}
		n, err := strconv.ParseUint(string(release[1]), 10, 64)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest: line 4: %w", err)
		}
		m.Release = n
	}
	for i, line := range lines[header:] {
		f := fileLine.FindSubmatch(line)
		if f == nil {
			return Manifest{}, fmt.Errorf("manifest: line %d is not '<sha256>  <name>'", i+header+1)
		}
		file := File{Name: string(f[2])}
		if _, err := hex.Decode(file.SHA256[:], f[1]); err != nil {
			return Manifest{}, fmt.Errorf("manifest: line %d: %w", i+header+1, err)
		}
		if n := len(m.Files); n > 0 && m.Files[n-1].Name >= file.Name {
			return Manifest{}, fmt.Errorf("manifest: line %d is out of order or repeats a name", i+header+1)
		}
		m.Files = append(m.Files, file)
	}
	return m, nil
}
