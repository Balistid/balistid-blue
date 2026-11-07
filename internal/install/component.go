package install

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// component is what balistid-install knows of one component (ADR 0058, 0068): its files and where they go, which
// directories it trusts or creates and which units it owns. Paths are relative to the root.
type component struct {
	name string
	// table is in the order it is written; the installer goes last, so a stop leaves the one that ran in place.
	table []target
	// units are its own: stopped before the install, each loaded from unitDir and without drop-ins after the reload.
	units []string
	// trusted exist on every host; they and every directory above them are only checked, never changed.
	trusted []string
	// created are absent or exactly root:root 0755; the install creates the absent ones.
	created []string
	// tmpfiles are the table names of its tmpfiles.conf files, read in this order: a parent is listed before its children.
	tmpfiles []string
	// late are table names written only after the units are enabled: a stop before them leaves the next boot as it was.
	late []string
}

// components are the ones balistid-install installs, by the name a MANIFEST gives.
var components = map[string]component{runnerComponent.name: runnerComponent, recorderComponent.name: recorderComponent}

// bundle is the file name of the component's signed bundle.
func (c component) bundle() string { return "balistid-" + c.name + "-bundle.tar" }

// released checks the bundle in dir is a signed release of exactly this component: its MANIFEST names it and lists
// exactly the table's files.
func (c component) released(ctx context.Context, cfg Config, host *os.Root, dir, fingerprint string, d *Decision) (Release, error) {
	r, err := check(ctx, cfg, host, c.bundle(), dir, fingerprint)
	if err != nil {
		return Release{}, err
	}
	d.Commit, d.ManifestSHA256, d.Signer = r.Manifest.Commit, hex.EncodeToString(r.ManifestSHA256[:]), r.Signer.Fingerprint()
	if r.Manifest.Component != c.name {
		return Release{}, fmt.Errorf("the manifest is not of the %s component", c.name)
	}
	names := make([]string, len(c.table))
	for i, f := range c.table {
		names[i] = f.name
	}
	if !slices.Equal(slices.Sorted(slices.Values(names)), slices.Sorted(maps.Keys(r.Files))) {
		return Release{}, fmt.Errorf("the manifest's files are not the %s's", c.name)
	}
	return r, nil
}

// writeFiles writes the files of the table but the installer that are late or not, skipping an installed
// allowed_signers that check found equal to the bundle's.
func (c component) writeFiles(host *os.Root, r Release, absent map[string]bool, late bool) error {
	for _, f := range c.table[:len(c.table)-1] {
		if f.name == signersName && !absent[f.dest] || slices.Contains(c.late, f.name) != late {
			continue
		}
		if err := wholefile.WriteIn(host, f.dest, r.Files[f.name], f.mode); err != nil {
			return fmt.Errorf("step write /%s: %w", f.dest, err)
		}
	}
	return nil
}

// writeInstaller writes the installer, the table's last file.
func (c component) writeInstaller(host *os.Root, r Release) error {
	last := c.table[len(c.table)-1]
	if err := wholefile.WriteIn(host, last.dest, r.Files[last.name], last.mode); err != nil {
		return fmt.Errorf("step write /%s: %w", last.dest, err)
	}
	return nil
}

// createDirs creates the component's absent directories, root:root 0755.
func (c component) createDirs(host *os.Root, absent map[string]bool) error {
	for _, dir := range c.created {
		if !absent[dir] {
			continue
		}
		if err := errors.Join(host.Mkdir(dir, 0o755), host.Chmod(dir, 0o755)); err != nil {
			return fmt.Errorf("step create /%s: %w", dir, err)
		}
	}
	return nil
}
