package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/transparency-dev/tessera/api/layout"
)

// Only full bundles count, each with its level-0 tile; a full bundle missing a file measures nothing.
func TestFullBundleBytes(t *testing.T) {
	dir := t.TempDir()
	put := func(p string, n int) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(layout.EntriesPath(0, 0), 30000)
	put(layout.TilePath(0, 0, 0), 8192)
	put(layout.EntriesPath(1, 44), 5000) // the right edge's partial bundle
	if b, n, err := fullBundleBytes(dir, 255); b != 0 || n != 0 || err != nil {
		t.Errorf("no full bundle yet: %d, %d", b, n)
	}
	b, n, err := fullBundleBytes(dir, 300)
	if err != nil {
		t.Fatal(err)
	}
	if b != 1 || n < 30000+8192 || n > 30000+8192+2*64<<10 {
		t.Errorf("one full bundle: %d bundles, %d bytes", b, n)
	}
	// partial copies Tessera's GC has not removed yet count against the full bundle
	put(layout.EntriesPath(0, 0)+".p/200", 20000)
	if _, n2, err := fullBundleBytes(dir, 300); err != nil || n2 < n+20000 {
		t.Errorf("a leftover partial of a full bundle: %d bytes, was %d", n2, n)
	}
	if b, n, err := fullBundleBytes(dir, 600); b != 0 || n != 0 || err != nil {
		t.Errorf("a full bundle without its files: %d, %d", b, n)
	}
	// a partials directory that cannot be read is an error, not fewer bytes
	if err := os.Chmod(filepath.Join(dir, layout.EntriesPath(0, 0)+".p"), 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(dir, layout.EntriesPath(0, 0)+".p"), 0o700) //nolint:errcheck,gosec // the test's own directory, back to traversable
	if os.Getuid() != 0 {
		if _, _, err := fullBundleBytes(dir, 300); err == nil {
			t.Error("an unreadable partials directory measured")
		}
	}
}
