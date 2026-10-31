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
	if b, n := fullBundleBytes(dir, 255); b != 0 || n != 0 {
		t.Errorf("no full bundle yet: %d, %d", b, n)
	}
	b, n := fullBundleBytes(dir, 300)
	if b != 1 || n < 30000+8192 || n > 30000+8192+2*64<<10 {
		t.Errorf("one full bundle: %d bundles, %d bytes", b, n)
	}
	if b, n := fullBundleBytes(dir, 600); b != 0 || n != 0 {
		t.Errorf("a full bundle without its files: %d, %d", b, n)
	}
}
