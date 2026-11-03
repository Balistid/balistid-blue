package install

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Once a uid holds more than pipe-user-pages-soft (16384 pages by default), its new pipes get two pages. An agent
// at the maintainer's uid can spend that budget; the unprivileged verify must still return within its timeout, here
// with an ssh-keygen that never reads, rather than block writing a signature of the full cap.
func TestCheckReturnsWhenThePipeBudgetIsSpent(t *testing.T) {
	var held []*os.File
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()
	for range 1100 {
		r, w, err := os.Pipe()
		must(t, err)
		held = append(held, r, w)
	}
	stand := filepath.Join(t.TempDir(), "ssh-keygen")
	must(t, os.WriteFile(stand, []byte("#!/bin/sh\nexec sleep 60\n"), 0o700)) //nolint:gosec // a stand-in program
	h := newHost(t)
	h.release(t)
	must(t, os.WriteFile(filepath.Join(h.dir, sigName), bytes.Repeat([]byte("A"), maxSigBytes), 0o600))
	h.cfg.SSHKeygen, h.cfg.VerifyTimeout = stand, 200*time.Millisecond
	start := time.Now()
	h.refuses(t, "a spent pipe budget", "", "the signature does not verify")
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("Check took %v", d)
	}
}
