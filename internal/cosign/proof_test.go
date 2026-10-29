package cosign

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO planted where a tile or checkpoint should be is refused at once, not waited on for a writer.
func TestReadFileRefusesAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(nil, path, MaxNote)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read a FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}
