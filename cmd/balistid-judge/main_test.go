package main

import (
	"os"
	"testing"
)

// The stub gives no verdict: one UNKNOWN line on stderr and a non-zero status, never a pass.
func TestRunIsUnknown(t *testing.T) {
	oldStderr := os.Stderr
	t.Cleanup(func() { os.Stderr = oldStderr })
	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = stderr
	got := run()
	os.Stderr = oldStderr
	if got != 2 {
		t.Errorf("exit %d, want 2", got)
	}
	out, err := os.ReadFile(stderr.Name())
	if want := "balistid-judge: UNKNOWN not built yet (ADR 0074)\n"; err != nil || string(out) != want {
		t.Errorf("stderr %q, want %q (%v)", out, want, err)
	}
}
