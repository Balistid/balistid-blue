package main

import "testing"

// The unit starts the judge without arguments; anything else is a usage error, never a read of another store.
func TestRunRefusesArguments(t *testing.T) {
	for _, args := range [][]string{{"x"}, {"--store", "/tmp"}} {
		if got := run(t.Context(), args); got != 1 {
			t.Errorf("run(%q) = %d, want 1", args, got)
		}
	}
}
