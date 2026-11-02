package main

import "testing"

// Anything but the two commands is a usage error, never a status.
func TestUsageIsExitTwo(t *testing.T) {
	for _, args := range [][]string{nil, {"status", "--yaml"}, {"status", "--json", "x"}, {"--json", "status"}, {"Status"}} {
		if got := run(args); got != 2 {
			t.Errorf("%q: exit %d", args, got)
		}
	}
}
