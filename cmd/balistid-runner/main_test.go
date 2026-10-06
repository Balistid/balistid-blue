package main

import "testing"

// Paths come only from the unit, absolute and clean; a binary without a full commit id as its
// version refuses before it touches anything.
func TestRunRefusesBadInvocations(t *testing.T) {
	tick := []string{"tick", "--state", "/s", "--inbox", "/i", "--results", "/r"}
	cases := []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"run"}, 2},
		{[]string{"tick"}, 2},
		{[]string{"tick", "--state", "s", "--inbox", "/i", "--results", "/r"}, 2},
		{[]string{"tick", "--state", "/s/../s", "--inbox", "/i", "--results", "/r"}, 2},
		{[]string{"build", "--state", "/s"}, 2},
		{append(tick, "extra"), 2},
		{tick, 1},
		{[]string{"build", "--state", "/s", "--objects", "/o"}, 1},
	}
	for _, c := range cases {
		if got := run(t.Context(), c.args); got != c.code {
			t.Errorf("run(%q) = %d, want %d", c.args, got, c.code)
		}
	}
}
