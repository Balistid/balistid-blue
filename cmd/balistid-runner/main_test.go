package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
)

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
		{[]string{"tick", "--state", "/s", "--inbox", "/i", "--results", "/r", "--objects", "/o"}, 2},
		{[]string{"build", "--state", "/s", "--objects", "/o", "--inbox", "/i"}, 2},
	}
	for _, c := range cases {
		if got := run(t.Context(), c.args); got != c.code {
			t.Errorf("run(%q) = %d, want %d", c.args, got, c.code)
		}
	}
}

// A binary whose version is not a full commit id stops before it touches its state; one that is
// goes on to the runner.
func TestRunRefusesADevelopmentBuildFirst(t *testing.T) {
	old := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = old })
	for _, c := range []struct {
		version string
		touched bool
	}{{"dev", false}, {"0123456789abcdef0123456789abcdef01234567", true}} {
		buildinfo.Version = c.version
		state := t.TempDir()
		if err := os.Chmod(state, 0o700); err != nil { //nolint:gosec // a directory needs its x bit
			t.Fatal(err)
		}
		if got := run(t.Context(), []string{"tick", "--state", state, "--inbox", "/i", "--results", "/r"}); got != 1 {
			t.Fatalf("version %q: exit %d", c.version, got)
		}
		_, err := os.Stat(filepath.Join(state, "cache"))
		if touched := err == nil; touched != c.touched {
			t.Errorf("version %q: state touched %v, want %v", c.version, touched, c.touched)
		}
	}
}
