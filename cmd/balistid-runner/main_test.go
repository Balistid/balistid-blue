package main

import (
	"bytes"
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

// A binary whose version is not a full commit id is refused before the runner; one that is reaches
// the runner, whose tick outside its unit refuses too. Neither touches its state.
func TestRunRefusesADevelopmentBuildFirst(t *testing.T) {
	old, oldStderr := buildinfo.Version, os.Stderr
	t.Cleanup(func() { buildinfo.Version, os.Stderr = old, oldStderr })
	for _, c := range []struct {
		version, logged string
	}{{"dev", "msg=refused"}, {"0123456789abcdef0123456789abcdef01234567", "confinement missing"}} {
		buildinfo.Version = c.version
		state := t.TempDir()
		if err := os.Chmod(state, 0o700); err != nil { //nolint:gosec // a directory needs its x bit
			t.Fatal(err)
		}
		stderr, err := os.CreateTemp(t.TempDir(), "stderr")
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = stderr
		got := run(t.Context(), []string{"tick", "--state", state, "--inbox", "/i", "--results", "/r"})
		os.Stderr = oldStderr
		if got != 1 {
			t.Fatalf("version %q: exit %d", c.version, got)
		}
		if _, err := os.Stat(filepath.Join(state, "cache")); err == nil {
			t.Errorf("version %q: state touched", c.version)
		}
		if out, err := os.ReadFile(stderr.Name()); err != nil || !bytes.Contains(out, []byte(c.logged)) {
			t.Errorf("version %q: log %q, want %q (%v)", c.version, out, c.logged, err)
		}
	}
}
