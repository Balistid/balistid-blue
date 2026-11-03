package main

import (
	"testing"
)

// Anything but the two subcommands with their arguments is a usage error, and runner refuses without root before
// it reads anything; no case here reaches the host.
func TestRunRefusesUsageAndAnUnprivilegedRunner(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		args []string
		want int
	}{
		"nothing":             {nil, 2},
		"another command":     {[]string{"install", dir}, 2},
		"verify without dir":  {[]string{"verify"}, 2},
		"verify, extra words": {[]string{"verify", dir, "SHA256:x", "more"}, 2},
		"runner without user": {[]string{"runner", dir}, 2},
		"runner, extra words": {[]string{"runner", dir, "maint", "SHA256:x", "more"}, 2},
		"runner not as root":  {[]string{"runner", dir, "maint"}, 1},
		"verify an empty dir": {[]string{"verify", dir}, 1},
	} {
		if got := run(t.Context(), c.args, 1000); got != c.want {
			t.Errorf("%s: exit %d, want %d", name, got, c.want)
		}
	}
}
