package main

import (
	"testing"
)

// Anything but the four subcommands with their arguments is a usage error, and recorder, judge and runner refuse without
// root before they read anything; no case here reaches the host.
func TestRunRefusesUsageAndAnUnprivilegedRunner(t *testing.T) {
	dir := t.TempDir()
	for name, c := range map[string]struct {
		args []string
		want int
	}{
		"nothing":               {nil, 2},
		"another command":       {[]string{"install", dir}, 2},
		"verify without dir":    {[]string{"verify", "runner"}, 2},
		"verify, extra words":   {[]string{"verify", "runner", dir, "SHA256:x", "more"}, 2},
		"runner without user":   {[]string{"runner", dir}, 2},
		"runner, extra words":   {[]string{"runner", dir, "maint", "SHA256:x", "more"}, 2},
		"runner not as root":    {[]string{"runner", dir, "maint"}, 1},
		"verify an empty dir":   {[]string{"verify", "runner", dir}, 1},
		"verify, no component":  {[]string{"verify", "witness", dir}, 1},
		"recorder without dir":  {[]string{"recorder"}, 2},
		"recorder, extra words": {[]string{"recorder", dir, "SHA256:x", "more"}, 2},
		"recorder not as root":  {[]string{"recorder", dir}, 1},
		"judge without dir":     {[]string{"judge"}, 2},
		"judge, extra words":    {[]string{"judge", dir, "SHA256:x", "more"}, 2},
		"judge not as root":     {[]string{"judge", dir}, 1},
	} {
		if got := run(t.Context(), c.args, 1000); got != c.want {
			t.Errorf("%s: exit %d, want %d", name, got, c.want)
		}
	}
}
