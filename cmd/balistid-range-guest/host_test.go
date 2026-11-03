package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// The host shows exactly the lines hostLine writes: tools/ci/range_kvm.py's pattern is this marker and length.
func TestHostLineIsWhatTheHostShows(t *testing.T) {
	src, err := os.ReadFile("../../tools/ci/range_kvm.py")
	if err != nil {
		t.Fatal(err)
	}
	if want := `: (` + hostPrefix + `[ -~]{1,` + strconv.Itoa(hostLineMax) + `})")`; !strings.Contains(string(src), want) {
		t.Errorf("range_kvm.py does not show %s", want)
	}
	unit, err := os.ReadFile("../../range/balistid-range-guest.service")
	if err != nil {
		t.Fatal(err)
	}
	// journald forwards stdout to the console as "guest[<pid>]: ", the binary's name, which the script matches.
	for _, line := range []string{"ExecStart=/usr/lib/balistid-range/guest\n", "StandardOutput=journal+console\n"} {
		if !strings.Contains(string(unit), line) || strings.Contains(string(unit), "SyslogIdentifier=") {
			t.Errorf("the guest's unit does not have %q, or names another identifier", line)
		}
	}
}
