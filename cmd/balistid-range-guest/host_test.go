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
	if want := `re.compile(r"` + hostPrefix + `[ -~]{1,` + strconv.Itoa(hostLineMax) + `}")`; !strings.Contains(string(src), want) {
		t.Errorf("range_kvm.py does not show %s", want)
	}
}
