package collector

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// A probe goes out a second inside acceptance canary_interval_s, so the gap the range measures holds with the
// writer's ticks and the audit clock's coarseness, and the margin lives in the code, not in the judge
// (maintainer, 2026-11-03).
func TestCanaryEveryIsASecondInsideTheInterval(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^id = "canary_interval_s"\nmax = (\d+)\n`).FindSubmatch(data)
	if m == nil {
		t.Fatal("no canary_interval_s in acceptance/0.toml")
	}
	limit, err := strconv.Atoi(string(m[1]))
	if err != nil || CanaryEvery != time.Duration(limit)*time.Second-time.Second {
		t.Errorf("CanaryEvery %s, canary_interval_s %q s", CanaryEvery, m[1])
	}
}
