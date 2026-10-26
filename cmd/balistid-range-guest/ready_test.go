package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseUptime(t *testing.T) {
	if d, err := parseUptime("31.57 60.10"); err != nil || d != 31570*time.Millisecond {
		t.Errorf("31.57: %v, %v", d, err)
	}
	for _, s := range []string{"", "x 1", "-1 2", "error: open /proc/uptime"} {
		if _, err := parseUptime(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

// Ready is the whole ms from kernel start to the first health OK, "none" without one, and a reason,
// never a number, when the record says it came before the kernel started.
func TestReadyMS(t *testing.T) {
	boot := int64(1_000_000_000_000)
	for _, c := range []struct {
		ready int64
		want  string
	}{
		{0, "none"},
		{boot + 12_345_678_901, "12345"},
		{boot, "0"},
		{boot - 1, "before kernel start"},
	} {
		if got := readyMS(boot, c.ready); got != c.want {
			t.Errorf("ready %d: %q, want %q", c.ready, got, c.want)
		}
	}
}

// The exposure is the value of the collector's one overall line; none, or two, is an error.
func TestExposureOf(t *testing.T) {
	out := "  NAME  DESCRIPTION  EXPOSURE\n✗ PrivateTmp= ...\n\n→ Overall exposure level for balistid-collector.service: 0.8 SAFE 😀\n"
	if v, err := exposureOf([]byte(out)); err != nil || v != "0.8" {
		t.Errorf("%q, %v", v, err)
	}
	for _, bad := range []string{
		"→ Overall exposure level for laurel.service: 0.8 SAFE\n",
		strings.Repeat("→ Overall exposure level for balistid-collector.service: 0.8 SAFE\n", 2),
		"",
	} {
		if v, err := exposureOf([]byte(bad)); err == nil {
			t.Errorf("%q gave %q", bad, v)
		}
	}
}

func TestUsageUsec(t *testing.T) {
	if n, err := usageUsec("usage_usec 1234\nuser_usec 1000\nsystem_usec 234"); err != nil || n != 1234 {
		t.Errorf("%d, %v", n, err)
	}
	for _, s := range []string{"user_usec 1", "usage_usec x", "error: open cpu.stat"} {
		if _, err := usageUsec(s); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

// CPU counts only between samples of one invocation that both read; anything else says why.
func TestUsedAndUnitsState(t *testing.T) {
	a := unitSample{usec: 100, invocation: "i1", memPeak: "4096"}
	if n, why := used(a, unitSample{usec: 150, invocation: "i1"}); n != 50 || why != "" {
		t.Errorf("%d %q", n, why)
	}
	for want, after := range map[string]unitSample{
		"restarted":         {usec: 150, invocation: "i2"},
		"counter went back": {usec: 50, invocation: "i1"},
		"gone":              {err: errors.New("gone")},
	} {
		if _, why := used(a, after); why != want {
			t.Errorf("%q, want %q", why, want)
		}
	}
	if cpu, mem := collectorMeasures(a, unitSample{usec: 150, invocation: "i1", memPeak: "8192"}); cpu != "50" || mem != "8192" {
		t.Errorf("measures %q %q", cpu, mem)
	}
	if cpu, mem := collectorMeasures(a, unitSample{usec: 150, invocation: "i2"}); cpu != "restarted" || mem != "restarted" {
		t.Errorf("measures of a restart %q %q", cpu, mem)
	}
	if s := unitsState("", ""); s != "same" {
		t.Errorf("%q", s)
	}
	if s := unitsState("", "restarted"); s != "auditd: restarted" {
		t.Errorf("%q", s)
	}
}

// The load has drained once commit lines stop for a second; without any, or with the follower gone, it
// cannot be told.
func TestDrained(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	w := &commitWatch{seq: 5, at: now.Add(-cpuDrainQuiet), done: make(chan struct{})}
	if err := drained(w, clock); err != nil {
		t.Errorf("quiet for a second: %v", err)
	}
	if err := drained(&commitWatch{done: make(chan struct{})}, clock); err == nil || !strings.Contains(err.Error(), "no commit line") {
		t.Errorf("no commit line: %v", err)
	}
	ended := &commitWatch{seq: 5, at: now, done: make(chan struct{})}
	close(ended.done)
	if err := drained(ended, clock); err == nil || !strings.Contains(err.Error(), "follower ended") {
		t.Errorf("follower ended: %v", err)
	}
	tick := now
	busy := &commitWatch{seq: 5, at: now.Add(time.Hour), done: make(chan struct{})} // never a quiet second
	moving := func() time.Time {
		tick = tick.Add(10 * time.Second)
		return tick
	}
	if err := drained(busy, moving); err == nil || !strings.Contains(err.Error(), "still committed") {
		t.Errorf("never quiet: %v", err)
	}
}
