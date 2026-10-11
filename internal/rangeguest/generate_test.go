package rangeguest

import (
	"errors"
	"testing"
	"testing/fstest"
	"time"
)

// fakeClock advances only by Sleep, which overshoots by late, and by what each emit costs.
type fakeClock struct {
	now  time.Time
	late time.Duration
}

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.now = c.now.Add(d + c.late) }

func emitter(c *fakeClock, cost time.Duration, got *[]uint64) func(uint64) error {
	return func(seq uint64) error {
		*got = append(*got, seq)
		c.now = c.now.Add(cost)
		return nil
	}
}

func TestGenerateHoldsTheRate(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	var got []uint64
	generated, windowMin, err := Generate(100, 20, emitter(c, time.Millisecond, &got), c)
	if err != nil || generated != 2000 || windowMin != 1000 {
		t.Fatalf("Generate = %d, %d, %v; want 2000 with 1000 in every window", generated, windowMin, err)
	}
	for i, seq := range got {
		if seq != uint64(i)+1 {
			t.Fatalf("number %d is %d: numbers must run 1, 2, ...", i, seq)
		}
	}
}

// A sleep that overruns a little puts the last numbers of a window just past its end; they still
// count where they were due, so scheduler jitter is no lost rate.
func TestGenerateToleratesSleepJitter(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0), late: 3 * time.Millisecond}
	var got []uint64
	generated, windowMin, err := Generate(10000, 10, emitter(c, 0, &got), c)
	if err != nil || generated != 100000 || windowMin != 100000 {
		t.Errorf("jittered sleep: %d generated, %d in the slowest window, %v; want all 100000", generated, windowMin, err)
	}
}

// An emitter slower than the rate falls behind: it stops grace after the schedule's end, so the
// run has fewer numbers than planned, and a number later than grace counts where it was emitted.
func TestGenerateReportsARateNotHeld(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	var got []uint64
	generated, windowMin, err := Generate(100, 10, emitter(c, 20*time.Millisecond, &got), c)
	if err != nil || generated != 505 || windowMin != 505 {
		t.Errorf("slow emitter: %d generated, %d in the slowest window, %v; want 505 and 505", generated, windowMin, err)
	}
	c = &fakeClock{now: time.Unix(0, 0)}
	n := 0
	generated, windowMin, _ = Generate(100, 20, func(uint64) error {
		if n++; n == 500 {
			c.now = c.now.Add(10 * time.Second) // a stall past the first window's end
		}
		return nil
	}, c)
	if generated != 2000 || windowMin != 500 {
		t.Errorf("stall: %d generated, %d in the slowest window; want 2000 and 500", generated, windowMin)
	}
}

func TestGenerateStopsAtAFailedEvent(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	n := 0
	_, _, err := Generate(10, 10, func(uint64) error {
		if n++; n == 5 {
			return errors.New("boom")
		}
		return nil
	}, c)
	if err == nil {
		t.Error("a failed event went unreported")
	}
	for _, load := range [][2]int{{1, 0}, {1, 5}, {1, 15}, {0, 10}, {-1, 10}} {
		if _, _, err := Generate(load[0], load[1], func(uint64) error { return nil }, c); err == nil {
			t.Errorf("Generate accepted %d/s for %d s", load[0], load[1])
		}
	}
}

func TestCPUTicks(t *testing.T) {
	total, steal, err := CPUTicks("cpu  10 1 5 100 2 0 1 3 7 0\ncpu0 1 2 3 4 5 6 7 8 9 0\n")
	if err != nil || total != 122 || steal != 3 {
		t.Errorf("CPUTicks = %d, %d, %v; want 122 and 3", total, steal, err)
	}
	for _, bad := range []string{"", "cpu0 1 2 3 4 5 6 7 8\n", "cpu 1 2 3 4 5 6 7\n", "cpu 1 2 3 4 5 6 7 x\n"} {
		if _, _, err := CPUTicks(bad); err == nil {
			t.Errorf("CPUTicks(%q) accepted", bad)
		}
	}
}

func TestTrialCredentials(t *testing.T) {
	both := fstest.MapFS{"balistid.trial": {Data: []byte("rate-burst")}, "balistid.phase": {Data: []byte("1")}}
	if name, phase, err := TrialCredentials(both); err != nil || name != "rate-burst" || phase != "1" {
		t.Errorf("both: %q, %q, %v", name, phase, err)
	}
	if name, _, err := TrialCredentials(nil); err != nil || name != "" {
		t.Errorf("no credentials directory: %q, %v", name, err)
	}
	for _, none := range []fstest.MapFS{{}, {"other": {Data: []byte("x")}}} {
		if name, _, err := TrialCredentials(none); err != nil || name != "" {
			t.Errorf("%v: %q, %v", none, name, err)
		}
	}
	for _, half := range []fstest.MapFS{
		{"balistid.trial": {Data: []byte("rate-burst")}},
		{"balistid.phase": {Data: []byte("1")}},
	} {
		if _, _, err := TrialCredentials(half); err == nil {
			t.Errorf("%v: one credential without the other accepted", half)
		}
	}
}
