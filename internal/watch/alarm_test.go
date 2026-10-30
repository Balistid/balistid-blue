package watch

import (
	"testing"
	"time"
)

var (
	grow      = Findings{Entries: 3}
	announced = Findings{Entries: 1, Announced: 1}
)

func silent(w *Watchdog, at time.Time, behind bool) bool {
	_, ok := w.Conditions(at, behind)[KeySilence]
	return ok
}

func TestSilenceAlarm(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Grew(t0, grow, Rules{})
	if silent(w, t0.Add(899*time.Second), false) {
		t.Fatal("silence alarmed at 899 s")
	}
	if !silent(w, t0.Add(900*time.Second), false) {
		t.Fatal("no silence alarm at 900 s")
	}
	w.Grew(t0.Add(901*time.Second), grow, Rules{})
	if silent(w, t0.Add(902*time.Second), false) {
		t.Fatal("growth did not end the silence")
	}
}

// Bundles the relay withholds leave the Pi behind the witness: nothing verified, so the silence alarm runs.
func TestSilenceWhenBundlesWithheld(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	if !silent(w, t0.Add(900*time.Second), true) {
		t.Fatal("withheld bundles did not alarm")
	}
}

func TestQuietHoldsAfterLateEntries(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Grew(t0, announced, Rules{})
	w.Grew(t0.Add(3*time.Second), grow, Rules{}) // the collector's last batch and health after the announcement
	if silent(w, t0.Add(10*time.Hour), false) {
		t.Fatal("announced quiet alarmed")
	}
}

func TestQuietCapDoesNotRestart(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Grew(t0, announced, Rules{})
	back := t0.Add(20 * time.Hour)
	for i := range 10 { // back for ten minutes, then announces again
		w.Grew(back.Add(time.Duration(i)*time.Minute), grow, Rules{})
	}
	w.Grew(back.Add(10*time.Minute), announced, Rules{})
	if silent(w, t0.Add(24*time.Hour-time.Second), false) {
		t.Fatal("alarmed before the cap")
	}
	if !silent(w, t0.Add(24*time.Hour), false) {
		t.Fatal("the second announcement restarted the cap")
	}
}

func TestQuietEndsWhenWitnessGrowsUnseen(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Grew(t0, announced, Rules{})
	if !silent(w, t0.Add(900*time.Second), true) {
		t.Fatal("the witness grew past the Pi and the quiet still held")
	}
}

func TestQuietClosesAfterAnHourOfGrowth(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Grew(t0, announced, Rules{})
	for i := 1; i <= 61; i++ {
		w.Grew(t0.Add(time.Duration(i)*time.Minute), grow, Rules{})
	}
	if w.Quiet(t0.Add(61*time.Minute)) != nil {
		t.Fatal("an hour of growth did not close the episode")
	}
	if !silent(w, t0.Add(61*time.Minute+900*time.Second), false) {
		t.Fatal("silence after a closed episode did not alarm")
	}
}

func TestQuietSurvivesPiRestart(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Grew(t0, announced, Rules{})
	age := w.Quiet(t0.Add(20 * time.Hour))
	t1 := t0.Add(30 * time.Hour) // the Pi was down for ten hours: they do not count
	r := NewWatchdog(DefaultLimits, t1, age)
	if silent(r, t1.Add(4*time.Hour-time.Second), false) {
		t.Fatal("alarmed before the restored cap")
	}
	if !silent(r, t1.Add(4*time.Hour), false) {
		t.Fatal("the restart restarted the cap")
	}
}

func TestVerifyFreshness(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil)
	w.Caught(t0.Add(time.Minute))
	if _, ok := w.Conditions(t0.Add(time.Minute+3599*time.Second), false)[KeyFresh]; ok {
		t.Fatal("fresh verification alarmed")
	}
	if _, ok := w.Conditions(t0.Add(time.Minute+3600*time.Second), false)[KeyFresh]; !ok {
		t.Fatal("no freshness alarm after 3600 s")
	}
}

func TestTruncationAlarm11vs10(t *testing.T) {
	t0 := time.Now()
	for _, c := range []struct{ n, alarms int }{{10, 0}, {11, 1}} {
		w := NewWatchdog(DefaultLimits, t0, nil)
		for i := range c.n {
			w.Grew(t0.Add(time.Duration(i)*5*time.Minute), Findings{Entries: 2, Truncated: 1}, Rules{})
		}
		_, ok := w.Conditions(t0.Add(55*time.Minute), false)[KeyTruncated]
		if ok != (c.alarms == 1) {
			t.Errorf("%d truncated within an hour: alarm %v", c.n, ok)
		}
		if _, ok := w.Conditions(t0.Add(2*time.Hour), false)[KeyTruncated]; ok {
			t.Errorf("%d truncated: still alarming after the hour", c.n)
		}
	}
}
