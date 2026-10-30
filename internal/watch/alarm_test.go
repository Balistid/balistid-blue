package watch

import (
	"runtime"
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
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, grow, Rules{})
	lim := DefaultLimits.Silence
	if lim > 900*time.Second-time.Minute {
		t.Fatalf("silence limit %v leaves no minute for the push within silence_alarm_s", lim)
	}
	if silent(w, t0.Add(lim-time.Second), false) {
		t.Fatal("silence alarmed before its limit")
	}
	if !silent(w, t0.Add(lim), false) {
		t.Fatal("no silence alarm at its limit")
	}
	w.Grew(t0.Add(lim+time.Second), grow, Rules{})
	if silent(w, t0.Add(lim+2*time.Second), false) {
		t.Fatal("growth did not end the silence")
	}
}

// Bundles the relay withholds leave the Pi behind the witness: nothing verified, so the silence alarm runs.
func TestSilenceWhenBundlesWithheld(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	if !silent(w, t0.Add(DefaultLimits.Silence), true) {
		t.Fatal("withheld bundles did not alarm")
	}
}

func TestQuietHoldsAfterLateEntries(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, announced, Rules{})
	w.Grew(t0.Add(3*time.Second), grow, Rules{}) // the collector's last batch and health after the announcement
	if silent(w, t0.Add(10*time.Hour), false) {
		t.Fatal("announced quiet alarmed")
	}
}

func TestQuietCapDoesNotRestart(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, announced, Rules{})
	back := t0.Add(20 * time.Hour)
	for i := range 10 { // back for ten minutes, then announces again
		w.Grew(back.Add(time.Duration(i)*time.Minute), grow, Rules{})
	}
	w.Grew(back.Add(10*time.Minute), announced, Rules{})
	if DefaultLimits.Quiet >= 24*time.Hour {
		t.Fatal("the quiet cap leaves no time for the push within announced_quiet_max_h")
	}
	if silent(w, t0.Add(DefaultLimits.Quiet-time.Second), false) {
		t.Fatal("alarmed before the cap")
	}
	if !silent(w, t0.Add(DefaultLimits.Quiet), false) {
		t.Fatal("the second announcement restarted the cap")
	}
}

func TestQuietEndsWhenWitnessGrowsUnseen(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, announced, Rules{})
	if !silent(w, t0.Add(DefaultLimits.Silence), true) {
		t.Fatal("the witness grew past the Pi, or was not read, and the quiet still held")
	}
}

func TestQuietClosesAfterAnHourOfGrowth(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, announced, Rules{})
	for i := 1; i <= 61; i++ {
		w.Grew(t0.Add(time.Duration(i)*time.Minute), grow, Rules{})
	}
	if w.Quiet(t0.Add(61*time.Minute)) != nil {
		t.Fatal("an hour of growth did not close the episode")
	}
	if !silent(w, t0.Add(61*time.Minute+DefaultLimits.Silence), false) {
		t.Fatal("silence after a closed episode did not alarm")
	}
}

func TestQuietSurvivesPiRestart(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, announced, Rules{})
	age := w.Quiet(t0.Add(20 * time.Hour))
	t1 := t0.Add(30 * time.Hour) // the Pi was down for ten hours: they do not count
	r := NewWatchdog(DefaultLimits, t1, age, false)
	rest := DefaultLimits.Quiet - 20*time.Hour
	if silent(r, t1.Add(rest-time.Second), false) {
		t.Fatal("alarmed before the restored cap")
	}
	if !silent(r, t1.Add(rest), false) {
		t.Fatal("the restart restarted the cap")
	}
}

func TestVerifyFreshness(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Caught(t0.Add(time.Minute))
	if DefaultLimits.Fresh > time.Hour-time.Minute {
		t.Fatal("the freshness limit leaves no minute for the push within verify_freshness_s")
	}
	if _, ok := w.Conditions(t0.Add(time.Minute+DefaultLimits.Fresh-time.Second), false)[KeyFresh]; ok {
		t.Fatal("fresh verification alarmed")
	}
	if _, ok := w.Conditions(t0.Add(time.Minute+DefaultLimits.Fresh), false)[KeyFresh]; !ok {
		t.Fatal("no freshness alarm at its limit")
	}
}

func TestTruncationAlarm11vs10(t *testing.T) {
	t0 := time.Now()
	for _, c := range []struct{ n, alarms int }{{10, 0}, {11, 1}} {
		w := NewWatchdog(DefaultLimits, t0, nil, false)
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

// The host sets how many truncated entries one step brings: the Pi keeps only what the decision needs.
func TestTruncationWindowIsBounded(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	w.Grew(t0, Findings{Entries: 1, Truncated: 4_000_000}, Rules{})
	runtime.ReadMemStats(&after)
	if len(w.trunc) != DefaultLimits.Truncated+1 || after.TotalAlloc-before.TotalAlloc > 1<<20 {
		t.Fatalf("kept %d times, allocated %d bytes", len(w.trunc), after.TotalAlloc-before.TotalAlloc)
	}
	if _, ok := w.Conditions(t0, false)[KeyTruncated]; !ok {
		t.Fatal("no alarm")
	}
}

func TestPendingUnknownSurvivesRestart(t *testing.T) {
	t0 := time.Now()
	w := NewWatchdog(DefaultLimits, t0, nil, true)
	if _, ok := w.Conditions(t0.Add(DefaultLimits.Grace), false)[KeyHealth]; !ok {
		t.Fatal("a saved pending UNKNOWN never alarmed after a restart")
	}
	if _, ok := NewWatchdog(DefaultLimits, t0, nil, false).Conditions(t0.Add(time.Hour), false)[KeyHealth]; ok {
		t.Fatal("alarmed with nothing pending")
	}
}
