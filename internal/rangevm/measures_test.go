package rangevm

import (
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"
)

func TestMeasuresOfARateTrialAreItsCounts(t *testing.T) {
	tr := trial(t, "rate-burst")
	m := Measures(tr, report(tr))
	// The collector's CPU is a measure too; its memory peak, reported as unknown, is left out.
	if len(m) != len(counts)+1 || m[FactStealTicks] != 100 || m[FactCPUTicks] != 10000 || m[FactGenerated] != 100000 ||
		m[FactCollectorUS] != 9000000 {
		t.Fatalf("measures %v", m)
	}
	if _, ok := m[FactCollectorMem]; ok {
		t.Errorf("a memory peak that is not a number: %v", m)
	}
	for _, k := range []string{MeasureH, MeasureSynced, MeasureExitAfterFail, MeasureKilledAfterFail} {
		if _, ok := m[k]; ok {
			t.Errorf("a rate trial has %s", k)
		}
	}
}

// The guest's report is hostile input (T30): a count it repeats or writes as anything but a plain
// number is left out, not read one way or the other.
func TestMeasuresLeaveOutABadCount(t *testing.T) {
	tr := trial(t, "rate-burst")
	for name, o := range map[string]Outcome{
		"repeated": func() Outcome {
			o := report(tr)
			o.Facts = append(o.Facts, Record{Name: FactStealTicks, Value: "0"})
			return o
		}(),
		"signed":  report(tr, FactStealTicks+"=+100"),
		"padded":  report(tr, FactStealTicks+"=0100"),
		"text":    report(tr, FactStealTicks+"=lots"),
		"missing": report(tr, FactStealTicks+"="),
	} {
		m := Measures(tr, o)
		if _, ok := m[FactStealTicks]; ok || len(m) != len(counts) {
			t.Errorf("%s: measures %v", name, m)
		}
	}
}

func TestMeasuresOfAFailureTrialTimeTheMarks(t *testing.T) {
	t0 := time.Unix(1790899200, 0)
	reset, kill := trial(t, "reset-control-sync250"), trial(t, "kill-control-buffer2s")

	o := failureRun(reset)
	o.Marks.Fail, o.Marks.Exited = t0, t0.Add(37*time.Millisecond+250*time.Microsecond)
	want := map[string]uint64{FactStoredPrefix: 1200, FactStoredCount: 1300, MeasureH: 1000, MeasureSynced: 1100, MeasureExitAfterFail: 37250}
	if m := Measures(reset, o); !maps.Equal(m, want) {
		t.Errorf("reset: measures %v, want %v", m, want)
	}

	o = failureRun(kill)
	o.Marks.Fail, o.Marks.Killed, o.Marks.Exited = t0, t0.Add(2*time.Millisecond), t0.Add(-time.Millisecond)
	m := Measures(kill, o)
	if m[MeasureKilledAfterFail] != 2000 {
		t.Errorf("kill: measures %v", m)
	}
	if _, ok := m[MeasureExitAfterFail]; ok {
		t.Errorf("kill: an exit before the fail mark was measured: %v", m)
	}

	// Without a fail mark there is nothing to time and no H or S the host saw.
	m = Measures(reset, failureRun(reset))
	if want := (map[string]uint64{FactStoredPrefix: 1200, FactStoredCount: 1300}); !maps.Equal(m, want) {
		t.Errorf("no fail mark: measures %v, want %v", m, want)
	}
}

// A self-test stores no measures key at all.
func TestResultWithoutMeasuresHasNoKey(t *testing.T) {
	data, err := json.Marshal(Result{SchemaVersion: resultSchema})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "measures") {
		t.Errorf("result %s", data)
	}
}
