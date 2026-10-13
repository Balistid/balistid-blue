package rangerun

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

const resultID = "20261013T081016Z-ab121c4f"

func tableTrial(t *testing.T, name string) rangejob.Trial {
	t.Helper()
	tr, ok := rangejob.Lookup(name)
	if !ok {
		t.Fatalf("no trial %s", name)
	}
	return tr
}

// counted is a label a counting run would carry once the collector's store reader is in the table.
const counted = "acceptance"

// runAll records every run the suite asks for with what verdict says for it, until it is done.
func runAll(a Acceptance, verdict func(rangejob.Trial) (label, verdict string)) Acceptance {
	for range 100 {
		tr, ok := a.Next()
		if !ok {
			return a
		}
		l, v := verdict(tr)
		a = a.Record(tr, l, v, resultID)
	}
	return a
}

func TestAMetricPassesOnlyWhenEveryRunPassesAndEveryControlHolds(t *testing.T) {
	a := Acceptance{}.ForCommit(testCommit)
	a = runAll(a, func(tr rangejob.Trial) (string, string) {
		if tr.Expect != "" {
			return rangevm.LabelControl, tr.Expect
		}
		return counted, rangevm.Pass
	})
	for _, m := range []string{"sustained_rate", "burst_rate"} {
		if v := a.Verdict(m); v != rangevm.Pass {
			t.Errorf("%s: %q", m, v)
		}
	}
	// crash_loss_ms has only controls until the collector's failure trials join the table (B4).
	if v := a.Verdict("crash_loss_ms"); v != "" {
		t.Errorf("crash_loss_ms passed on its controls alone: %q", v)
	}
	// One run short of the count leaves the metric open.
	b := Acceptance{}.ForCommit(testCommit).Record(tableTrial(t, "rate-burst"), counted, rangevm.Pass, resultID)
	if v := b.Verdict("burst_rate"); v != "" {
		t.Errorf("one of three runs: %q", v)
	}
}

// Baseline runs measure Laurel, not the collector: they never pass a metric and their MISS does not stand.
func TestBaselineRunsDecideNothing(t *testing.T) {
	a := runAll(Acceptance{}.ForCommit(testCommit), func(tr rangejob.Trial) (string, string) {
		if tr.Expect != "" {
			return rangevm.LabelControl, tr.Expect
		}
		return rangevm.LabelBaseline, rangevm.Miss
	})
	if v := a.Verdict("sustained_rate"); v != "" {
		t.Errorf("baseline decided the metric: %q", v)
	}
	if _, ok := a.Next(); ok {
		t.Error("the suite is not done after every run")
	}
	burst := tableTrial(t, "rate-burst")
	if r := (Acceptance{}).ForCommit(testCommit).Record(burst, rangevm.LabelBaseline, rangevm.Pass, resultID).Trials[burst.Name]; r.Passed != 0 || r.Valid != 1 {
		t.Errorf("a baseline PASS: %+v", r)
	}
}

func TestAMissStandsAndStopsTheMetric(t *testing.T) {
	sustained := tableTrial(t, "rate-sustained")
	a := Acceptance{}.ForCommit(testCommit).Record(sustained, counted, rangevm.Miss, resultID)
	a = a.Record(sustained, counted, rangevm.Pass, "20261013T090000Z-00000000")
	if v := a.Verdict("sustained_rate"); v != rangevm.Miss || a.Trials[sustained.Name].Miss != resultID {
		t.Fatalf("verdict %q, runs %+v", v, a.Trials[sustained.Name])
	}
	if tr, ok := a.Next(); ok && tr.Metric == "sustained_rate" {
		t.Errorf("a missed metric is run again: %s", tr.Name)
	}
}

// INVALID runs repeat; once they outnumber the metric's runs the metric is a MISS. A control that
// gives the other verdict is INVALID, never a MISS of the metric.
func TestInvalidRunsRepeatThenMiss(t *testing.T) {
	burst := tableTrial(t, "rate-burst")
	a := Acceptance{}.ForCommit(testCommit)
	for i := range burst.Count {
		a = a.Record(burst, counted, rangevm.Invalid, resultID)
		if tr, ok := a.Next(); !ok || a.Verdict("burst_rate") != "" {
			t.Fatalf("after %d INVALID: next %v %v, verdict %q", i+1, tr.Name, ok, a.Verdict("burst_rate"))
		}
	}
	if a = a.Record(burst, counted, rangevm.Unknown, resultID); a.Verdict("burst_rate") != rangevm.Miss {
		t.Fatalf("%d INVALID of %d runs: %q", a.Trials[burst.Name].Invalid, burst.Count, a.Verdict("burst_rate"))
	}
	drop := tableTrial(t, "rate-control-drop")
	b := Acceptance{}.ForCommit(testCommit).Record(drop, rangevm.LabelControl, rangevm.Pass, resultID)
	if r := b.Trials[drop.Name]; r.Invalid != 1 || r.Valid != 0 || r.Miss != "" {
		t.Errorf("a control that passed instead of missing: %+v", r)
	}
}

func TestANewCommitRestartsTheSuite(t *testing.T) {
	a := Acceptance{}.ForCommit(testCommit).Record(tableTrial(t, "rate-sustained"), counted, rangevm.Miss, resultID)
	if b := a.ForCommit(testCommit); b.Trials["rate-sustained"].Miss == "" {
		t.Error("the same commit lost its MISS")
	}
	other := strings.Repeat("b", 40)
	if b := a.ForCommit(other); b.Commit != other || len(b.Trials) != 0 {
		t.Errorf("another commit kept %+v", b)
	}
}

func TestAcceptanceRoundTripsAndRefusesWhatItWouldNotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acceptance.json")
	if a, err := LoadAcceptance(path, testCommit); err != nil || a.Commit != testCommit || len(a.Trials) != 0 {
		t.Fatalf("missing file: %+v, %v", a, err)
	}
	a := Acceptance{}.ForCommit(testCommit).Record(tableTrial(t, "rate-sustained"), counted, rangevm.Miss, resultID)
	if err := SaveAcceptance(path, a); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadAcceptance(path, testCommit); err != nil || got.Trials["rate-sustained"] != a.Trials["rate-sustained"] {
		t.Fatalf("loaded %+v, %v", got, err)
	}
	head := `{"schema_version":1,"commit":"` + testCommit + `","trials":`
	for name, data := range map[string]string{
		"unknown trial":   head + `{"rate-fast":{"valid":0,"passed":0,"invalid":0}}}`,
		"over count":      head + `{"rate-burst":{"valid":4,"passed":0,"invalid":0}}}`,
		"passed > valid":  head + `{"rate-burst":{"valid":1,"passed":2,"invalid":0}}}`,
		"negative":        head + `{"rate-burst":{"valid":0,"passed":0,"invalid":-1}}}`,
		"control missed":  head + `{"rate-control-drop":{"valid":1,"passed":0,"invalid":0,"miss":"` + resultID + `"}}}`,
		"miss not an id":  head + `{"rate-burst":{"valid":1,"passed":0,"invalid":0,"miss":"../x"}}}`,
		"unknown field":   head + `{},"x":1}`,
		"no trials":       `{"schema_version":1,"commit":"` + testCommit + `"}`,
		"short commit":    `{"schema_version":1,"commit":"abc","trials":{}}`,
		"other schema":    `{"schema_version":2,"commit":"` + testCommit + `","trials":{}}`,
		"trailing object": head + `{}}{}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAcceptance(path, testCommit); err == nil || strings.Contains(err.Error(), "../x") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := SaveAcceptance(path, Acceptance{Commit: "short"}); err == nil {
		t.Error("saved a suite of no full commit")
	}
	// Another commit's suite is not checked against this table, which may have renamed its trials.
	other := `{"schema_version":1,"commit":"` + strings.Repeat("b", 40) + `","trials":{"rate-old":{"valid":9,"passed":0,"invalid":0,"strikes":0}}}`
	if err := os.WriteFile(path, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := LoadAcceptance(path, testCommit); err != nil || a.Commit != testCommit || len(a.Trials) != 0 {
		t.Errorf("another commit's suite: %+v, %v", a, err)
	}
}

// Only INVALID runs that may decide a metric add up to its MISS: never a baseline's or a control's.
func TestOnlyDecidingInvalidsMakeAMiss(t *testing.T) {
	burst, drop := tableTrial(t, "rate-burst"), tableTrial(t, "rate-control-drop")
	a := Acceptance{}.ForCommit(testCommit)
	for range 10 {
		a = a.Record(burst, rangevm.LabelBaseline, rangevm.Invalid, resultID)
		a = a.Record(drop, rangevm.LabelControl, rangevm.Invalid, resultID)
	}
	if v := a.Verdict("burst_rate"); v != "" {
		t.Errorf("baseline INVALIDs decided burst_rate: %q", v)
	}
	if v := a.Verdict("sustained_rate"); v != "" {
		t.Errorf("control INVALIDs decided sustained_rate: %q", v)
	}
	if r := a.Trials[burst.Name]; r.Invalid != 10 || r.Strikes != 0 {
		t.Errorf("baseline runs %+v", r)
	}
}

// A trial that keeps coming out INVALID gives up after Count+1 tries, so the trials after it run.
func TestATrialThatCannotMeasureGivesUp(t *testing.T) {
	sync := tableTrial(t, "reset-control-sync250")
	a := Acceptance{}.ForCommit(testCommit)
	for _, name := range []string{"rate-sustained", "rate-burst", "rate-control-drop"} {
		tr := tableTrial(t, name)
		for range tr.Count {
			label, v := rangevm.LabelBaseline, rangevm.Pass
			if tr.Expect != "" {
				label, v = rangevm.LabelControl, tr.Expect
			}
			a = a.Record(tr, label, v, resultID)
		}
	}
	for i := range sync.Count + 1 {
		if next, ok := a.Next(); !ok || next.Name != sync.Name {
			t.Fatalf("try %d: next %s", i+1, next.Name)
		}
		a = a.Record(sync, rangevm.LabelControl, rangevm.Invalid, resultID)
	}
	if next, ok := a.Next(); !ok || next.Name == sync.Name {
		t.Fatalf("after %d INVALID the suite still runs %s", sync.Count+1, next.Name)
	}
}

// A MISS made by INVALID runs stands with the result that made it, so retention keeps it.
func TestAMissOfInvalidsKeepsItsResult(t *testing.T) {
	burst := tableTrial(t, "rate-burst")
	a := Acceptance{}.ForCommit(testCommit)
	for i := range burst.Count + 1 {
		a = a.Record(burst, counted, rangevm.Invalid, fmt.Sprintf("20261013T0900%02dZ-00000000", i))
	}
	if v, r := a.Verdict("burst_rate"), a.Trials[burst.Name]; v != rangevm.Miss || r.Miss != "20261013T090003Z-00000000" {
		t.Fatalf("verdict %q, runs %+v", v, r)
	}
}
