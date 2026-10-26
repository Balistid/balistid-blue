package rangerun

import (
	"os"
	"path/filepath"
	"slices"
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
	for _, m := range []string{"sustained_rate", "burst_rate", "crash_loss_ms"} {
		if v := a.Verdict(m); v != rangevm.Pass {
			t.Errorf("%s: %q", m, v)
		}
	}
	// crash_loss_ms never passes on its writer controls alone, only with the collector's failures.
	c := Acceptance{}.ForCommit(testCommit)
	for _, tr := range rangejob.Trials() {
		if tr.Method() == rangejob.MethodWriterFailure {
			c = c.Record(tr, rangevm.LabelControl, tr.Expect, resultID)
		}
	}
	if v := c.Verdict("crash_loss_ms"); v != "" {
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
	other := `{"schema_version":2,"commit":"` + strings.Repeat("b", 40) + `","trials":{"rate-old":{"valid":9}},"new":1}`
	if err := os.WriteFile(path, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if a, err := LoadAcceptance(path, testCommit); err != nil || a.Commit != testCommit || len(a.Trials) != 0 {
		t.Errorf("another commit's suite: %+v, %v", a, err)
	}
}

// INVALID runs repeat, then the trial gives up and its metric is INVALID, never a MISS (ADR 0021):
// a counting trial's and a control's alike. A control that gives the other verdict is INVALID.
func TestInvalidRunsMakeAnInvalidMetricNeverAMiss(t *testing.T) {
	burst, drop := tableTrial(t, "rate-burst"), tableTrial(t, "rate-control-drop")
	a := Acceptance{}.ForCommit(testCommit)
	for i := range burst.Count + 1 {
		if v := a.Verdict("burst_rate"); v != "" {
			t.Fatalf("after %d INVALID: %q", i, v)
		}
		a = a.Record(burst, counted, rangevm.Invalid, resultID)
	}
	if v, r := a.Verdict("burst_rate"), a.Trials[burst.Name]; v != rangevm.Invalid || r.Miss != "" {
		t.Fatalf("verdict %q, runs %+v", v, r)
	}
	if tr, ok := a.Next(); ok && tr.Metric == "burst_rate" {
		t.Errorf("an INVALID metric runs again: %s", tr.Name)
	}
	b := Acceptance{}.ForCommit(testCommit)
	for range drop.Count + 1 {
		b = b.Record(drop, rangevm.LabelControl, rangevm.Pass, resultID)
	}
	if v, r := b.Verdict("sustained_rate"), b.Trials[drop.Name]; v != rangevm.Invalid || r.Valid != 0 || r.Miss != "" {
		t.Errorf("a control that passed instead of missing: %q, %+v", v, r)
	}
	// A MISS is never replaced by INVALID runs after it.
	c := Acceptance{}.ForCommit(testCommit).Record(burst, counted, rangevm.Miss, resultID)
	for range burst.Count + 1 {
		c = c.Record(burst, counted, rangevm.Invalid, resultID)
	}
	if v := c.Verdict("burst_rate"); v != rangevm.Miss {
		t.Errorf("INVALID replaced a MISS: %q", v)
	}
}

// Baseline INVALID runs decide nothing either; the trial gives up so the suite ends.
func TestBaselineInvalidsDecideNothing(t *testing.T) {
	burst := tableTrial(t, "rate-burst")
	a := Acceptance{}.ForCommit(testCommit)
	for range 10 {
		a = a.Record(burst, rangevm.LabelBaseline, rangevm.Invalid, resultID)
	}
	if v := a.Verdict("burst_rate"); v != "" {
		t.Errorf("baseline INVALIDs decided burst_rate: %q", v)
	}
	if tr, ok := a.Next(); ok && tr.Name == burst.Name {
		t.Error("a baseline trial that cannot measure holds the suite")
	}
}

// A control that cannot measure makes its metric INVALID, and the suite moves on to other metrics.
func TestAControlThatCannotMeasureGivesUp(t *testing.T) {
	sync := tableTrial(t, "reset-control-sync250")
	a := Acceptance{}.ForCommit(testCommit)
	for range sync.Count + 1 {
		a = a.Record(sync, rangevm.LabelControl, rangevm.Invalid, resultID)
	}
	if v := a.Verdict("crash_loss_ms"); v != rangevm.Invalid {
		t.Fatalf("crash_loss_ms %q", v)
	}
	if tr, ok := a.Next(); !ok || tr.Metric == "crash_loss_ms" {
		t.Fatalf("next %s %v", tr.Name, ok)
	}
}

func TestMetricsAreTheTables(t *testing.T) {
	if got := Metrics(); !slices.Equal(got, []string{"sustained_rate", "burst_rate", "crash_loss_ms", "record_max_kib", "refusal_summary_s",
		"ready_s", "systemd_exposure", "cpu_cores"}) {
		t.Errorf("metrics %v", got)
	}
}
