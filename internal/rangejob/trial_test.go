package rangejob

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// Every trial fits one batch with its setup (ADR 0018, point 1), and its load is one the guest has.
func TestTrialTableFitsTheBudget(t *testing.T) {
	name := regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	seen := map[string]bool{}
	for _, tr := range Trials() {
		switch {
		case !name.MatchString(tr.Name) || seen[tr.Name]:
			t.Errorf("%q: name not a unique lowercase word", tr.Name)
		case tr.Count < 1 || tr.Wall <= 0 || tr.Serial <= 0:
			t.Errorf("%s: count, wall and serial must be positive", tr.Name)
		case int64(tr.Count)*int64(tr.Wall+Setup) > int64(Batch):
			t.Errorf("%s: %d × (%s + %s) exceeds the %s batch", tr.Name, tr.Count, tr.Wall, Setup, Batch)
		case tr.Load.Kind != LoadExec && tr.Load.Kind != LoadPtrace:
			t.Errorf("%s: unknown load %q", tr.Name, tr.Load.Kind)
		case tr.Load.Seconds < 10 || tr.Load.Seconds%10 != 0 || tr.Load.Rate < 1 || tr.Metric == "":
			t.Errorf("%s: a trial measures a metric at a positive rate for whole 10 s windows", tr.Name)
		}
		seen[tr.Name] = true
	}
}

func TestLookupOnlyFindsTheTable(t *testing.T) {
	if tr, ok := Lookup("rate-burst"); !ok || tr.Load.Kind != LoadPtrace {
		t.Errorf("Lookup(rate-burst) = %+v, %v", tr, ok)
	}
	for _, name := range []string{"", "rate", "RATE-BURST", "rate-burst ", "../rate-burst"} {
		if _, ok := Lookup(name); ok {
			t.Errorf("Lookup(%q) found a trial", name)
		}
	}
	Trials()[0].Name = "changed"
	if _, ok := Lookup("changed"); ok {
		t.Error("Trials returns the table itself")
	}
}

// A trial's load is its metric's threshold in acceptance/0.toml: the minimum rate for the stated
// seconds, so the table cannot drift from what the acceptance file promises.
func TestTrialLoadIsTheAcceptanceThreshold(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range Trials() {
		if tr.Load.Drop {
			continue
		}
		block := regexp.MustCompile(`(?m)^id = "` + tr.Metric + `"\nmin = (\d+)\nunit = "records/s for (\d+) s`).FindSubmatch(data)
		if block == nil {
			t.Errorf("%s: no metric %s with a minimum rate in acceptance/0.toml", tr.Name, tr.Metric)
			continue
		}
		if rate, s := string(block[1]), string(block[2]); rate != strconv.Itoa(tr.Load.Rate) || s != strconv.Itoa(tr.Load.Seconds) {
			t.Errorf("%s: %d/s for %d s, acceptance says %s/s for %s s", tr.Name, tr.Load.Rate, tr.Load.Seconds, rate, s)
		}
	}
}
