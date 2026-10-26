package rangejob

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
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
		case tr.Metric == "":
			t.Errorf("%s: a trial measures a metric", tr.Name)
		case tr.Load != (Load{}) && (tr.Load.Seconds < 10 || tr.Load.Seconds%10 != 0 || tr.Load.Rate < 1):
			t.Errorf("%s: a load has a positive rate for whole 10 s windows", tr.Name)
		case tr.Expect != "" && tr.Expect != ExpectPass && tr.Expect != ExpectMiss, tr.Load.Drop && tr.Expect != ExpectMiss:
			t.Errorf("%s: a control expects PASS or MISS, and one that drops a number MISS", tr.Name)
		case tr.Method() == "":
			t.Errorf("%s: no method runs a %s trial with load %q", tr.Name, tr.Metric, tr.Load.Kind)
		case tr.Load.Kind == LoadWrite && tr.Method() != MethodWriterFailure:
			t.Errorf("%s: only a writer failure hands numbers to a measured writer", tr.Name)
		case tr.Method() == MethodRate && tr.Load.Kind != LoadExec && tr.Load.Kind != LoadPtrace:
			t.Errorf("%s: unknown load %q", tr.Name, tr.Load.Kind)
		case tr.Failure == FailReset && tr.Boots != 2, tr.Failure == FailKill && tr.Boots != 1,
			tr.Failure != "" && tr.Failure != FailReset && tr.Failure != FailKill, tr.Failure == "" && tr.Boots != 1:
			t.Errorf("%s: a reset boots twice, a kill and a rate trial once", tr.Name)
		case tr.Scratch < StoreScratch:
			t.Errorf("%s: scratch disk of %d bytes, below the store's %d (ADR 0022, point 2)", tr.Name, tr.Scratch, StoreScratch)
		case tr.Load.Writer != (WriterPolicy{}) && tr.Load.Kind != LoadWrite:
			t.Errorf("%s: only a write load has a writer policy", tr.Name)
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

// Each trial has one method, from its failure, load and metric; anything else has none.
func TestMethod(t *testing.T) {
	for _, c := range []struct {
		tr   Trial
		want string
	}{
		{Trial{Metric: MetricSustained, Load: Load{Kind: LoadExec}}, MethodRate},
		{Trial{Metric: MetricBurst, Load: Load{Kind: LoadPtrace}}, MethodRate},
		{Trial{Metric: MetricCrashLoss, Failure: FailReset, Load: Load{Kind: LoadWrite}}, MethodWriterFailure},
		{Trial{Metric: MetricCrashLoss, Failure: FailKill, Load: Load{Kind: LoadExec}}, MethodCollectorFailure},
		{Trial{Metric: MetricCrashLoss, Failure: FailKill, Load: Load{Kind: LoadPtrace}}, ""},
		{Trial{Metric: MetricCrashLoss, Load: Load{Kind: LoadExec}}, ""},
		{Trial{Metric: "healthy_ok", Load: Load{Kind: LoadExec}}, ""},
		{Trial{Metric: MetricRecordMax}, MethodRecord},
		{Trial{Metric: MetricRecordMax, Load: Load{Kind: LoadExec, Rate: 1, Seconds: 10}}, ""},
		{Trial{Metric: MetricRefusal, Load: Load{Kind: LoadConnect, Rate: 100, Seconds: 150}}, MethodRefusal},
		{Trial{Metric: MetricRefusal}, ""},
		{Trial{Metric: MetricRecordMax, Failure: FailKill}, ""},
		{Trial{Metric: MetricReady}, MethodReady},
		{Trial{Metric: MetricExposure}, MethodExposure},
		{Trial{Metric: MetricExposure, Load: Load{Kind: LoadConnect, Rate: 1, Seconds: 10}}, ""},
		{Trial{Metric: MetricCPU, Load: Load{Kind: LoadExec, Rate: 1000, Seconds: 600}}, MethodCPU},
		{Trial{Metric: MetricCPU, Load: Load{Kind: LoadPtrace, Rate: 1000, Seconds: 600}}, ""},
		{Trial{Metric: MetricCPU, Load: Load{Kind: LoadExec, Rate: 1000, Seconds: 600, Drop: true}}, ""},
	} {
		if got := c.tr.Method(); got != c.want {
			t.Errorf("%+v: method %q, want %q", c.tr, got, c.want)
		}
	}
}

// cpu_cores is measured at 1000 records a second over 10 min (acceptance/0.toml), in rows that pass
// the metric only together with ten boots of ready_s.
func TestCPUAndReadyTrialsAreTheAcceptances(t *testing.T) {
	cpu, ok := Lookup("cpu-1000")
	if !ok || cpu.Load != (Load{Kind: LoadExec, Rate: 1000, Seconds: 600}) {
		t.Errorf("cpu-1000 = %+v", cpu)
	}
	boots := 0
	for _, tr := range Trials() {
		if tr.Method() == MethodReady {
			boots += tr.Count
		}
	}
	if boots < 10 {
		t.Errorf("%d ready boots; acceptance ready_s asks 10", boots)
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
		if !regexp.MustCompile(`(?m)^id = "` + tr.Metric + `"$`).Match(data) {
			t.Errorf("%s: no metric %s in acceptance/0.toml", tr.Name, tr.Metric)
		}
		switch {
		case tr.Failure != "":
			// Failures run at sustained_rate (acceptance crash_loss_ms).
			tr.Metric, tr.Load.Seconds = "sustained_rate", 600
		case tr.Expect != "", tr.Method() != MethodRate:
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

// The failure controls are the ones ADR 0018 point 4 names: a writer syncing every 250 ms to the
// end (must pass), one whose last sync is 1500 ms before the reset, and one holding records 2 s
// before write() under a kill (both must miss), all at sustained_rate.
func TestFailureControlsAreTheADRs(t *testing.T) {
	want := map[string]struct {
		failure, expect string
		writer          WriterPolicy
	}{
		"reset-control-sync250":      {FailReset, ExpectPass, WriterPolicy{Sync: 250 * time.Millisecond}},
		"reset-control-lastsync1500": {FailReset, ExpectMiss, WriterPolicy{Sync: 250 * time.Millisecond, LastSync: 1500 * time.Millisecond}},
		"kill-control-buffer2s":      {FailKill, ExpectMiss, WriterPolicy{Hold: 2 * time.Second}},
	}
	for name, w := range want {
		tr, ok := Lookup(name)
		if !ok || tr.Failure != w.failure || tr.Expect != w.expect || tr.Load.Writer != w.writer || tr.Load.Rate != 2000 {
			t.Errorf("%s = %+v, want %+v at 2000/s", name, tr, w)
		}
	}
}
