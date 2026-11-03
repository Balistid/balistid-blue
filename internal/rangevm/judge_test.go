package rangevm

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

const cleanBuild = "0123456789abcdef0123456789abcdef01234567"

// Every trial of the table is a run RunTrial accepts.
func TestTrialTableIsValidLimits(t *testing.T) {
	for _, tr := range rangejob.Trials() {
		lim := Limits{Trial: tr.Name, Wall: tr.Wall, Serial: tr.Serial, Boots: tr.Boots, Scratch: tr.Scratch, Failure: tr.Failure}
		if err := lim.check(); err != nil {
			t.Errorf("%s: %v", tr.Name, err)
		}
	}
}

func trial(t *testing.T, name string) rangejob.Trial {
	t.Helper()
	tr, ok := rangejob.Lookup(name)
	if !ok {
		t.Fatalf("no trial %s", name)
	}
	return tr
}

// report is a complete rate report of tr with no loss, changed by the given name=value pairs.
func report(tr rangejob.Trial, change ...string) Outcome {
	planned := strconv.Itoa(tr.Load.Rate * tr.Load.Seconds)
	values := map[string]string{
		FactTrial: tr.Name, FactPhase: "1", FactKernel: TargetKernel,
		FactGenerated: planned, FactWindowMin: strconv.Itoa(tr.Load.Rate * 10), FactLostBefore: "0", FactLostAfter: "0",
		FactOverflowBefore: "no", FactOverflowAfter: "no", FactStealWindows: windows(tr.Load.Seconds), FactFollow: "ok",
		FactStored: planned, FactMissing: "0", FactDuplicate: "0", FactOutside: "0",
		FactCollectorUS: "9000000", FactCollectorMem: "unknown",
	}
	for _, c := range change {
		name, value, _ := strings.Cut(c, "=")
		values[name] = value
	}
	var o Outcome
	for _, name := range rateFacts {
		if v, ok := values[name]; ok {
			o.Facts = append(o.Facts, Record{Name: name, Value: v})
		}
	}
	return o
}

// windows is a steal series of a load of seconds and 30 s of drain on 4 vCPUs, the last second at exactly 1 %
// steal, with spans replaced by the given index=span pairs.
func windows(seconds int, change ...string) string {
	spans := slices.Repeat([]string{"1000:400:0"}, seconds+30)
	spans[len(spans)-1] = "1000:400:4"
	for _, c := range change {
		i, span, _ := strings.Cut(c, "=")
		n, _ := strconv.Atoi(i)
		spans[n] = span
	}
	return strings.Join(spans, ",")
}

// Host steal makes a run INVALID whatever it would have given (ADR 0057), so rerunning INVALID runs cannot pick
// the PASSes: judged second by second, one stolen second is not diluted by the rest of the run, nor a second the
// guest did not measure. A series that is malformed or does not cover the load is INVALID too.
func TestJudgeRateStealVoidsEitherVerdict(t *testing.T) {
	tr := trial(t, "rate-sustained")
	miss := []string{FactMissing + "=1", FactStored + "=1199999"}
	cases := []struct {
		name, series string
		miss         bool
		want         string
	}{
		{"clean", windows(600), false, Pass},
		{"clean miss", windows(600), true, Miss},
		{"stolen second", windows(600, "300=1000:400:5"), false, Invalid},
		{"stolen second, miss", windows(600, "300=1000:400:5"), true, Invalid},
		{"stolen second in the drain, miss", windows(600, "620=1000:100:2"), true, Invalid},
		{"stolen short span, miss", windows(600, "0=10:4:1"), true, Invalid},
		{"unmeasured, miss", windows(600, "300=2001:800:0"), true, Invalid},
		{"unmeasured", windows(600, "300=2001:800:0"), false, Invalid},
		{"one long span", "600000:240000:0", false, Invalid},
		{"two seconds", windows(600, "300=2000:800:8"), false, Pass},
		{"two seconds, miss", windows(600, "300=2000:800:8"), true, Miss},
		{"no ticks in a second, miss", windows(600, "300=1000:0:0"), true, Invalid},
		{"no ticks in a short last span, miss", windows(600, "629=999:0:0"), true, Miss},
		{"empty", "", false, Invalid},
		{"no steal", windows(600, "3=1000:400"), false, Invalid},
		{"steal over its ticks", windows(600, "3=1000:400:401"), false, Invalid},
		{"padded", windows(600, "3=01000:400:0"), false, Invalid},
		{"signed", windows(600, "3=1000:400:-1"), false, Invalid},
		{"spaced", windows(600, "3=1000:400:0 "), false, Invalid},
		{"overlong", windows(600, "3=1000:4000000000000:0"), false, Invalid},
		{"short of the load", strings.Join(slices.Repeat([]string{"1000:400:0"}, 599), ","), false, Invalid},
		{"too many spans", strings.Join(slices.Repeat([]string{"1000:400:0"}, maxStealWindows+1), ","), false, Invalid},
	}
	for _, c := range cases {
		change := []string{FactStealWindows + "=" + c.series}
		if c.miss {
			change = append(change, miss...)
		}
		if v, r := JudgeTrial(tr, report(tr, change...), cleanBuild, cleanBuild); v != c.want {
			t.Errorf("%s: %s (%s); want %s", c.name, v, r, c.want)
		}
	}
	// The reason names the first stolen span and how many there were, so a log shows how noisy the host was.
	two := report(tr, append(miss, FactStealWindows+"="+windows(600, "5=1000:400:5", "9=2500:1000:0"))...)
	if v, r := JudgeTrial(tr, two, cleanBuild, cleanBuild); v != Invalid || !strings.Contains(r, "steal 5 of 400 ticks in 1000 ms from 5000 ms on; 2 of 630 spans") {
		t.Errorf("two stolen spans: %s (%s)", v, r)
	}
	// A run keeps its worst span as a measure: 5 of 400 ticks is 12500 ppm; the clean series' worst is 1 %.
	if m := Measures(tr, two); m[MeasureStealWorstPPM] != 12500 {
		t.Errorf("worst steal measure %v", m)
	}
	if m := Measures(tr, report(tr)); m[MeasureStealWorstPPM] != 10000 {
		t.Errorf("clean worst steal measure %v", m)
	}
	// The control's dropped number under steal proves nothing either.
	control := trial(t, "rate-control-drop")
	stolen := report(control, FactMissing+"=1", FactStored+"=29999", FactStealWindows+"="+windows(30, "10=1000:400:5"))
	if v, r := JudgeTrial(control, stolen, cleanBuild, cleanBuild); v != Invalid || !strings.Contains(r, "host steal") {
		t.Errorf("control under steal: %s (%s); want INVALID", v, r)
	}
}

func TestJudgeTrialPassesOnlyACompleteRun(t *testing.T) {
	tr := trial(t, "rate-sustained")
	if v, r := JudgeTrial(tr, report(tr), cleanBuild, cleanBuild); v != Pass {
		t.Fatalf("clean run: %s (%s); want PASS", v, r)
	}
	cases := map[string][]string{
		Miss: {
			"missing=1,stored=1199999", "duplicate=1", "outside=1", "audit_lost_after=1", "overflow_after=yes",
			"window_min=19999", "generated=1199999,stored=1199999,window_min=19999",
		},
		Invalid: {
			"follow=barrier missing", "kernel=6.0.0", "overflow_after=stale",
			"overflow_before=yes", "overflow_after=maybe", "generated=1200001,stored=1200001", "stored=1199999",
			"generated=", "duplicate=00", "missing=-1", "missing=1 ", "trial=rate-burst",
			// Codex round 1 on #100: contradictions get no binding verdict.
			"window_min=120001",
			"stored=18446744073709551615,missing=1200001",
			"stored=1200001,missing=0",
			"audit_lost_before=10,audit_lost_after=0",
		},
	}
	for want, changes := range cases {
		for _, c := range changes {
			if v, r := JudgeTrial(tr, report(tr, strings.Split(c, ",")...), cleanBuild, cleanBuild); v != want {
				t.Errorf("%s: %s (%s); want %s", c, v, r, want)
			}
		}
	}
}

// A control is judged like any trial, so its one dropped number makes it a MISS; a reader that
// misses nothing makes it a PASS, which is not what a control must give.
func TestJudgeTrialControlMustMiss(t *testing.T) {
	tr := trial(t, "rate-control-drop")
	if ExpectedVerdict(tr) != Miss || ExpectedVerdict(trial(t, "rate-burst")) != Pass {
		t.Fatal("a control must give MISS, a metric trial PASS")
	}
	cases := map[string]string{
		"missing=1,stored=29999": Miss,
		"":                       Pass,
		"missing=1,stored=29999,overflow_after=yes": Miss,
		"missing=1,stored=29999,follow=behind":      Invalid,
	}
	for c, want := range cases {
		if v, r := JudgeTrial(tr, report(tr, strings.Split(c, ",")...), cleanBuild, cleanBuild); v != want {
			t.Errorf("control %q: %s (%s); want %s", c, v, r, want)
		}
	}
}

// A report missing a fact, repeating one, adding one or saying the guest failed is INVALID, as is
// a launcher or image that is not the same clean build, and the boot's own INVALID stands.
func TestJudgeTrialRefusesAnIncompleteReport(t *testing.T) {
	tr := trial(t, "rate-burst")
	full := report(tr)
	outcomes := map[string]Outcome{
		"missing fact": {Facts: full.Facts[:len(full.Facts)-1]},
		"no phase":     {Facts: append(append([]Record(nil), full.Facts[:1]...), full.Facts[2:]...)},
		"repeated":     {Facts: append(append([]Record(nil), full.Facts...), full.Facts[5])},
		"unknown":      {Facts: append(append([]Record(nil), full.Facts...), Record{Name: "canary", Value: "seen"})},
		"guest error":  {Facts: append(append([]Record(nil), full.Facts[:3]...), Record{Name: FactTrialError, Value: "no"})},
		"boot invalid": {Facts: full.Facts, Invalid: "vm: no exit"},
	}
	for name, o := range outcomes {
		if v, r := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("%s: %s (%s); want INVALID", name, v, r)
		}
	}
	for _, pair := range [][2]string{{"dev", "dev"}, {cleanBuild, strings.Repeat("f", 40)}} {
		if v, _ := JudgeTrial(tr, full, pair[0], pair[1]); v != Invalid {
			t.Errorf("launcher %s, image %s: %s", pair[0], pair[1], v)
		}
	}
}

// A trial no method judges is INVALID, whatever its facts say.
func TestJudgeTrialWithoutAMethodIsInvalid(t *testing.T) {
	tr := trial(t, "rate-burst")
	tr.Metric = "healthy_ok"
	if v, r := JudgeTrial(tr, report(trial(t, "rate-burst")), cleanBuild, cleanBuild); v != Invalid || !strings.Contains(r, "no method") {
		t.Fatalf("%s (%s); want INVALID", v, r)
	}
}

// Whatever the guest reports, a PASS means a complete, lossless run at the planned rate.
func FuzzJudgeTrial(f *testing.F) {
	f.Add("missing=0\nwindow_min=20000")
	f.Add("stored=1\nmissing=1199999")
	f.Fuzz(func(t *testing.T, changes string) {
		tr, _ := rangejob.Lookup("rate-sustained")
		o := report(tr, strings.Split(changes, "\n")...)
		if v, _ := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != Pass {
			return
		}
		facts := map[string]string{}
		for _, r := range o.Facts {
			facts[r.Name] = r.Value
		}
		for name, want := range map[string]string{
			FactGenerated: "1200000", FactStored: "1200000", FactMissing: "0", FactDuplicate: "0", FactOutside: "0",
			FactFollow: "ok", FactOverflowAfter: "no", FactKernel: TargetKernel,
		} {
			if facts[name] != want {
				t.Fatalf("PASS with %s=%q", name, facts[name])
			}
		}
		if facts[FactLostAfter] != facts[FactLostBefore] {
			t.Fatalf("PASS with audit lost %s → %s", facts[FactLostBefore], facts[FactLostAfter])
		}
		if w, err := strconv.Atoi(facts[FactWindowMin]); err != nil || w < 20000 {
			t.Fatalf("PASS with window_min=%q", facts[FactWindowMin])
		}
	})
}

// A trial's stored result names the trial and its label, baseline or control, so a baseline PASS
// is never read as a metric's PASS.
func TestCheckStoresTheTrialAndItsLabel(t *testing.T) {
	image := storeImage(t, t.TempDir(), "x", cleanBuild)
	state := t.TempDir()
	for _, name := range []string{"rate-burst", "rate-control-drop"} {
		tr := trial(t, name)
		res, err := check(t.Context(), image, t.TempDir(), state, tr.Name, TrialLabel(tr),
			func(string, io.Writer) (Outcome, error) { return report(tr), nil },
			func(o Outcome, _, _ string) (string, string) { return JudgeTrial(tr, o, cleanBuild, cleanBuild) },
			func(o Outcome) map[string]uint64 { return Measures(tr, o) })
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(state, "results", res.ID, "result.json")) //nolint:gosec // the test's state directory
		if err != nil {
			t.Fatal(err)
		}
		var stored Result
		if err := json.Unmarshal(data, &stored); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"rate-burst": "", "rate-control-drop": LabelControl}[name]
		if stored.Trial != name || stored.Label != want || stored.Verdict != Pass {
			t.Errorf("%s stored trial %q, label %q, verdict %q; want label %q", name, stored.Trial, stored.Label, stored.Verdict, want)
		}
		if stored.SchemaVersion != 2 || stored.Measures[FactCollectorUS] != 9000000 || len(stored.Measures) != len(counts)+2 {
			t.Errorf("%s stored schema %d, measures %v", name, stored.SchemaVersion, stored.Measures)
		}
	}
}

// Since the guest reads the collector's store (ADR 0022), a trial's run may decide its metric: only a
// control is labelled, and no run is baseline (ADR 0018, point 4, amended).
func TestTrialLabelIsNeverBaseline(t *testing.T) {
	for _, tr := range rangejob.Trials() {
		want := ""
		if tr.Expect != "" {
			want = LabelControl
		}
		if got := TrialLabel(tr); got != want {
			t.Errorf("%s: label %q, want %q", tr.Name, got, want)
		}
	}
}
