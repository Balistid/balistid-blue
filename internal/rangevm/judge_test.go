package rangevm

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
		FactOverflowBefore: "no", FactOverflowAfter: "no", FactCPUTicks: "10000", FactStealTicks: "100", FactFollow: "ok",
		FactDrainCPU: "5000", FactDrainSteal: "50",
		FactStored: planned, FactMissing: "0", FactDuplicate: "0", FactOutside: "0",
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
			"follow=barrier missing", "steal_ticks=101", "cpu_ticks=0", "kernel=6.0.0", "overflow_after=stale",
			"overflow_before=yes", "overflow_after=maybe", "generated=1200001,stored=1200001", "stored=1199999",
			"generated=", "duplicate=00", "missing=-1", "missing=1 ", "trial=rate-burst",
			"cpu_ticks=0,steal_ticks=0",
			// Codex round 1 on #100: contradictions get no binding verdict.
			"window_min=120001",
			"stored=18446744073709551615,missing=1200001",
			"stored=1200001,missing=0",
			"audit_lost_before=10,audit_lost_after=0",
			"drain_steal_ticks=51",
			"drain_cpu_ticks=0,drain_steal_ticks=1",
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
		if stored.SchemaVersion != 2 || stored.Measures[FactStealTicks] != 100 || len(stored.Measures) != len(counts) {
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
