package rangevm

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// anchorRun is a sound anchor run of tr: the rate report with no loss, then gap and batches, changed by the given
// name=value pairs; a name alone drops that fact and "+name=value" adds one more.
func anchorRun(tr rangejob.Trial, change ...string) Outcome {
	batches := strconv.Itoa(tr.Load.Seconds * 7 / 6)
	o := report(tr)
	o.Facts = append(o.Facts, Record{Name: FactAnchorGapMS, Value: "900"}, Record{Name: FactAnchorBatches, Value: batches})
	for _, c := range change {
		k, v, set := strings.Cut(c, "=")
		if extra, ok := strings.CutPrefix(k, "+"); ok {
			o.Facts = append(o.Facts, Record{Name: extra, Value: v})
			continue
		}
		o.Facts = slices.DeleteFunc(o.Facts, func(r Record) bool { return r.Name == k && !set })
		for i := range o.Facts {
			if o.Facts[i].Name == k {
				o.Facts[i].Value = v
			}
		}
	}
	return o
}

// Every path to PASS with a false fact gives MISS or INVALID: the gap over the limit misses, at the limit passes;
// a load not shown whole, a gap not measured, no batch, a gap and count that cannot cover the load, a fact missing,
// repeated or unknown are INVALID (ADR 0069, point 1).
func TestJudgeAnchor(t *testing.T) {
	tr := trial(t, "anchor-sustained")
	for want, changes := range map[string][]string{
		Pass: {"", FactAnchorGapMS + "=1000", FactAnchorGapMS + "=1," + FactAnchorBatches + "=600000"},
		Miss: {FactAnchorGapMS + "=1001", FactAnchorGapMS + "=2100", FactAnchorGapMS + "=599000," + FactAnchorBatches + "=1"},
		Invalid: {
			FactMissing + "=1," + FactStored + "=1199999", // a loss during the run measured no recording
			FactLostAfter + "=3",
			FactOverflowAfter + "=yes",
			FactGenerated + "=1199990," + FactStored + "=1199990",                   // the rate not held
			FactStealWindows + "=" + windows(600, "300=1000:400:5"),                 // host steal
			FactFollow + "=the reader stopped",                                      // the store not read to the run's end
			FactAnchorGapMS + "=error: checkpoint: no file",                         // gap not measured
			FactAnchorBatches + "=error: bundle 3: short",                           // batches not counted
			FactAnchorBatches + "=0",                                                // no batch in the window
			FactAnchorGapMS + "=599500," + FactAnchorBatches + "=0",                 // no batch, a gap as long as the load
			FactAnchorGapMS + "=100," + FactAnchorBatches + "=50",                   // spans that do not cover the load
			FactAnchorGapMS + "=900," + FactAnchorBatches + "=18446744073709551615", // a count that wraps
			FactAnchorGapMS + "=600001," + FactAnchorBatches + "=1",                 // a gap longer than the load
			FactAnchorGapMS + "=0900",                                               // not plain
			FactAnchorGapMS,                                                         // missing
			FactAnchorBatches,                                                       // missing
			FactStored,                                                              // a rate fact missing
			"+" + FactAnchorGapMS + "=900",                                          // repeated
			"+anchor_gap_max_ms=900",                                                // unknown
			FactTrial + "=rate-sustained",                                           // another trial
			FactKernel + "=6.1.0",                                                   // another kernel
		},
	} {
		for _, c := range changes {
			var change []string
			if c != "" {
				change = strings.Split(c, ",")
			}
			if v, r := JudgeTrial(tr, anchorRun(tr, change...), cleanBuild, cleanBuild); v != want {
				t.Errorf("%q: %s (%s), want %s", c, v, r, want)
			}
		}
	}
}

// The stall control misses only by its gap: its sound run without a stall passes, so the control's MISS means the
// judge saw the 2 s (ADR 0069, point 2); a stall that also lost records is INVALID, never a MISS.
func TestAnchorControlMissesOnlyByTheGap(t *testing.T) {
	tr := trial(t, "anchor-control-stall")
	for c, want := range map[string]string{
		"":                        Pass,
		FactAnchorGapMS + "=2100": Miss,
		FactAnchorGapMS + "=2100," + FactMissing + "=1," + FactStored + "=2999": Invalid,
	} {
		var change []string
		if c != "" {
			change = strings.Split(c, ",")
		}
		if v, r := JudgeTrial(tr, anchorRun(tr, change...), cleanBuild, cleanBuild); v != want {
			t.Errorf("%q: %s (%s), want %s", c, v, r, want)
		}
	}
	if m := Measures(tr, anchorRun(tr, FactAnchorGapMS+"=2100")); m[FactAnchorGapMS] != 2100 || m[FactAnchorBatches] != 35 {
		t.Errorf("measures %v", m)
	}
}
