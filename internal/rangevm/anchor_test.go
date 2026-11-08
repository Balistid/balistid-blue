package rangevm

import (
	"os"
	"regexp"
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

// Every path to PASS with a false fact gives MISS or INVALID, each for its own reason: the gap over the limit and no
// batch over the whole load miss, the gap at the limit passes; a load not shown whole, a gap not measured, a gap and
// count that do not fit or cannot cover the load, a fact missing, repeated or unknown are INVALID (ADR 0069, point 1).
func TestJudgeAnchor(t *testing.T) {
	tr := trial(t, "anchor-sustained")
	gap, batches := FactAnchorGapMS+"=", ";"+FactAnchorBatches+"="
	for _, c := range []struct{ change, want, reason string }{
		{"", Pass, "at most 900 ms between 700 batch entries"},
		{gap + "1000", Pass, "at most 1000 ms between 700 batch entries"},
		{gap + "1" + batches + "600000", Pass, "at most 1 ms between 600000 batch entries"}, // as many batches as the load has ms
		{gap + "1000" + batches + "599", Pass, "at most 1000 ms between 599 batch entries"}, // 600 spans of 1 s just cover 600 s
		{gap + "1001", Miss, "1001 ms without a batch entry, over 1000 ms; 700 batches"},
		{gap + "2100", Miss, "2100 ms without a batch entry, over 1000 ms; 700 batches"},
		{gap + "600000" + batches + "1", Miss, "600000 ms without a batch entry, over 1000 ms; 1 batches"}, // the whole load
		{FactMissing + "=1;" + FactStored + "=1199999", Invalid,
			"the rate load is not shown whole (MISS): generated 1200000, stored 1199999, missing 1, duplicate 0, outside 0"},
		{FactLostAfter + "=3", Invalid, "the rate load is not shown whole (MISS): audit lost 0 before, 3 after"},
		{FactOverflowAfter + "=yes", Invalid, "the rate load is not shown whole (MISS): the plugin queue overflowed"},
		{FactGenerated + "=1199990;" + FactStored + "=1199990;" + FactWindowMin + "=19999", Invalid, "the rate load is not shown whole (MISS): rate not held"},
		{FactStealWindows + "=" + windows(600, "300=1000:400:5"), Invalid, "the rate load is not shown whole (INVALID): host steal"},
		{FactFollow + "=the reader stopped", Invalid, "(INVALID): the reader did not see the whole run"},
		{FactTrial + "=rate-sustained", Invalid, "(INVALID): the guest ran another trial"},
		{FactKernel + "=6.1.0", Invalid, `(INVALID): guest kernel "6.1.0" is not the target`},
		{gap + "error: checkpoint: no file", Invalid, `the ledger's batches are not measured: gap "error: checkpoint: no file", batches "700"`},
		{FactAnchorBatches + "=error: bundle 3: short", Invalid, `not measured: gap "900", batches "error: bundle 3: short"`},
		{gap + "0900", Invalid, `not measured: gap "0900", batches "700"`},
		{gap + "600000" + batches + "0", Miss, "no batch entry during the 600 s load"},
		{gap + "600050" + batches + "0", Miss, "no batch entry during the 600 s load"}, // the window a little over the load
		{gap + "599999" + batches + "0", Miss, "no batch entry during the 600 s load"}, // the last event 0.5 ms before the end
		{gap + "599998" + batches + "0", Invalid, "a longest gap of 599998 ms between 0 batches does not cover a 600 s load"},
		{gap + "600100" + batches + "0", Miss, "no batch entry during the 600 s load"},
		{FactAnchorBatches + "=0", Invalid, "a longest gap of 900 ms between 0 batches does not cover a 600 s load"},
		{gap + "600101" + batches + "1", Invalid, "a gap of 600101 ms or 1 batches do not fit a 600 s load"},
		{gap + "600101" + batches + "0", Invalid, "a gap of 600101 ms or 0 batches do not fit a 600 s load"},
		{gap + "1" + batches + "600001", Invalid, "a gap of 1 ms or 600001 batches do not fit a 600 s load"},
		{gap + "900" + batches + "18446744073709551615", Invalid, "a gap of 900 ms or 18446744073709551615 batches do not fit"}, // wraps
		{gap + "100" + batches + "50", Invalid, "a longest gap of 100 ms between 50 batches does not cover a 600 s load"},
		{gap + "999" + batches + "599", Invalid, "a longest gap of 999 ms between 599 batches does not cover a 600 s load"},
		{gap + "1000" + batches + "598", Invalid, "a longest gap of 1000 ms between 598 batches does not cover a 600 s load"},
		{FactAnchorGapMS, Invalid, "report has 18 of 19 facts"},
		{FactAnchorBatches, Invalid, "report has 18 of 19 facts"},
		{FactStored, Invalid, "report has 18 of 19 facts"},
		{"+" + FactAnchorGapMS + "=900", Invalid, "fact anchor_gap_ms reported twice"},
		{"+anchor_gap_max_ms=900", Invalid, `unexpected fact "anchor_gap_max_ms"`},
	} {
		var change []string
		if c.change != "" {
			change = strings.Split(c.change, ";")
		}
		if v, r := JudgeTrial(tr, anchorRun(tr, change...), cleanBuild, cleanBuild); v != c.want || !hasReason(r, c.reason) {
			t.Errorf("%q: %s (%s), want %s (%s)", c.change, v, r, c.want, c.reason)
		}
	}
	// a guest's error is quoted up to 128 bytes, so a long one cannot flood the result
	long := "error: " + strings.Repeat("x", 200)
	if _, r := JudgeTrial(tr, anchorRun(tr, gap+long), cleanBuild, cleanBuild); !strings.Contains(r, `gap "`+long[:128]+`"`) {
		t.Errorf("a long gap error quoted as %s", r)
	}
	if _, r := JudgeTrial(tr, anchorRun(tr, FactAnchorBatches+"="+long), cleanBuild, cleanBuild); !strings.Contains(r, `batches "`+long[:128]+`"`) {
		t.Errorf("a long batches error quoted as %s", r)
	}
}

// The stall control misses only by its gap: its sound run without a stall passes, so the control's MISS shows the
// judge can MISS on a stalled ledger (ADR 0069, point 2); a stall that also lost records is INVALID, never a MISS.
func TestAnchorControlMissesOnlyByTheGap(t *testing.T) {
	tr := trial(t, "anchor-control-stall")
	gap, batches := FactAnchorGapMS+"=", ";"+FactAnchorBatches+"="
	for _, c := range []struct{ change, want, reason string }{
		{"", Pass, "at most 900 ms between 35 batch entries"},
		{FactAnchorGapMS + "=2100", Miss, "2100 ms without a batch entry, over 1000 ms; 35 batches"},
		{FactAnchorGapMS + "=2100;" + FactMissing + "=1;" + FactStored + "=2999", Invalid, "the rate load is not shown whole (MISS)"},
		{gap + "1000" + batches + "29", Pass, "at most 1000 ms between 29 batch entries"}, // 30 spans of 1 s just cover 30 s
		{gap + "1000" + batches + "28", Invalid, "a longest gap of 1000 ms between 28 batches does not cover a 30 s load"},
		{gap + "30000" + batches + "0", Miss, "no batch entry during the 30 s load"},
		{gap + "29990" + batches + "0", Miss, "no batch entry during the 30 s load"}, // the last event 10 ms before the end
		{gap + "29989" + batches + "0", Invalid, "a longest gap of 29989 ms between 0 batches does not cover a 30 s load"},
		{gap + "599999" + batches + "0", Invalid, "a gap of 599999 ms or 0 batches do not fit a 30 s load"},
	} {
		var change []string
		if c.change != "" {
			change = strings.Split(c.change, ";")
		}
		if v, r := JudgeTrial(tr, anchorRun(tr, change...), cleanBuild, cleanBuild); v != c.want || !hasReason(r, c.reason) {
			t.Errorf("%q: %s (%s), want %s (%s)", c.change, v, r, c.want, c.reason)
		}
	}
	if m := Measures(tr, anchorRun(tr, FactAnchorGapMS+"=2100")); m[FactAnchorGapMS] != 2100 || m[FactAnchorBatches] != 35 {
		t.Errorf("measures %v", m)
	}
}

// The judge's limit is acceptance anchor_interval_s.
func TestAnchorLimitIsTheAcceptance(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^id = "anchor_interval_s"\nmax = (\d+)\n`).FindSubmatch(data)
	if m == nil || string(m[1])+"000" != strconv.Itoa(anchorLimitMS) {
		t.Errorf("acceptance anchor_interval_s %q, the judge's limit %d ms", m, anchorLimitMS)
	}
}
