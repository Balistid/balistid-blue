package rangevm

import (
	"strings"
	"testing"
)

// probeRun is a one-boot report of trial name with facts in order, base values changed by name=value;
// a name without "=" is left out, an unknown name added.
func probeRun(name string, order []string, base map[string]string, change ...string) Outcome {
	values := map[string]string{FactTrial: name, FactPhase: "1", FactKernel: TargetKernel}
	for k, v := range base {
		values[k] = v
	}
	order = append([]string(nil), order...)
	for _, c := range change {
		k, v, set := strings.Cut(c, "=")
		if _, known := values[k]; set && !known {
			order = append(order, k)
		}
		if set {
			values[k] = v
		} else {
			delete(values, k)
		}
	}
	var o Outcome
	for _, k := range order {
		if v, ok := values[k]; ok {
			o.Facts = append(o.Facts, Record{Name: k, Value: v})
		}
	}
	return o
}

func judgeCases(t *testing.T, name string, run func(change ...string) Outcome, cases map[string][]string) {
	t.Helper()
	tr := trial(t, name)
	if v, r := JudgeTrial(tr, run(), cleanBuild, cleanBuild); v != Pass {
		t.Fatalf("%s sound run: %s (%s)", name, v, r)
	}
	for want, changes := range cases {
		for _, c := range changes {
			if v, r := JudgeTrial(tr, run(strings.Split(c, ",")...), cleanBuild, cleanBuild); v != want {
				t.Errorf("%s with %s: %s (%s); want %s", name, c, v, r, want)
			}
		}
	}
}

func TestJudgeRecord(t *testing.T) {
	base := map[string]string{
		FactRecord131K: RecordWhole, FactRecord2M: RecordWhole, FactRecord6M: RecordTruncated, FactMalformedStored: "3",
		FactStatsAfter: "yes", FactStatsTruncated: "2", FactStoredTruncated: "2", FactStatsMalformed: "3", FactStoredMalformed: "3",
	}
	run := func(change ...string) Outcome { return probeRun("record-max", recordFacts, base, change...) }
	judgeCases(t, "record-max", run, map[string][]string{
		Miss: {
			"record_131k=missing", "record_2m=truncated", "record_2m=cut", "record_6m=whole", "record_6m=missing",
			"malformed_stored=2", "malformed_stored=4", "stats_truncated=1", "stats_malformed=4",
			"stats_truncated=3,stored_truncated=3,stats_malformed=4,stored_malformed=4,record_6m=missing",
		},
		Invalid: {
			"stats_after=no", "stats_after=", "trial=refusal-flood", "stats_truncated=-1", "kernel=6.0.0", "record_6m", "canary=seen",
			"stored_truncated=1,stats_truncated=1", "stored_malformed=2,stats_malformed=2",
		},
		Pass: {"stats_truncated=5,stored_truncated=5", "stats_malformed=9,stored_malformed=9"},
	})
}

func TestJudgeRefusal(t *testing.T) {
	base := map[string]string{
		FactAttemptsRoot: "15000", FactAttemptsOther: "14900", FactRefusedCount: "29900", FactRefusedUID: "29900",
		FactSummaries: "4", FactMaxLatencyMS: "60250", FactSummaryFields: "ok", FactOtherRecords: "0",
	}
	run := func(change ...string) Outcome { return probeRun("refusal-flood", refusalFacts, base, change...) }
	judgeCases(t, "refusal-flood", run, map[string][]string{
		Miss: {
			"refused_count=29899", "refused_count=29901", "refused_uid=29899", "summary_fields=rule_version",
			"summaries=0", "summaries=5", "max_latency_ms=60251", "other_records=1",
		},
		Invalid: {
			"attempts_root=14849,refused_count=29749,refused_uid=29749", "attempts_other=0,refused_count=15000,refused_uid=15000",
			"summaries=x", "max_latency_ms", "kernel=6.0.0", "trial=record-max",
		},
		Pass: {"max_latency_ms=0", "summaries=1", "attempts_root=14850,refused_count=29750,refused_uid=29750"},
	})
}
