package rangevm

import (
	"fmt"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a record trial (record_max_kib, ADR 0023 point 3): how each exec's record was stored ("whole",
// "truncated" or why neither), how many of the three malformed lines are stored, whether a stats record
// came after them, and what it and the store count as truncated and malformed before it.
const (
	FactRecord131K      = "record_131k"
	FactRecord2M        = "record_2m"
	FactRecord6M        = "record_6m"
	FactMalformedStored = "malformed_stored"
	FactStatsAfter      = "stats_after"
	FactStatsTruncated  = "stats_truncated"
	FactStoredTruncated = "stored_truncated"
	FactStatsMalformed  = "stats_malformed"
	FactStoredMalformed = "stored_malformed"

	RecordWhole     = "whole"
	RecordTruncated = "truncated"
	// MalformedLines is how many malformed lines a record trial sends: text, JSON without an ID and one
	// over the record limit.
	MalformedLines = 3
)

var recordFacts = []string{
	FactTrial, FactPhase, FactKernel, FactRecord131K, FactRecord2M, FactRecord6M, FactMalformedStored, FactStatsAfter,
	FactStatsTruncated, FactStoredTruncated, FactStatsMalformed, FactStoredMalformed,
}

// Facts of a refusal trial (refusal_summary_s, ADR 0023 point 4): connections each flooder made, what
// the refusal summaries count in all and under cause uid, how many there are, the longest from a
// summary's first refusal to its record, "ok" when each names its socket and rule version or the first
// field missing, and how many other health records came during the flood.
const (
	FactAttemptsRoot  = "attempts_root"
	FactAttemptsOther = "attempts_other"
	FactRefusedCount  = "refused_count"
	FactRefusedUID    = "refused_uid"
	FactSummaries     = "summaries"
	FactMaxLatencyMS  = "max_latency_ms"
	FactSummaryFields = "summary_fields"
	FactOtherRecords  = "other_records"
	// refusalLimitMS is a minute plus one tick of the collector (store.FlushEvery, ADR 0023 point 4).
	refusalLimitMS uint64 = 60_000 + 250
)

var refusalFacts = []string{
	FactTrial, FactPhase, FactKernel, FactAttemptsRoot, FactAttemptsOther, FactRefusedCount, FactRefusedUID, FactSummaries,
	FactMaxLatencyMS, FactSummaryFields, FactOtherRecords,
}

// probeFacts maps the closed facts of a one-boot run of tr on the target kernel, with nums plain numbers.
func probeFacts(tr rangejob.Trial, o Outcome, names, nums []string) (map[string]string, map[string]uint64, string) {
	f, err := closedFacts(o.Facts, names)
	if err != nil {
		return nil, nil, err.Error()
	}
	if f[FactTrial] != tr.Name {
		return nil, nil, "the guest ran another trial"
	}
	if f[FactKernel] != TargetKernel {
		return nil, nil, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	}
	n := map[string]uint64{}
	for _, name := range nums {
		if n[name], err = plainNumber(f[name]); err != nil {
			return nil, nil, fmt.Sprintf("fact %s is not a plain number", name)
		}
	}
	return f, n, ""
}

// judgeRecord: the 131 KB and 2 MB execs stored whole, the 6 MB one truncated, the three malformed lines
// stored, and a stats record after them counting every truncated and malformed record the store holds
// before it. Without a stats record after the lines the run is INVALID.
func judgeRecord(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, recordFacts, []string{FactMalformedStored, FactStatsTruncated, FactStoredTruncated,
		FactStatsMalformed, FactStoredMalformed})
	switch {
	case why != "":
		return Invalid, why
	case f[FactStatsAfter] != "yes":
		return Invalid, "no stats record after the malformed lines"
	case f[FactRecord131K] != RecordWhole || f[FactRecord2M] != RecordWhole:
		return Miss, fmt.Sprintf("records within the limit not stored whole: 131 KB %q, 2 MB %q",
			Printable(f[FactRecord131K], 64), Printable(f[FactRecord2M], 64))
	case f[FactRecord6M] != RecordTruncated:
		return Miss, fmt.Sprintf("the 6 MB record is %q, not truncated", Printable(f[FactRecord6M], 64))
	case n[FactMalformedStored] != MalformedLines:
		return Miss, fmt.Sprintf("%d of %d malformed lines stored", n[FactMalformedStored], MalformedLines)
	case n[FactStatsTruncated] != n[FactStoredTruncated] || n[FactStatsMalformed] != n[FactStoredMalformed]:
		return Miss, fmt.Sprintf("stats count %d truncated and %d malformed, the store holds %d and %d",
			n[FactStatsTruncated], n[FactStatsMalformed], n[FactStoredTruncated], n[FactStoredMalformed])
	case n[FactStoredTruncated] < 2 || n[FactStoredMalformed] < MalformedLines:
		return Invalid, "the store holds fewer truncated or malformed records than the trial stored"
	}
	return Pass, fmt.Sprintf("stored whole up to 2 MB, 6 MB truncated, %d truncated and %d malformed counted",
		n[FactStoredTruncated], n[FactStoredMalformed])
}

// judgeRefusal: each flooder must have made 99 % of its connections, else INVALID. Every connection
// must be counted once under cause uid, every summary name its socket and rule version and come at most
// a minute and one collector tick after its first refusal, at most two more summaries than minutes
// of flood, and no other health record during it, else MISS.
func judgeRefusal(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, refusalFacts, []string{FactAttemptsRoot, FactAttemptsOther, FactRefusedCount,
		FactRefusedUID, FactSummaries, FactMaxLatencyMS, FactOtherRecords})
	if why != "" {
		return Invalid, why
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) //nolint:gosec // positive table values
	attempts := n[FactAttemptsRoot] + n[FactAttemptsOther]
	switch {
	case 100*n[FactAttemptsRoot] < 99*planned || 100*n[FactAttemptsOther] < 99*planned:
		return Invalid, fmt.Sprintf("flooders made %d and %d of %d connections each", n[FactAttemptsRoot], n[FactAttemptsOther], planned)
	case n[FactRefusedCount] != attempts || n[FactRefusedUID] != attempts:
		return Miss, fmt.Sprintf("%d connections refused, summaries count %d, %d under cause uid", attempts,
			n[FactRefusedCount], n[FactRefusedUID])
	case f[FactSummaryFields] != "ok":
		return Miss, fmt.Sprintf("a refusal summary lacks %q", Printable(f[FactSummaryFields], 64))
	case n[FactSummaries] == 0 || n[FactSummaries] > uint64(tr.Load.Seconds)/60+2: //nolint:gosec // positive table value
		return Miss, fmt.Sprintf("%d refusal summaries for %d s of flood", n[FactSummaries], tr.Load.Seconds)
	case n[FactMaxLatencyMS] > refusalLimitMS:
		return Miss, fmt.Sprintf("a summary came %d ms after its first refusal, over %d", n[FactMaxLatencyMS], refusalLimitMS)
	case n[FactOtherRecords] > 0:
		return Miss, fmt.Sprintf("%d other health records during the flood", n[FactOtherRecords])
	}
	return Pass, fmt.Sprintf("%d refusals in %d summaries, at most %d ms after the first", attempts, n[FactSummaries], n[FactMaxLatencyMS])
}
