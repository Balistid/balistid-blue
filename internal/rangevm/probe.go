package rangevm

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

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
	FactLostRecords     = "lost_records"

	RecordWhole     = "whole"
	RecordTruncated = "truncated"
	// MalformedLines is how many malformed lines a record trial sends: text, JSON without an ID and one
	// over the record limit.
	MalformedLines = 3
)

var recordFacts = []string{
	FactTrial, FactPhase, FactKernel, FactRecord131K, FactRecord2M, FactRecord6M, FactMalformedStored, FactStatsAfter,
	FactStatsTruncated, FactStoredTruncated, FactStatsMalformed, FactStoredMalformed, FactLostRecords,
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
	// refusalLimitMS is a minute plus two ticks of the collector (store.FlushEvery): the tick the minute
	// ends in and the one whose flush stores the summary (ADR 0023 point 4).
	refusalLimitMS uint64 = 60_000 + 2*250
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

// judgeRecord: the 131 KB and 2 MB execs stored whole, the 6 MB one truncated with its length, head and
// tail, the three malformed lines stored exactly (the long one by head, tail, length and SHA-256), no
// loss record, and a stats record after them counting every truncated and malformed record the store
// holds before it. Without a stats record after the lines the run is INVALID.
func judgeRecord(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, recordFacts, []string{FactMalformedStored, FactStatsTruncated, FactStoredTruncated,
		FactStatsMalformed, FactStoredMalformed, FactLostRecords})
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
	case n[FactLostRecords] > 0:
		return Miss, fmt.Sprintf("%d loss records during the trial", n[FactLostRecords])
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

// judgeRefusal: each flooder must have made 99 % of its connections and no more than planned, else
// INVALID. Every connection must be counted once under cause uid, every summary be whole (socket, rule
// version, one cause) and stored at most a minute and two collector ticks after its first refusal, one
// summary for every minute of flood and at most two more, and no other health record during it, else
// MISS.
func judgeRefusal(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, refusalFacts, []string{FactAttemptsRoot, FactAttemptsOther, FactRefusedCount,
		FactRefusedUID, FactSummaries, FactMaxLatencyMS, FactOtherRecords})
	if why != "" {
		return Invalid, why
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) //nolint:gosec // positive table values
	minutes := (uint64(tr.Load.Seconds) + 59) / 60            //nolint:gosec // positive table value
	attempts := n[FactAttemptsRoot] + n[FactAttemptsOther]
	switch {
	case n[FactAttemptsRoot] > planned || n[FactAttemptsOther] > planned:
		return Invalid, fmt.Sprintf("flooders made %d and %d connections, more than the %d planned", n[FactAttemptsRoot], n[FactAttemptsOther], planned)
	case 100*n[FactAttemptsRoot] < 99*planned || 100*n[FactAttemptsOther] < 99*planned:
		return Invalid, fmt.Sprintf("flooders made %d and %d of %d connections each", n[FactAttemptsRoot], n[FactAttemptsOther], planned)
	case n[FactRefusedCount] != attempts || n[FactRefusedUID] != attempts:
		return Miss, fmt.Sprintf("%d connections refused, summaries count %d, %d under cause uid", attempts,
			n[FactRefusedCount], n[FactRefusedUID])
	case f[FactSummaryFields] != "ok":
		return Miss, fmt.Sprintf("a refusal summary lacks %q", Printable(f[FactSummaryFields], 64))
	case n[FactSummaries] < minutes || n[FactSummaries] > minutes+2:
		return Miss, fmt.Sprintf("%d refusal summaries for %d s of flood", n[FactSummaries], tr.Load.Seconds)
	case n[FactMaxLatencyMS] > refusalLimitMS:
		return Miss, fmt.Sprintf("a summary came %d ms after its first refusal, over %d", n[FactMaxLatencyMS], refusalLimitMS)
	case n[FactOtherRecords] > 0:
		return Miss, fmt.Sprintf("%d other health records during the flood", n[FactOtherRecords])
	}
	return Pass, fmt.Sprintf("%d refusals in %d summaries, at most %d ms after the first", attempts, n[FactSummaries], n[FactMaxLatencyMS])
}

// Facts of a ready trial (ready_s): ms from kernel start to the store's receipt of the first health
// record OK, or "none". Of an exposure trial (systemd_exposure): each service's overall exposure as
// systemd-analyze prints it, "unit=N.N" joined by commas. Of a CPU trial (cpu_cores), besides the load's counts and
// ticks: CPU µs of the collector's and of auditd's cgroup (auditd and Laurel) from before the load to
// its drain, and "same" when neither unit restarted in between, else what did.
const (
	FactReadyMS      = "ready_ms"
	FactExposure     = "exposure"
	FactCollectorUS  = "collector_usec"
	FactAuditdUS     = "auditd_usec"
	FactCollectorMem = "collector_memory_peak"
	FactUnits        = "units"

	readyLimitMS = 30_000
	// maxCores bounds what a CPU trial's counts may claim, so a report cannot overflow their sum.
	maxCores = 1024
	// exposureLimit is systemd_exposure's 2.5 in tenths.
	exposureLimit = 25
)

var (
	readyFacts    = []string{FactTrial, FactPhase, FactKernel, FactReadyMS}
	exposureFacts = []string{FactTrial, FactPhase, FactKernel, FactExposure}
	cpuFacts      = []string{FactTrial, FactPhase, FactKernel, FactGenerated, FactWindowMin, FactCPUTicks, FactStealTicks,
		FactCollectorUS, FactAuditdUS, FactUnits, FactStored, FactMissing}
	exposureValue = regexp.MustCompile(`^(balistid-[a-z0-9-]{1,64}\.service)=([0-9]{1,2})\.([0-9])$`)
)

// judgeReady: health OK within 30 s of kernel start; none, or later, is a MISS (the range runs only the
// smoke-tested target kernel, so UNKNOWN has no excuse).
func judgeReady(tr rangejob.Trial, o Outcome) (string, string) {
	f, _, why := probeFacts(tr, o, readyFacts, nil)
	if why != "" {
		return Invalid, why
	}
	if f[FactReadyMS] == "none" {
		return Miss, "no health record OK in the store"
	}
	ms, err := plainNumber(f[FactReadyMS])
	switch {
	case err != nil:
		return Invalid, fmt.Sprintf("ready time %q is not a plain number", Printable(f[FactReadyMS], 64))
	case ms > readyLimitMS:
		return Miss, fmt.Sprintf("health OK %d ms after kernel start, over %d", ms, readyLimitMS)
	}
	return Pass, fmt.Sprintf("health OK %d ms after kernel start", ms)
}

// ExposureUnits are the units systemd_exposure scores (ADR 0023 point 5): the floor-0 recorder's services
// in the range image, not the range runner's on the host. Every other service of the image is in
// UnscoredUnits; one in neither makes the exposure trial INVALID.
func ExposureUnits() map[string]bool {
	return map[string]bool{
		"balistid-collector.service": true, "balistid-ledger.service": true, "balistid-relay.service": true,
		"balistid-announce.service": true, "balistid-announce-suspend.service": true,
	}
}

// UnscoredUnits are the image's services that are not the host's: the range's own, and the Pi's, which run
// off the host (ADR 0031). balistid-auditstat, not in the image yet, has its own metric and joins neither set
// until it comes with its trial.
func UnscoredUnits() map[string]bool {
	return map[string]bool{
		"balistid-range-guest.service": true, "balistid-range-store.service": true,
		"balistid-range-ledger-key.service": true, "balistid-range-witness-key.service": true,
		"balistid-range-witness-agent.service": true, "balistid-range-witness.service": true,
		"balistid-pi.service": true, "balistid-pi-failed.service": true,
	}
}

// judgeExposure: exactly the ExposureUnits scored, each at most 2.5; a report not of the form
// "unit=N.N,..." or of another set of units is INVALID.
func judgeExposure(tr rangejob.Trial, o Outcome) (string, string) {
	f, _, why := probeFacts(tr, o, exposureFacts, nil)
	if why != "" {
		return Invalid, why
	}
	worst, worstUnit, seen := -1, "", map[string]bool{}
	for _, score := range strings.Split(f[FactExposure], ",") {
		m := exposureValue.FindStringSubmatch(score)
		if m == nil {
			return Invalid, fmt.Sprintf("exposure %q is not unit=N.N", Printable(score, 96))
		}
		if seen[m[1]] {
			return Invalid, fmt.Sprintf("exposure of %s reported twice", m[1])
		}
		whole, _ := strconv.Atoi(m[2])
		if tenths := whole*10 + int(m[3][0]-'0'); tenths > worst {
			worst, worstUnit = tenths, m[1]
		}
		seen[m[1]] = true
	}
	switch {
	case !maps.Equal(seen, ExposureUnits()):
		return Invalid, fmt.Sprintf("exposure of %d units, want exactly %v", len(seen), slices.Sorted(maps.Keys(ExposureUnits())))
	case worst > exposureLimit:
		return Miss, fmt.Sprintf("%s has exposure %d.%d, over 2.5", worstUnit, worst/10, worst%10)
	}
	return Pass, fmt.Sprintf("the worst unit, %s, has exposure %d.%d", worstUnit, worst/10, worst%10)
}

// judgeCPU: the load held its rate in every 10 s window, steal stayed within 1 %, neither unit restarted
// and every record was stored, else INVALID: a lighter or broken load would understate the cost. CPU of
// collector, auditd and Laurel over the load's seconds above 0.5 cores is a MISS.
func judgeCPU(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, cpuFacts, []string{FactGenerated, FactWindowMin, FactCPUTicks, FactStealTicks,
		FactCollectorUS, FactAuditdUS, FactStored, FactMissing})
	if why != "" {
		return Invalid, why
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds)                                                           //nolint:gosec // positive table values
	if limit := uint64(tr.Load.Seconds) * 1_000_000 * maxCores; n[FactCollectorUS] > limit || n[FactAuditdUS] > limit { //nolint:gosec // positive table value
		return Invalid, fmt.Sprintf("CPU of %d and %d µs is more than %d cores could use", n[FactCollectorUS], n[FactAuditdUS], maxCores)
	}
	used := n[FactCollectorUS] + n[FactAuditdUS]
	milli := used / uint64(tr.Load.Seconds) / 1000 //nolint:gosec // positive table value
	switch {
	case n[FactGenerated] != planned || n[FactWindowMin] < uint64(tr.Load.Rate)*10 || n[FactWindowMin] > n[FactGenerated]: //nolint:gosec // positive table value
		return Invalid, fmt.Sprintf("rate not held: generated %d of %d, %d in the slowest 10 s", n[FactGenerated], planned, n[FactWindowMin])
	case n[FactCPUTicks] == 0 || n[FactStealTicks] > n[FactCPUTicks]/100:
		return Invalid, fmt.Sprintf("guest steal over 1 %%: %d of %d ticks", n[FactStealTicks], n[FactCPUTicks])
	case f[FactUnits] != "same":
		return Invalid, fmt.Sprintf("units changed during the load: %q", Printable(f[FactUnits], 64))
	case n[FactMissing] != 0 || n[FactStored] != n[FactGenerated]:
		return Invalid, fmt.Sprintf("stored %d of %d, missing %d", n[FactStored], n[FactGenerated], n[FactMissing])
	case used*2 > uint64(tr.Load.Seconds)*1_000_000: //nolint:gosec // positive table value
		return Miss, fmt.Sprintf("%d.%03d cores at %d records/s, over 0.5", milli/1000, milli%1000, tr.Load.Rate)
	}
	return Pass, fmt.Sprintf("%d.%03d cores at %d records/s", milli/1000, milli%1000, tr.Load.Rate)
}
