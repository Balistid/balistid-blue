package rangevm

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of an RSS trial (rss_mib, ADR 0054), besides the load's counts, the audit lost counter and auditd's
// overflow flag around it, the store's loss records and "same" when no unit restarted: "ok" or why the run is not
// whole; the units sampled, comma-separated; how many samples, one a second from before the load until it drained,
// and the longest time in ms no sample covered of the load; the fewest processes any unit held in a sample; the
// largest summed VmRSS of a sample and the summed VmHWM at the end, in KiB; the OOM events of the units' cgroups;
// the collector's -queue-bytes; the largest sum of auditd's cgroup with Laurel, a trend, a number or why not; and of
// the OOM control alone, else RSSNone, when in ns it lowered OOMControlUnit's MemoryMax or why not, and that unit's
// OOM events before it.
const (
	FactRSSRun        = "rss_run"
	FactRSSUnits      = "rss_units"
	FactRSSSamples    = "rss_samples"
	FactRSSLoadGapMS  = "rss_load_gap_ms"
	FactRSSProcsMin   = "rss_procs_min"
	FactRSSMaxKiB     = "rss_max_kib"
	FactRSSHWMKiB     = "rss_hwm_kib"
	FactRSSOOM        = "rss_oom"
	FactRSSQueueBytes = "rss_queue_bytes"
	FactRSSAuditKiB   = "rss_auditd_max_kib"
	FactRSSInjected   = "rss_injected"
	FactRSSOOMBefore  = "rss_oom_before"
	RSSNone           = "none"
)

// OOMControlUnit is the unit rss-oom-control OOM-kills, neither sampled nor waited for in that trial: it proves the
// OOM path, not memory.
const OOMControlUnit = "balistid-ledger.service"

// CollectorQueueBytes is collector.QueueBytes, the queue the shipped collector holds; the range runs a smaller one
// (ADR 0039, point 2). The judge does not link the collector; a test pins the two.
const CollectorQueueBytes = 64 << 20

const (
	// rssLimitKiB is rss_mib's 256 MiB.
	rssLimitKiB = 256 << 10
	// rssLoadGapMS is the longest the load may go unsampled: two of the guest's 1 s intervals.
	rssLoadGapMS = 2_000
)

var rssFacts = []string{
	FactTrial, FactPhase, FactKernel, FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter, FactOverflowBefore,
	FactOverflowAfter, FactLostRecords, FactUnits, FactRSSRun, FactRSSUnits, FactRSSSamples, FactRSSLoadGapMS,
	FactRSSProcsMin, FactRSSMaxKiB, FactRSSHWMKiB, FactRSSOOM, FactRSSQueueBytes, FactRSSAuditKiB, FactRSSInjected,
	FactRSSOOMBefore,
}

// rssCounts are the RSS facts that must be plain numbers.
var rssCounts = []string{
	FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter, FactLostRecords, FactRSSSamples, FactRSSLoadGapMS,
	FactRSSProcsMin, FactRSSMaxKiB, FactRSSHWMKiB, FactRSSOOM, FactRSSQueueBytes,
}

// RSSUnits are the units rss_mib sums: the image's long-running Balistid Blue services, and litewitness with
// the agent's stand-in, which local mode runs on the host (ADR 0043); not the oneshots. One more or one fewer
// sampled makes an RSS trial INVALID.
func RSSUnits() map[string]bool {
	return map[string]bool{
		"balistid-collector.service": true, "balistid-auditstat.service": true, "balistid-ledger.service": true,
		"balistid-relay.service": true, "balistid-pi.service": true, "balistid-range-witness.service": true,
		"balistid-range-witness-agent.service": true,
	}
}

// judgeRSS: an OOM event in a unit's cgroup, or a peak over 256 MiB, is a MISS whatever else the report shows. The
// peak is the larger of the sampled sum and the summed VmHWM, plus the queue the shipped collector holds beyond the
// range's. Otherwise exactly the RSSUnits sampled, each with a process in every sample, the load covered by samples
// at most 2 s apart and its rate held in every 10 s window, no record dropped by the kernel, auditd's dispatcher, the
// collector or the store, and no unit restarted, else INVALID: a lighter load or a unit left out would understate
// the memory. The auditd trend must be reported but is never judged.
func judgeRSS(tr rangejob.Trial, o Outcome) (string, string) {
	f, missing, why := knownFacts(tr, o, rssFacts)
	if why != "" {
		return Invalid, why
	}
	var misses, unproven []string
	bad := func(format string, a ...any) { unproven = append(unproven, fmt.Sprintf(format, a...)) }
	if missing != "" {
		bad("%s", missing)
	}
	n := map[string]uint64{}
	for _, name := range rssCounts {
		v, err := plainNumber(f[name])
		if err != nil {
			bad("fact %s is not a plain number: \"%s\"", name, Printable(f[name], 256))
			continue
		}
		n[name] = v
	}
	_, queueRead := n[FactRSSQueueBytes]
	if queueRead && n[FactRSSQueueBytes] > CollectorQueueBytes {
		bad("the collector's queue of %d bytes is over the shipped %d", n[FactRSSQueueBytes], CollectorQueueBytes)
		queueRead = false
	}
	queueKiB := uint64(0)
	if queueRead {
		queueKiB = (CollectorQueueBytes - n[FactRSSQueueBytes] + 1023) >> 10
	}
	if tr.Inject == rangejob.InjectOOM {
		return oomControl(tr, f, n, unproven)
	}
	if f[FactRSSInjected] != RSSNone || f[FactRSSOOMBefore] != RSSNone {
		bad("an injection in a trial without one: \"%s\", \"%s\"", Printable(f[FactRSSInjected], 64), Printable(f[FactRSSOOMBefore], 64))
	}
	peak := max(n[FactRSSMaxKiB], n[FactRSSHWMKiB])
	if n[FactRSSOOM] > 0 {
		misses = append(misses, fmt.Sprintf("%d OOM events in the units' cgroups", n[FactRSSOOM]))
	}
	if peak > rssLimitKiB || queueKiB > rssLimitKiB-peak {
		misses = append(misses, fmt.Sprintf("%d KiB resident at most and %d KiB of the shipped collector's larger queue, over %d",
			peak, queueKiB, rssLimitKiB))
	}
	if len(misses) > 0 {
		return Miss, strings.Join(misses, "; ")
	}
	rssUnproven(tr, f, n, RSSUnits(), bad)
	if len(unproven) > 0 {
		return Invalid, strings.Join(unproven, "; ")
	}
	return Pass, fmt.Sprintf("%d KiB at most with %d KiB of the shipped queue over %d samples", peak, queueKiB,
		n[FactRSSSamples])
}

// rssUnproven calls bad for each reason an RSS run proves nothing: another set of units, a run not whole, a load not
// held or not delivered, a restart, too few samples or a gap in them, a unit without a process or no memory read.
func rssUnproven(tr rangejob.Trial, f map[string]string, n map[string]uint64, want map[string]bool, bad func(string, ...any)) {
	sampled := strings.Split(f[FactRSSUnits], ",")
	units := map[string]bool{}
	for _, u := range sampled {
		units[u] = true
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) //nolint:gosec // positive table values
	if len(sampled) != len(units) || !maps.Equal(units, want) {
		bad("sampled units \"%s\", want exactly %v", Printable(f[FactRSSUnits], 256), slices.Sorted(maps.Keys(want)))
	}
	if f[FactRSSRun] != "ok" {
		bad("the run: \"%s\"", Printable(f[FactRSSRun], 256))
	}
	if n[FactGenerated] != planned || n[FactWindowMin] < uint64(tr.Load.Rate)*10 || n[FactWindowMin] > n[FactGenerated] { //nolint:gosec // positive table value
		bad("rate not held: generated %d of %d, %d in the slowest 10 s", n[FactGenerated], planned, n[FactWindowMin])
	}
	if n[FactLostAfter] != n[FactLostBefore] {
		bad("audit lost %d before the load, %d after", n[FactLostBefore], n[FactLostAfter])
	}
	if f[FactOverflowBefore] != "no" || f[FactOverflowAfter] != "no" {
		bad("the dispatcher's overflow flag read \"%s\" before the load and \"%s\" after", Printable(f[FactOverflowBefore], 16),
			Printable(f[FactOverflowAfter], 16))
	}
	if n[FactLostRecords] > 0 {
		bad("%d loss records: the collector or the store dropped part of the load", n[FactLostRecords])
	}
	if f[FactUnits] != "same" {
		bad("units changed during the load: \"%s\"", Printable(f[FactUnits], 64))
	}
	if n[FactRSSSamples] < uint64(tr.Load.Seconds) { //nolint:gosec // positive table value
		bad("%d samples over a %d s load", n[FactRSSSamples], tr.Load.Seconds)
	}
	if n[FactRSSLoadGapMS] > rssLoadGapMS {
		bad("%d ms of the load without a sample, over %d", n[FactRSSLoadGapMS], rssLoadGapMS)
	}
	if n[FactRSSProcsMin] == 0 {
		bad("a unit had no process in a sample")
	}
	if n[FactRSSMaxKiB] == 0 || n[FactRSSHWMKiB] == 0 {
		bad("no resident memory read: %d KiB sampled, %d KiB of peaks", n[FactRSSMaxKiB], n[FactRSSHWMKiB])
	}
}

// oomControl judges rss-oom-control from evidence of its own injection only: a whole run of the other units, as an
// RSS trial must be, the injection proven by its time, no OOM event of OOMControlUnit before it, and then one after
// it, the expected MISS. Anything missing or failed is INVALID, never that MISS; peaks are not looked at.
func oomControl(tr rangejob.Trial, f map[string]string, n map[string]uint64, unproven []string) (string, string) {
	bad := func(format string, a ...any) { unproven = append(unproven, fmt.Sprintf(format, a...)) }
	others := RSSUnits()
	delete(others, OOMControlUnit)
	rssUnproven(tr, f, n, others, bad)
	if at, err := plainNumber(f[FactRSSInjected]); err != nil || at == 0 {
		bad("the OOM injection is not proven: \"%s\"", Printable(f[FactRSSInjected], 256))
	}
	if f[FactRSSOOMBefore] != "0" {
		bad("OOM events of %s before the injection: \"%s\"", OOMControlUnit, Printable(f[FactRSSOOMBefore], 256))
	}
	switch {
	case len(unproven) > 0:
		return Invalid, strings.Join(unproven, "; ")
	case n[FactRSSOOM] == 0:
		return Invalid, "no OOM event of " + OOMControlUnit + " after the injection"
	}
	return Miss, fmt.Sprintf("%d OOM events of %s after the injection", n[FactRSSOOM], OOMControlUnit)
}
