package rangevm

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of an RSS trial (rss_mib), besides the load's counts, the audit lost counter around it and "same" when
// no unit restarted: the units sampled, comma-separated; how many samples, one a second from before the load
// until it drained; the fewest processes any of those units held in a sample; the largest summed VmRSS of a
// sample in KiB; and the same of auditd's cgroup with Laurel, a trend never judged, a number or why not.
const (
	FactRSSUnits    = "rss_units"
	FactRSSSamples  = "rss_samples"
	FactRSSProcsMin = "rss_procs_min"
	FactRSSMaxKiB   = "rss_max_kib"
	FactRSSAuditKiB = "rss_auditd_max_kib"

	// rssLimitKiB is rss_mib's 256 MiB.
	rssLimitKiB = 256 << 10
)

var rssFacts = []string{
	FactTrial, FactPhase, FactKernel, FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter, FactUnits,
	FactRSSUnits, FactRSSSamples, FactRSSProcsMin, FactRSSMaxKiB, FactRSSAuditKiB,
}

// RSSUnits are the units rss_mib sums: the image's long-running Balistid Blue services, not the range's own
// and not the oneshots. One more or one fewer sampled makes an RSS trial INVALID.
func RSSUnits() map[string]bool {
	return map[string]bool{
		"balistid-collector.service": true, "balistid-auditstat.service": true, "balistid-ledger.service": true,
		"balistid-relay.service": true, "balistid-pi.service": true,
	}
}

// judgeRSS: exactly the RSSUnits sampled, each once and with a process in every sample, a sample for each
// second of the load, its rate held in every 10 s window, no record lost by the kernel and no unit restarted,
// else INVALID: a lighter load or a unit left out would understate the memory. A largest sum over 256 MiB is a
// MISS. The auditd trend must be reported but is never judged.
func judgeRSS(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, rssFacts, []string{FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter,
		FactRSSSamples, FactRSSProcsMin, FactRSSMaxKiB})
	if why != "" {
		return Invalid, why
	}
	sampled := strings.Split(f[FactRSSUnits], ",")
	units := map[string]bool{}
	for _, u := range sampled {
		units[u] = true
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) //nolint:gosec // positive table values
	switch {
	case len(sampled) != len(units) || !maps.Equal(units, RSSUnits()):
		return Invalid, fmt.Sprintf("sampled units \"%s\", want exactly %v", Printable(f[FactRSSUnits], 256),
			slices.Sorted(maps.Keys(RSSUnits())))
	case n[FactGenerated] != planned || n[FactWindowMin] < uint64(tr.Load.Rate)*10 || n[FactWindowMin] > n[FactGenerated]: //nolint:gosec // positive table value
		return Invalid, fmt.Sprintf("rate not held: generated %d of %d, %d in the slowest 10 s", n[FactGenerated], planned, n[FactWindowMin])
	case n[FactLostAfter] != n[FactLostBefore]:
		return Invalid, fmt.Sprintf("audit lost %d before the load, %d after", n[FactLostBefore], n[FactLostAfter])
	case f[FactUnits] != "same":
		return Invalid, fmt.Sprintf("units changed during the load: \"%s\"", Printable(f[FactUnits], 64))
	case n[FactRSSSamples] < uint64(tr.Load.Seconds): //nolint:gosec // positive table value
		return Invalid, fmt.Sprintf("%d samples over a %d s load", n[FactRSSSamples], tr.Load.Seconds)
	case n[FactRSSProcsMin] == 0:
		return Invalid, "a unit had no process in a sample"
	case n[FactRSSMaxKiB] == 0:
		return Invalid, "no resident memory read"
	case n[FactRSSMaxKiB] > rssLimitKiB:
		return Miss, fmt.Sprintf("%d KiB resident at most, over %d", n[FactRSSMaxKiB], rssLimitKiB)
	}
	return Pass, fmt.Sprintf("%d KiB resident at most over %d samples", n[FactRSSMaxKiB], n[FactRSSSamples])
}
