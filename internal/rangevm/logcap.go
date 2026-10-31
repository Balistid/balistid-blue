package rangevm

import (
	"fmt"
	"time"

	logentry "github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a log-cap trial (ADR 0036, point 5), besides an alarm trial's posts and watcher: the cap it set, in
// entries; when the ledger restarted with it and when the cosigned size reached the cap's UNKNOWN, on the
// guest's uptime in ms ("none" when it never did); the cosigned size at the end; whether the entry before the
// final slot is the cap's UNKNOWN, proven in the cosigned root; whether the ledger's journal summed a refusal
// for the cap; and the full entry bundles' count and their bytes on disk with their level-0 hash tiles.
const (
	FactCapEntries  = "cap_entries"
	FactRestartMS   = "restart_ms"
	FactCapMS       = "cap_ms"
	FactCosignedEnd = "cosigned_end"
	FactCapEntry    = "cap_entry"
	FactCapRefused  = "cap_refused"
	FactFullBundles = "full_bundles"
	FactFullBytes   = "full_bytes"

	// capAlarm is how soon after the cap's UNKNOWN is cosigned its alert must reach the sink: the Pi alerts on
	// an UNKNOWN at once, and loss_alarm_s's 120 s less the minute for delivery bound it (ADR 0036, point 1).
	capAlarm = 65 * time.Second
	// capEarly is how much earlier than the guest's 250 ms sample of the cosigned size the Pi may see it.
	capEarly = 5 * time.Second
	// bundleEntries is a full entry bundle's (Tessera's layout.EntryBundleWidth).
	bundleEntries = 256
)

var logCapFacts = []string{FactTrial, FactPhase, FactKernel, FactInject, FactCapEntries, FactRestartMS, FactCapMS, FactCosignedEnd,
	FactCapEntry, FactCapRefused, FactFullBundles, FactFullBytes, FactPosts, FactRefused, FactPiActive}

// judgeLogCap: the closed facts, the lowered cap set and reached, a full bundle to measure and the watcher's
// start through the sink, else INVALID. With those, a log grown past the cap's UNKNOWN, no such entry before the
// final slot, no refusal of the collector for the cap, full bundles over the bytes the cap counts per entry,
// or no unknown alert within capAlarm is a MISS.
func judgeLogCap(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, logCapFacts, []string{FactCapEntries, FactRestartMS, FactCosignedEnd, FactFullBundles,
		FactFullBytes, FactRefused})
	if why != "" {
		return Invalid, why
	}
	posts, err := ParsePosts(f[FactPosts])
	capMS, capErr := plainNumber(f[FactCapMS])
	start := firstPost(posts, "start", 0)
	switch {
	case err != nil:
		return Invalid, err.Error()
	case f[FactInject] != "ok":
		return Invalid, fmt.Sprintf("the cap was not lowered: \"%s\"", Printable(f[FactInject], 256))
	case capErr != nil:
		return Invalid, fmt.Sprintf("the log did not reach its lowered cap: \"%s\"", Printable(f[FactCapMS], 64))
	case n[FactCapEntries] < 3 || n[FactCosignedEnd] < n[FactCapEntries]-1 || capMS < n[FactRestartMS]:
		return Invalid, fmt.Sprintf("cap %d entries, cosigned %d, reached at %d ms before the restart at %d", n[FactCapEntries],
			n[FactCosignedEnd], capMS, n[FactRestartMS])
	case n[FactFullBundles] == 0:
		return Invalid, "no full bundle to measure"
	case f[FactPiActive] != "active":
		return Invalid, fmt.Sprintf("the watcher ended %s: the range stopped it", Printable(f[FactPiActive], 64))
	case start == nil || start.MS > n[FactRestartMS]:
		if n[FactRefused] > 0 {
			return Miss, fmt.Sprintf("the sink refused %d of the watcher's pushes: its token is not the range's", n[FactRefused])
		}
		return Invalid, "the sink saw no start of the watcher before the restart"
	case n[FactCosignedEnd] > n[FactCapEntries]-1:
		return Miss, fmt.Sprintf("the log grew to %d past its cap's UNKNOWN at %d", n[FactCosignedEnd], n[FactCapEntries]-2)
	case f[FactCapEntry] != "yes":
		return Miss, fmt.Sprintf("no UNKNOWN for the cap before the final slot: \"%s\"", Printable(f[FactCapEntry], 256))
	case f[FactCapRefused] != "yes":
		return Miss, fmt.Sprintf("the ledger summed no refusal for the cap: \"%s\"", Printable(f[FactCapRefused], 64))
	case n[FactFullBytes] > n[FactFullBundles]*bundleEntries*logentry.LogBytes:
		return Miss, fmt.Sprintf("%d full bundles take %d bytes, over %d a bundle", n[FactFullBundles], n[FactFullBytes],
			bundleEntries*logentry.LogBytes)
	}
	alarm := firstPost(posts, "unknown", max(capMS, n[FactRestartMS]+uint64(capEarly/time.Millisecond))-uint64(capEarly/time.Millisecond))
	if alarm == nil {
		return Miss, "no unknown alert reached the sink"
	}
	at := msDuration(max(alarm.MS, capMS) - capMS)
	if at > capAlarm {
		return Miss, fmt.Sprintf("unknown alert %s after the cap's UNKNOWN was cosigned, over %s", at, capAlarm)
	}
	return Pass, fmt.Sprintf("unknown alert %s after the cap's UNKNOWN was cosigned; %d full bundles in %d bytes", at,
		n[FactFullBundles], n[FactFullBytes])
}
