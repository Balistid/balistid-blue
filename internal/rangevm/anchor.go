package rangevm

import (
	"fmt"
	"slices"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of an anchor trial (anchor_interval_s, ADR 0069) after a rate trial's: the longest time in ms, rounded up,
// without a batch entry in the ledger's log from the load's start to its end, both ends counted, and how many batch
// entries were stamped in between; each "error: ..." when the log could not be read.
const (
	FactAnchorGapMS   = "anchor_gap_ms"
	FactAnchorBatches = "anchor_batches"
)

// anchorLimitMS is anchor_interval_s: 1 s between batch entries while recording.
const anchorLimitMS = 1000

// anchorLateMS is how late the load's last event may come and still count (rangeguest's grace, ADR 0019).
const anchorLateMS = 100

var anchorFacts = append(slices.Clone(rateFacts), FactAnchorGapMS, FactAnchorBatches)

// judgeAnchor: the closed facts, a rate run that passes its own judge, a gap and batch count that are plain numbers
// and gaps that cover the load, else INVALID: a load not held or with any loss measured no recording. With those, no
// batch entry over the whole load or a gap over anchorLimitMS is a MISS.
func judgeAnchor(tr rangejob.Trial, o Outcome) (string, string) {
	f, err := closedFacts(o.Facts, anchorFacts)
	if err != nil {
		return Invalid, err.Error()
	}
	rate := Outcome{Facts: slices.DeleteFunc(slices.Clone(o.Facts), func(r Record) bool {
		return r.Name == FactAnchorGapMS || r.Name == FactAnchorBatches
	})}
	if v, why := judgeRate(tr, rate); v != Pass {
		return Invalid, fmt.Sprintf("the rate load is not shown whole (%s): %s", v, why)
	}
	gap, errG := plainNumber(f[FactAnchorGapMS])
	batches, errB := plainNumber(f[FactAnchorBatches])
	loadMS := uint64(tr.Load.Seconds) * 1000 //nolint:gosec // positive table value
	windowMS := anchorWindowMS(loadMS, tr.Load.Rate)
	switch {
	case errG != nil || errB != nil:
		return Invalid, fmt.Sprintf("the ledger's batches are not measured: gap \"%s\", batches \"%s\"",
			Printable(f[FactAnchorGapMS], 128), Printable(f[FactAnchorBatches], 128))
	case gap > loadMS+anchorLateMS || batches > loadMS:
		return Invalid, fmt.Sprintf("a gap of %d ms or %d batches do not fit a %d s load", gap, batches, tr.Load.Seconds)
	case (batches+1)*gap < windowMS:
		// batches+1 rounded-up spans cover the window from the first event to the last, one interval short of the load
		return Invalid, fmt.Sprintf("a longest gap of %d ms between %d batches does not cover a %d s load", gap, batches, tr.Load.Seconds)
	case batches == 0:
		return Miss, fmt.Sprintf("no batch entry during the %d s load", tr.Load.Seconds)
	case gap > anchorLimitMS:
		return Miss, fmt.Sprintf("%d ms without a batch entry, over %d ms; %d batches", gap, anchorLimitMS, batches)
	}
	return Pass, fmt.Sprintf("at most %d ms between %d batch entries", gap, batches)
}

// anchorWindowMS is the generator's shortest window: the load less one interval between events, rounded down because
// the guest rounds gaps up.
func anchorWindowMS(loadMS uint64, rate int) uint64 {
	return loadMS - uint64(1000/rate) //nolint:gosec // positive table value
}
