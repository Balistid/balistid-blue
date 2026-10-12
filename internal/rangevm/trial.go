package rangevm

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Miss is a trial's verdict when the run was valid and the metric did not hold (ADR 0018, point 6).
const Miss = "MISS"

// Facts of a rate trial after its echo and kernel (ADR 0018, point 4). Counts are decimal; follow is
// "ok" only when the reader saw every record up to the canary that ends the run.
const (
	FactGenerated      = "generated"
	FactWindowMin      = "window_min"
	FactLostBefore     = "audit_lost_before"
	FactLostAfter      = "audit_lost_after"
	FactOverflowBefore = "overflow_before"
	FactOverflowAfter  = "overflow_after"
	FactCPUTicks       = "cpu_ticks"
	FactStealTicks     = "steal_ticks"
	FactDrainCPU       = "drain_cpu_ticks"
	FactDrainSteal     = "drain_steal_ticks"
	FactFollow         = "follow"
	FactStored         = "stored"
	FactMissing        = "missing"
	FactDuplicate      = "duplicate"
	FactOutside        = "outside"
	// FactTrialError replaces the counts when the guest could not run the trial.
	FactTrialError = "trial_error"
)

var rateFacts = []string{
	FactTrial, FactPhase, FactKernel, FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter,
	FactOverflowBefore, FactOverflowAfter, FactCPUTicks, FactStealTicks, FactDrainCPU, FactDrainSteal, FactFollow,
	FactStored, FactMissing, FactDuplicate, FactOutside,
}

// counts are the rate facts that must be plain decimal numbers.
var counts = []string{
	FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter, FactCPUTicks, FactStealTicks, FactDrainCPU,
	FactDrainSteal, FactStored, FactMissing, FactDuplicate, FactOutside,
}

// JudgeTrial judges a run of tr from an image built from commit image by a launcher built from
// commit launcher. The guest's facts form a closed set, each once, as plain values; anything else,
// another kernel or build, a reader that did not see the run's end, or steal over 1 % is INVALID.
// Loss, a changed audit lost counter, a plugin-queue overflow or a rate not held in every 10 s window
// is a MISS, so a control, whose reader drops one number, must come out MISS (ADR 0018, point 4).
func JudgeTrial(tr rangejob.Trial, o Outcome, launcher, image string) (verdict, reason string) {
	if o.Invalid != "" {
		return Invalid, o.Invalid
	}
	if launcher != image || !buildinfo.IsCommitID(launcher) {
		return Invalid, fmt.Sprintf("launcher is not a clean build of the image commit %s", image)
	}
	f := map[string]string{}
	for _, r := range o.Facts {
		if r.Name == FactTrialError {
			return Invalid, fmt.Sprintf("the guest could not run the trial: \"%s\"", Printable(r.Value, 256))
		}
		if !slices.Contains(rateFacts, r.Name) {
			return Invalid, fmt.Sprintf("unexpected fact \"%s\" in a trial report", Printable(r.Name, 64))
		}
		if _, dup := f[r.Name]; dup {
			return Invalid, fmt.Sprintf("fact %s reported twice", r.Name)
		}
		f[r.Name] = r.Value
	}
	if len(f) != len(rateFacts) {
		return Invalid, fmt.Sprintf("trial report has %d of %d facts", len(f), len(rateFacts))
	}
	n := map[string]uint64{}
	for _, name := range counts {
		v, err := strconv.ParseUint(f[name], 10, 64)
		if err != nil || strconv.FormatUint(v, 10) != f[name] {
			return Invalid, fmt.Sprintf("fact %s is not a plain number", name)
		}
		n[name] = v
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) //nolint:gosec // positive table values
	switch {
	case f[FactTrial] != tr.Name:
		return Invalid, "the guest ran another trial"
	case f[FactKernel] != TargetKernel:
		return Invalid, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	case f[FactFollow] != "ok":
		return Invalid, fmt.Sprintf("the reader did not see the whole run: \"%s\"", Printable(f[FactFollow], 256))
	case f[FactOverflowBefore] != "no" || (f[FactOverflowAfter] != "no" && f[FactOverflowAfter] != "yes"):
		return Invalid, "the plugin queue state is unknown"
	case n[FactCPUTicks] == 0 || n[FactStealTicks] > n[FactCPUTicks]/100 || n[FactDrainSteal] > n[FactDrainCPU]/100:
		return Invalid, fmt.Sprintf("guest steal over 1 %%: %d of %d ticks under load, %d of %d while draining",
			n[FactStealTicks], n[FactCPUTicks], n[FactDrainSteal], n[FactDrainCPU])
	case n[FactGenerated] == 0 || n[FactGenerated] > planned || n[FactStored] > n[FactGenerated] ||
		n[FactMissing] != n[FactGenerated]-n[FactStored]:
		return Invalid, fmt.Sprintf("generated %d of %d planned, stored %d and missing %d do not add up",
			n[FactGenerated], planned, n[FactStored], n[FactMissing])
	case n[FactWindowMin] > n[FactGenerated]/uint64(tr.Load.Seconds/10): //nolint:gosec // positive table value
		return Invalid, fmt.Sprintf("the slowest 10 s window holds %d of %d generated", n[FactWindowMin], n[FactGenerated])
	case n[FactLostAfter] < n[FactLostBefore]:
		return Invalid, "the audit lost counter went backwards"
	}
	loss := fmt.Sprintf("generated %d, stored %d, missing %d, duplicate %d, outside %d",
		n[FactGenerated], n[FactStored], n[FactMissing], n[FactDuplicate], n[FactOutside])
	switch {
	case n[FactMissing] > 0 || n[FactDuplicate] > 0 || n[FactOutside] > 0:
		return Miss, loss
	case n[FactLostAfter] != n[FactLostBefore]:
		return Miss, fmt.Sprintf("audit lost %d before, %d after", n[FactLostBefore], n[FactLostAfter])
	case f[FactOverflowAfter] == "yes":
		return Miss, "the plugin queue overflowed"
	case n[FactGenerated] < planned || n[FactWindowMin] < uint64(tr.Load.Rate)*10: //nolint:gosec // positive table value
		return Miss, fmt.Sprintf("rate not held: generated %d of %d, %d in the slowest 10 s", n[FactGenerated], planned, n[FactWindowMin])
	}
	return Pass, loss
}

// ExpectedVerdict is what a sound run of tr gives: MISS for a control, else PASS.
func ExpectedVerdict(tr rangejob.Trial) string {
	if tr.Load.Drop {
		return Miss
	}
	return Pass
}
