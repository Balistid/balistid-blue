package rangevm

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

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
	// FactTrialError replaces the counts when the guest could not run the trial; boot reports it.
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

// judgeRate judges a run of rate trial tr from an image built from commit image by a launcher built from
// commit launcher. The guest's facts form a closed set, each once, as plain values; anything else,
// another kernel or build, a reader that did not see the run's end, or steal over 1 % is INVALID.
// Loss, a changed audit lost counter, a plugin-queue overflow or a rate not held in every 10 s window
// is a MISS, so a control, whose reader drops one number, must come out MISS (ADR 0018, point 4).
func judgeRate(tr rangejob.Trial, o Outcome, launcher, image string) (verdict, reason string) {
	if o.Invalid != "" {
		return Invalid, o.Invalid
	}
	if launcher != image || !buildinfo.IsCommitID(launcher) {
		return Invalid, fmt.Sprintf("launcher is not a clean build of the image commit %s", image)
	}
	f := map[string]string{}
	for _, r := range o.Facts {
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

// ExpectedVerdict is what a sound run of tr gives: a control's Expect, else PASS.
func ExpectedVerdict(tr rangejob.Trial) string {
	if tr.Expect != "" {
		return tr.Expect
	}
	return Pass
}

// Measures of a trial run, kept beside its verdict so a margin can be read, not only a threshold
// that held: the guest's counts that are reported exactly once as plain numbers, and of a failure
// trial the host's marks and how long after the fail mark QEMU exited or the kill mark came.
const (
	MeasureH               = "h"
	MeasureSynced          = "synced"
	MeasureExitAfterFail   = "exit_after_fail_us"
	MeasureKilledAfterFail = "killed_after_fail_us"
)

// Measures returns the measures of a run of tr; a count missing, repeated or not a plain number is
// left out, never guessed (T30).
func Measures(tr rangejob.Trial, o Outcome) map[string]uint64 {
	names := counts
	if tr.Failure != "" {
		names = []string{FactStoredPrefix, FactStoredCount}
	}
	m := map[string]uint64{}
	for _, name := range names {
		var values []string
		for _, r := range o.Facts {
			if r.Name == name {
				values = append(values, r.Value)
			}
		}
		if len(values) != 1 {
			continue
		}
		if v, err := plainNumber(values[0]); err == nil {
			m[name] = v
		}
	}
	if tr.Failure == "" || o.Marks.Fail.IsZero() {
		return m
	}
	m[MeasureH], m[MeasureSynced] = o.Marks.H, o.Marks.Synced
	after := func(key string, t time.Time) {
		if d := t.Sub(o.Marks.Fail); !t.IsZero() && d >= 0 {
			m[key] = uint64(d / time.Microsecond)
		}
	}
	after(MeasureExitAfterFail, o.Marks.Exited)
	after(MeasureKilledAfterFail, o.Marks.Killed)
	return m
}

// Facts of a failure trial (ADR 0018, point 3): after a reset the second boot reports the scratch
// disk's superblock as it found it before mounting, and both kinds report the longest run 1..N of
// numbers the stored file holds and how many records it holds.
const (
	FactScratchJournal  = "scratch_journal"
	FactScratchRecovery = "scratch_recovery"
	FactStoredPrefix    = "stored_prefix"
	FactStoredCount     = "stored_count"
)

// JudgeTrial judges a run of tr: a rate trial by its counts, a failure trial by what survived.
func JudgeTrial(tr rangejob.Trial, o Outcome, launcher, image string) (verdict, reason string) {
	if tr.Failure != "" {
		return judgeFailure(tr, o, launcher, image)
	}
	return judgeRate(tr, o, launcher, image)
}

// judgeFailure: the host's marks, the closed facts of each boot, the target kernel and, after a
// reset, ext4 with a journal that still needed recovery are required, else INVALID. Every number up
// to H, the end of the contiguous numbers handed over 900 ms before the failure, must be stored,
// else MISS.
func judgeFailure(tr rangejob.Trial, o Outcome, launcher, image string) (string, string) {
	if o.Invalid != "" {
		return Invalid, o.Invalid
	}
	if launcher != image || !buildinfo.IsCommitID(launcher) {
		return Invalid, fmt.Sprintf("launcher is not a clean build of the image commit %s", image)
	}
	last := []string{FactTrial, FactPhase, FactKernel, FactStoredPrefix, FactStoredCount}
	if tr.Failure == FailReset {
		first, err := closedFacts(o.FirstBoot, []string{FactTrial, FactPhase, FactKernel, FactResetArmed})
		if err != nil {
			return Invalid, "first boot: " + err.Error()
		}
		if first[FactKernel] != TargetKernel {
			return Invalid, "first boot ran another kernel"
		}
		last = append(last, FactScratchJournal, FactScratchRecovery)
	}
	f, err := closedFacts(o.Facts, last)
	if err != nil {
		return Invalid, err.Error()
	}
	prefix, errP := plainNumber(f[FactStoredPrefix])
	count, errC := plainNumber(f[FactStoredCount])
	switch {
	case f[FactKernel] != TargetKernel:
		return Invalid, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	case errP != nil || errC != nil || count < prefix:
		return Invalid, "stored counts are not plain numbers that add up"
	case tr.Failure == FailReset && (f[FactScratchJournal] != "yes" || f[FactScratchRecovery] != "yes"):
		return Invalid, "the reset did not leave ext4 with a journal that needs recovery"
	case o.Marks.H == 0:
		return Invalid, "nothing was handed over in time to have to survive"
	case tr.Expect == Pass && o.Marks.Synced < o.Marks.H && prefix >= o.Marks.Synced:
		// The control's premise is a writer synced through H; a host that stalled its storage
		// broke the premise, not the file system. A number up to S lost is a real loss (ADR 0019).
		return Invalid, fmt.Sprintf("the writer had synced only through %d of H=%d", o.Marks.Synced, o.Marks.H)
	case prefix < max(o.Marks.H, o.Marks.Synced):
		// Everything handed over in time, and everything an fsync had returned for, must survive.
		return Miss, fmt.Sprintf("numbers up to %d (H=%d, synced %d) had to survive the %s; stored through %d",
			max(o.Marks.H, o.Marks.Synced), o.Marks.H, o.Marks.Synced, tr.Failure, prefix)
	}
	return Pass, fmt.Sprintf("every number up to %d (H=%d, synced %d) survived the %s (stored through %d)",
		max(o.Marks.H, o.Marks.Synced), o.Marks.H, o.Marks.Synced, tr.Failure, prefix)
}

// closedFacts maps facts that must be exactly names, each once.
func closedFacts(facts []Record, names []string) (map[string]string, error) {
	f := map[string]string{}
	for _, r := range facts {
		if !slices.Contains(names, r.Name) {
			return nil, fmt.Errorf("unexpected fact \"%s\"", Printable(r.Name, 64))
		}
		if _, dup := f[r.Name]; dup {
			return nil, fmt.Errorf("fact %s reported twice", r.Name)
		}
		f[r.Name] = r.Value
	}
	if len(f) != len(names) {
		return nil, fmt.Errorf("report has %d of %d facts", len(f), len(names))
	}
	return f, nil
}

// plainNumber is a canonical decimal.
func plainNumber(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, errors.New("not a plain number")
	}
	return v, nil
}
