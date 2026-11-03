package rangevm

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a canary trial (canary_interval_s, ADR 0017): how long the quiet phase lasted, how many of the
// collector's canaries went out in it by their audit time, and the longest time without one, the phase's start
// and end included. Each frozen stage adds the facts CanaryFact names.
const (
	FactCanaryQuietMS = "canary_quiet_ms"
	FactCanaryCount   = "canary_count"
	FactCanaryGapMS   = "canary_max_gap_ms"
)

// What a canary trial reports of each stage it froze: "yes" when the process was stopped a second after SIGSTOP
// and right before SIGCONT, or why not; the store's health when the freeze began; how long it was frozen and
// how long the guest watched after SIGCONT; and, each in ms or CanaryNone, when the first canary went out and
// the first "UNKNOWN canary-missed" came after the freeze began, and the first OK after SIGCONT.
const (
	CanaryStopped   = "stopped"
	CanaryHealth    = "health"
	CanaryFrozenMS  = "frozen_ms"
	CanaryAfterMS   = "after_ms"
	CanaryFirstMS   = "first_ms"
	CanaryUnknownMS = "unknown_ms"
	CanaryOKMS      = "ok_ms"
	CanaryNone      = "none"
)

// How long a canary trial's guest keeps each phase. Quiet, five intervals show four canaries at least. Frozen,
// the first probe after SIGSTOP goes out within 30 s and it and the next each have 30 s: two misses within 90 s.
// After SIGCONT, longer than canaryRecoverMS.
const (
	CanaryQuiet  = 150 * time.Second
	CanaryFreeze = 100 * time.Second
	CanaryAfter  = 45 * time.Second
)

// The judge's bounds. canaryGapMS is canary_interval_s. UNKNOWN comes within the deadlines of two probes from
// the first sent while frozen, plus the writer's ticks (250 ms each). OK comes back within the next probe after
// SIGCONT (30 s), Laurel's hold of 7 s and two ticks; auditd's state, written every 5 s, is fresh within that.
const (
	canaryGapMS       = 30_000
	canaryQuietMS     = uint64(CanaryQuiet / time.Millisecond)
	canaryMinSeen     = 4
	canaryFreezeMinMS = 3*canaryGapMS + 1_000
	canaryUnknownMS   = 2*canaryGapMS + 1_000
	canaryRecoverMS   = 40_000
)

// CanaryStage is a stage a canary trial drops canaries at, frozen as a status trial freezes it.
type CanaryStage struct{ Name, Kind string }

// CanaryStages are Laurel and then auditd. The kernel is no stage: the rules are locked with -e 2, so nothing
// can drop the canary's rule there.
func CanaryStages() []CanaryStage {
	return []CanaryStage{{"laurel", StatusFreezeLaurel}, {"auditd", StatusFreezeAuditd}}
}

// CanaryFact is the fact of what a canary trial reports of stage.
func CanaryFact(stage, what string) string { return "canary_" + stage + "_" + what }

func canaryFacts() []string {
	names := []string{FactTrial, FactPhase, FactKernel, FactCanaryQuietMS, FactCanaryCount, FactCanaryGapMS}
	for _, s := range CanaryStages() {
		for _, what := range []string{CanaryStopped, CanaryHealth, CanaryFrozenMS, CanaryAfterMS, CanaryFirstMS,
			CanaryUnknownMS, CanaryOKMS} {
			names = append(names, CanaryFact(s.Name, what))
		}
	}
	return names
}

// judgeCanary judges a canary trial. The facts are closed and on the target kernel, else INVALID. A gap over
// 30 s in the quiet phase, a freeze without "UNKNOWN canary-missed" or with it late, or no OK in time after it
// is a MISS. A quiet phase too short or with too few canaries for its gaps, or a stage whose freeze is not proven
// or did not begin OK, is INVALID; as in judgeStatus, no INVALID hides a MISS another part shows.
func judgeCanary(tr rangejob.Trial, o Outcome) (string, string) {
	f, _, why := probeFacts(tr, o, canaryFacts(), nil)
	if why != "" {
		return Invalid, why
	}
	var misses, unproven []string
	note := func(why string, invalid bool) {
		switch {
		case invalid:
			unproven = append(unproven, why)
		case why != "":
			misses = append(misses, why)
		}
	}
	note(quietCanaries(f))
	for _, s := range CanaryStages() {
		why, invalid := frozenStage(s.Name, f)
		if why != "" {
			why = s.Name + ": " + why
		}
		note(why, invalid)
	}
	switch {
	case len(misses) > 0:
		return Miss, strings.Join(misses, "; ")
	case len(unproven) > 0:
		return Invalid, strings.Join(unproven, "; ")
	}
	return Pass, fmt.Sprintf("%s canaries at most %s ms apart; UNKNOWN while Laurel and auditd were frozen, then OK",
		f[FactCanaryCount], f[FactCanaryGapMS])
}

// quietCanaries is why the quiet phase is a MISS, or proves nothing (invalid), or "". n canaries leave n+1
// gaps that cover the phase, so a run without a long gap has four canaries in 150 s.
func quietCanaries(f map[string]string) (string, bool) {
	quiet, errQ := plainNumber(f[FactCanaryQuietMS])
	count, errC := plainNumber(f[FactCanaryCount])
	gap, errG := plainNumber(f[FactCanaryGapMS])
	switch {
	case errG == nil && gap > canaryGapMS:
		return fmt.Sprintf("%d ms without a canary, over %d", gap, canaryGapMS), false
	case errQ != nil || errC != nil || errG != nil:
		return "a quiet phase's count is not a plain number", true
	case quiet < canaryQuietMS:
		return fmt.Sprintf("a quiet phase of %d ms, under %d", quiet, canaryQuietMS), true
	case count < canaryMinSeen || !covers(count, gap, quiet):
		return fmt.Sprintf("%d canaries at most %d ms apart cannot cover a quiet phase of %d ms", count, gap, quiet), true
	}
	return "", false
}

// covers reports whether count+1 gaps of at most gap ms can span quiet ms, without overflow.
func covers(count, gap, quiet uint64) bool {
	hi, lo := bits.Mul64(count+1, gap)
	return count+1 != 0 && (hi != 0 || lo >= quiet)
}

// frozenStage is why a stage's freeze is a MISS, or proves nothing (invalid), or "". A freeze not proven, not
// begun OK, shorter than two misses or watched less than the recovery after it proves nothing; a canary none
// went out in proves nothing of when UNKNOWN came, but a freeze without UNKNOWN misses whatever its canaries.
func frozenStage(stage string, f map[string]string) (string, bool) {
	v := func(what string) string { return f[CanaryFact(stage, what)] }
	frozen, errF := msOrNone(v(CanaryFrozenMS)) // none is under the minimum below
	after, errA := msOrNone(v(CanaryAfterMS))
	first, errFirst := msOrNone(v(CanaryFirstMS))
	unknown, errU := msOrNone(v(CanaryUnknownMS))
	ok, errO := msOrNone(v(CanaryOKMS))
	switch {
	case v(CanaryStopped) != "yes":
		return fmt.Sprintf("the freeze is not proven: \"%s\"", Printable(v(CanaryStopped), 256)), true
	case v(CanaryHealth) != StoreOK:
		return fmt.Sprintf("the store's health when the freeze began was \"%s\"", Printable(v(CanaryHealth), 32)), true
	case errF != nil || errA != nil || errFirst != nil || errU != nil || errO != nil:
		return "a time is not a plain number or none", true
	case frozen < canaryFreezeMinMS || after < canaryRecoverMS:
		return fmt.Sprintf("frozen %d ms and watched %d ms after, under %d and %d", frozen, after, canaryFreezeMinMS,
			canaryRecoverMS), true
	case unknown < 0 || unknown > frozen:
		return fmt.Sprintf("no UNKNOWN canary-missed in %d ms frozen", frozen), false
	case first < 0 || first > frozen:
		return "no canary went out while frozen, so its UNKNOWN is not timed", true
	case unknown > first+canaryUnknownMS:
		return fmt.Sprintf("UNKNOWN %d ms after the first canary sent while frozen, over %d", unknown-first,
			canaryUnknownMS), false
	case ok < 0 || ok > after:
		return fmt.Sprintf("no OK in the %d ms after SIGCONT", after), false
	case ok > canaryRecoverMS:
		return fmt.Sprintf("OK %d ms after SIGCONT, over %d", ok, canaryRecoverMS), false
	}
	return "", false
}

// msOrNone is a plain number of ms, or -1 for CanaryNone.
func msOrNone(s string) (int64, error) {
	if s == CanaryNone {
		return -1, nil
	}
	n, err := plainNumber(s)
	if err != nil || n > math.MaxInt64/2 {
		return 0, errors.New("not a time in ms")
	}
	return int64(n), nil
}
