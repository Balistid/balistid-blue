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

// Facts of a canary trial (canary_interval_s, ADR 0017, ADR 0054): how long the quiet phase lasted, the store's
// health over it, how many of the collector's canaries went out in it by their audit time, and the longest time
// without one, the phase's start and end included. Each frozen stage adds the facts CanaryFact names.
const (
	FactCanaryQuietMS     = "canary_quiet_ms"
	FactCanaryQuietHealth = "canary_quiet_health"
	FactCanaryCount       = "canary_count"
	FactCanaryGapMS       = "canary_max_gap_ms"
)

// What a canary trial reports of each stage it froze: "yes" when the process was stopped a second after SIGSTOP
// and right before SIGCONT, or why not; the store's health when the freeze began, and from the first "UNKNOWN
// canary-missed" to SIGCONT (CanaryNone without one); how long it was frozen and how long the guest watched after
// SIGCONT; and, each in ms or CanaryNone, when the first canary went out and the first UNKNOWN canary-missed came
// after the freeze began, and the first OK after SIGCONT.
const (
	CanaryStopped   = "stopped"
	CanaryHealth    = "health"
	CanaryHeld      = "held"
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

// The judge's bounds. canaryGapMS is canary_interval_s, also the latest the first probe of a freeze may go out.
// UNKNOWN comes within the deadlines of two probes from that first one, plus the writer's ticks (250 ms each), so a
// freeze of canaryFreezeMinMS holds both; it comes no earlier than the first probe's own deadline, the collector's
// CanaryEvery of 29 s less a second, or a probe missed before the freeze caused it. OK comes back within the next
// probe after SIGCONT (30 s), Laurel's hold of 7 s and two ticks; auditd's state, written every 5 s, is fresh then.
const (
	canaryGapMS       = 30_000
	canaryQuietMS     = uint64(CanaryQuiet / time.Millisecond)
	canaryMinSeen     = 4
	canaryUnknownMS   = 2*canaryGapMS + 1_000
	canaryFreezeMinMS = canaryGapMS + canaryUnknownMS
	canaryEarliestMS  = 28_000
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
	names := []string{FactTrial, FactPhase, FactKernel, FactCanaryQuietMS, FactCanaryQuietHealth, FactCanaryCount,
		FactCanaryGapMS}
	for _, s := range CanaryStages() {
		for _, what := range []string{CanaryStopped, CanaryHealth, CanaryHeld, CanaryFrozenMS, CanaryAfterMS,
			CanaryFirstMS, CanaryUnknownMS, CanaryOKMS} {
			names = append(names, CanaryFact(s.Name, what))
		}
	}
	return names
}

// judgeCanary judges a canary trial. A report with an unknown or repeated fact, or of another trial or kernel, is
// INVALID. A gap over 30 s or health not OK in the quiet phase, or a stage whose freeze shows UNKNOWN not in the
// order and within the bounds two missed probes give, health not UNKNOWN from then to SIGCONT, or no OK in time
// after it, is a MISS. A fact missing or not a number, a quiet phase too short or with too few canaries for its
// gaps, or a stage whose freeze is not proven or not long enough is INVALID; as in judgeStatus, every MISS the facts
// show is found before an INVALID is returned.
func judgeCanary(tr rangejob.Trial, o Outcome) (string, string) {
	f, missing, why := knownFacts(tr, o, canaryFacts())
	if why != "" {
		return Invalid, why
	}
	misses, unproven := quietCanaries(f)
	if missing != "" {
		unproven = append(unproven, missing)
	}
	for _, s := range CanaryStages() {
		m, u := frozenStage(s.Name, f)
		for _, why := range m {
			misses = append(misses, s.Name+": "+why)
		}
		for _, why := range u {
			unproven = append(unproven, s.Name+": "+why)
		}
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

// quietCanaries is why the quiet phase is a MISS, and why it proves nothing. n canaries leave n+1 gaps that cover
// the phase, so a run without a long gap has four canaries in 150 s.
func quietCanaries(f map[string]string) (misses, unproven []string) {
	quiet, errQ := plainNumber(f[FactCanaryQuietMS])
	count, errC := plainNumber(f[FactCanaryCount])
	gap, errG := plainNumber(f[FactCanaryGapMS])
	if errG == nil && gap > canaryGapMS {
		misses = append(misses, fmt.Sprintf("%d ms without a canary, over %d", gap, canaryGapMS))
	}
	if h, reported := f[FactCanaryQuietHealth]; reported && h != StoreOK {
		misses = append(misses, fmt.Sprintf("the store's health over the quiet phase was \"%s\"", Printable(h, 32)))
	}
	switch {
	case errQ != nil || errC != nil || errG != nil:
		unproven = append(unproven, "a quiet phase's count is not a plain number")
	case quiet < canaryQuietMS:
		unproven = append(unproven, fmt.Sprintf("a quiet phase of %d ms, under %d", quiet, canaryQuietMS))
	case count < canaryMinSeen || !covers(count, gap, quiet):
		unproven = append(unproven, fmt.Sprintf("%d canaries at most %d ms apart cannot cover a quiet phase of %d ms",
			count, gap, quiet))
	}
	return misses, unproven
}

// covers reports whether count+1 gaps of at most gap ms can span quiet ms, without overflow.
func covers(count, gap, quiet uint64) bool {
	hi, lo := bits.Mul64(count+1, gap)
	return count+1 != 0 && (hi != 0 || lo >= quiet)
}

// frozenStage is why a stage's freeze is a MISS, and why it proves nothing. A freeze is a MISS when UNKNOWN came
// before it, its first canary went out over 30 s into it, UNKNOWN came before that canary's deadline or over 61 s
// after it, health left UNKNOWN before SIGCONT, or OK did not come back within 40 s of SIGCONT. It proves nothing
// when not proven, shorter than the first canary's 30 s and two deadlines, watched less than the recovery after it,
// or without a canary that times its UNKNOWN; a freeze without UNKNOWN misses whatever its canaries.
func frozenStage(stage string, f map[string]string) (misses, unproven []string) {
	v := func(what string) string { return f[CanaryFact(stage, what)] }
	miss := func(format string, a ...any) { misses = append(misses, fmt.Sprintf(format, a...)) }
	bad := func(format string, a ...any) { unproven = append(unproven, fmt.Sprintf(format, a...)) }
	frozen, errF := msOrNone(v(CanaryFrozenMS)) // none is under the minimum below
	after, errA := msOrNone(v(CanaryAfterMS))
	first, errFirst := msOrNone(v(CanaryFirstMS))
	unknown, errU := msOrNone(v(CanaryUnknownMS))
	ok, errO := msOrNone(v(CanaryOKMS))
	if v(CanaryStopped) != "yes" {
		bad("the freeze is not proven: \"%s\"", Printable(v(CanaryStopped), 256))
	}
	switch h := v(CanaryHealth); h {
	case StoreOK:
	case StoreUnknown:
		miss("UNKNOWN already when the freeze began")
	default:
		bad("the store's health when the freeze began was \"%s\"", Printable(h, 32))
	}
	if errF != nil || errA != nil || frozen < canaryFreezeMinMS || after < canaryRecoverMS {
		bad("frozen %s ms and watched %s ms after, under %d and %d", Printable(v(CanaryFrozenMS), 32),
			Printable(v(CanaryAfterMS), 32), canaryFreezeMinMS, canaryRecoverMS)
	}
	switch {
	case errFirst != nil:
		bad("the first canary's time is not a plain number or none")
	case first < 0:
		bad("no canary went out from the freeze on, so its UNKNOWN is not timed")
	case first > canaryGapMS:
		miss("the first canary went out %d ms after the freeze began, over %d", first, canaryGapMS)
	}
	switch {
	case errU != nil:
		bad("UNKNOWN's time is not a plain number or none")
	case unknown < 0 || errF == nil && frozen >= 0 && unknown > frozen:
		miss("no UNKNOWN canary-missed in %s ms frozen", Printable(v(CanaryFrozenMS), 32))
	case errFirst == nil && first >= 0 && unknown < first+canaryEarliestMS:
		miss("UNKNOWN %d ms after the freeze began, before the deadline of its first canary at %d ms", unknown, first)
	case errFirst == nil && first >= 0 && unknown > first+canaryUnknownMS:
		miss("UNKNOWN %d ms after the first canary sent while frozen, over %d", unknown-first, canaryUnknownMS)
	}
	if held, reported := f[CanaryFact(stage, CanaryHeld)]; reported && errU == nil && unknown >= 0 && held != StoreUnknown {
		miss("the store's health from UNKNOWN to SIGCONT was \"%s\"", Printable(held, 32))
	}
	switch {
	case errO != nil:
		bad("OK's time is not a plain number or none")
	case ok < 0 || errA == nil && after >= 0 && ok > after:
		miss("no OK in the %s ms after SIGCONT", Printable(v(CanaryAfterMS), 32))
	case ok > canaryRecoverMS:
		miss("OK %d ms after SIGCONT, over %d", ok, canaryRecoverMS)
	}
	return misses, unproven
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
