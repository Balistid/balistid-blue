package rangevm

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/collector"
)

// canaryRun is a sound report of the canary trial, changed by name=value; a name without "=" is left out, an
// unknown one added.
func canaryRun(change ...string) Outcome {
	base := map[string]string{FactCanaryQuietMS: "150004", FactCanaryQuietHealth: StoreOK, FactCanaryCount: "5",
		FactCanaryGapMS: "29012"}
	for _, s := range CanaryStages() {
		for what, v := range map[string]string{CanaryStopped: "yes", CanaryHealth: StoreOK, CanaryHeld: StoreUnknown,
			CanaryFrozenMS: "100002",
			CanaryAfterMS:  "45001", CanaryFirstMS: "12000", CanaryUnknownMS: "70300", CanaryOKMS: "21000"} {
			base[CanaryFact(s.Name, what)] = v
		}
	}
	return probeRun("canary", canaryFacts(), base, change...)
}

// Every path to PASS with a false or missing fact: the report, each number re-parsed, a quiet phase too short or
// with too few canaries, a freeze not proven, too short or without a canary are INVALID; a gap over 30 s or health
// not OK in the quiet phase, UNKNOWN before the freeze, a first canary over 30 s into it, no UNKNOWN, one before
// that canary's deadline or late, health not UNKNOWN until SIGCONT, no OK or a late one are a MISS, and no
// INVALID, of the same part or another, hides one.
func TestJudgeCanary(t *testing.T) {
	invalid := []string{"canary=seen", "trial=rss-burst", "kernel=6.0.0",
		"canary_count=3", "canary_count=4", "canary_count=0", "canary_count=18446744073709551615", "canary_max_gap_ms=0",
		"canary_quiet_ms=149999", "canary_quiet_ms=" + strconv.Itoa(6*29012+1),
		"canary_count=4,canary_max_gap_ms=30000",
	}
	invalid = append(invalid, canaryFacts()...) // each fact left out
	for _, name := range []string{FactCanaryQuietMS, FactCanaryCount, FactCanaryGapMS} {
		for _, bad := range []string{"x", "-1", "029012", "29012 ", "", "+29012", "29012.0", "18446744073709551616", "none"} {
			invalid = append(invalid, name+"="+bad)
		}
	}
	miss := []string{
		"canary_max_gap_ms=30001", "canary_max_gap_ms=150004,canary_count=0", "canary_max_gap_ms=30001,canary_quiet_ms=x",
		"canary_max_gap_ms=30001,canary_count=x", "canary_max_gap_ms=18446744073709551615",
		// A MISS in one part outranks an INVALID in another.
		"canary_laurel_unknown_ms=none,canary_auditd_stopped=no", "canary_max_gap_ms=30001,canary_auditd_health=UNKNOWN",
		"canary_auditd_ok_ms=none,canary_laurel_frozen_ms=x", "canary_laurel_ok_ms=40001,canary_quiet_ms=1",
		"canary_max_gap_ms=30001,canary_laurel_ok_ms", "canary_quiet_health=UNKNOWN", "canary_quiet_health=mixed",
		"canary_quiet_health=none", "canary_quiet_health=", "canary_quiet_health=-", "canary_quiet_health=UNKNOWN,canary_count=x",
	}
	pass := []string{
		"canary_max_gap_ms=30000", "canary_count=4,canary_max_gap_ms=30000,canary_quiet_ms=150000", "canary_count=9",
	}
	for _, s := range CanaryStages() {
		f := func(what, v string) string { return CanaryFact(s.Name, what) + "=" + v }
		for _, bad := range []string{"x", "-1", "070300", "70300 ", "", "+70300", "70300.0", "18446744073709551616", "NONE"} {
			for _, what := range []string{CanaryFrozenMS, CanaryAfterMS, CanaryFirstMS, CanaryUnknownMS, CanaryOKMS} {
				invalid = append(invalid, f(what, bad))
			}
		}
		invalid = append(invalid,
			// The freeze not proven, not begun OK, too short to miss twice or not watched long enough after.
			f(CanaryStopped, "after SIGSTOP: pid 9 is \"S (sleeping)\""), f(CanaryStopped, ""), f(CanaryStopped, "yes "),
			f(CanaryHealth, StoreMixed), f(CanaryHealth, StoreNone), f(CanaryHealth, StoreUnread),
			f(CanaryHealth, ""), f(CanaryFrozenMS, "90999"), f(CanaryFrozenMS, "none"), f(CanaryAfterMS, "39999"),
			f(CanaryAfterMS, "none"),
			// UNKNOWN came, but no canary of the freeze times it.
			f(CanaryFirstMS, "none"),
		)
		miss = append(miss,
			f(CanaryUnknownMS, "none"), f(CanaryUnknownMS, "100003"), f(CanaryUnknownMS, "73001"),
			f(CanaryUnknownMS, "none")+","+f(CanaryFirstMS, "none"), f(CanaryUnknownMS, "none")+","+f(CanaryOKMS, "none"),
			f(CanaryOKMS, "none"), f(CanaryOKMS, "40001"), f(CanaryOKMS, "45002"),
			f(CanaryFirstMS, "0")+","+f(CanaryUnknownMS, "61001"),
			// UNKNOWN before the freeze, or before the deadline of the first canary sent while frozen.
			f(CanaryHealth, StoreUnknown), f(CanaryUnknownMS, "0"), f(CanaryUnknownMS, "5000"), f(CanaryUnknownMS, "12000"),
			f(CanaryUnknownMS, "39999"), f(CanaryFirstMS, "70300"), f(CanaryFirstMS, "29250")+","+f(CanaryUnknownMS, "29300"),
			// The first canary over 30 s into the freeze, which then cannot show two misses in time.
			f(CanaryFirstMS, "30001"), f(CanaryFirstMS, "100003"), f(CanaryUnknownMS, "100002")+","+f(CanaryFirstMS, "39002"),
			f(CanaryFirstMS, "99000")+","+f(CanaryUnknownMS, "99500"), f(CanaryFirstMS, "90000")+","+f(CanaryUnknownMS, "95000"),
			f(CanaryFirstMS, "60000")+","+f(CanaryUnknownMS, "99000"),
			// OK, or anything but UNKNOWN, between UNKNOWN and SIGCONT.
			f(CanaryHeld, StoreMixed), f(CanaryHeld, StoreOK), f(CanaryHeld, CanaryNone), f(CanaryHeld, ""),
			f(CanaryHeld, StoreMixed)+","+f(CanaryAfterMS, "x"),
			// A MISS in a stage outranks an INVALID of the same stage.
			f(CanaryUnknownMS, "none")+","+f(CanaryOKMS, "x"), f(CanaryFirstMS, "none")+","+f(CanaryOKMS, "40001"),
			f(CanaryFirstMS, "x")+","+f(CanaryOKMS, "40001"), f(CanaryUnknownMS, "5000")+","+f(CanaryStopped, "no"),
			f(CanaryOKMS, "none")+","+f(CanaryFrozenMS, "90999"),
		)
		pass = append(pass, f(CanaryUnknownMS, "73000"), f(CanaryUnknownMS, "40000"), f(CanaryOKMS, "40000"),
			f(CanaryOKMS, "0"), f(CanaryFrozenMS, "91000"), f(CanaryAfterMS, "40000"), f(CanaryFirstMS, "9300"),
			f(CanaryFirstMS, "30000")+","+f(CanaryUnknownMS, "91000"), f(CanaryFirstMS, "0")+","+f(CanaryUnknownMS, "28000"),
			f(CanaryHeld, StoreUnknown)+","+f(CanaryUnknownMS, "61000"))
	}
	judgeCases(t, "canary", canaryRun, map[string][]string{Miss: miss, Invalid: invalid, Pass: pass})
}

// The judge's gap is acceptance canary_interval_s, and the guest freezes and watches longer than the judge needs.
func TestCanaryBoundsAreTheAcceptance(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^id = "canary_interval_s"\nmax = (\d+)\n`).FindSubmatch(data)
	if m == nil || string(m[1]) != strconv.Itoa(canaryGapMS/1000) {
		t.Errorf("acceptance canary_interval_s %q, the judge's gap %d ms", m, canaryGapMS)
	}
	if CanaryFreeze < canaryFreezeMinMS*time.Millisecond || CanaryAfter < canaryRecoverMS*time.Millisecond ||
		CanaryQuiet < time.Duration(canaryMinSeen+1)*canaryGapMS*time.Millisecond {
		t.Errorf("the guest's phases %s, %s, %s are shorter than the judge's bounds", CanaryQuiet, CanaryFreeze, CanaryAfter)
	}
	if earliest := collector.CanaryEvery - time.Second; canaryEarliestMS*time.Millisecond != earliest || earliest <= 0 {
		t.Errorf("UNKNOWN no earlier than %d ms after a freeze's first canary, the collector's deadline less a second is %s",
			canaryEarliestMS, earliest)
	}
}

// A canary run keeps its count, gap and each stage's times, but not a time that is none.
func TestMeasuresOfACanaryTrial(t *testing.T) {
	tr := trial(t, "canary")
	m := Measures(tr, canaryRun())
	if len(m) != 8 || m[FactCanaryGapMS] != 29012 || m[FactCanaryCount] != 5 || m[CanaryFact("auditd", CanaryUnknownMS)] != 70300 {
		t.Errorf("measures %v", m)
	}
	if m := Measures(tr, canaryRun(CanaryFact("laurel", CanaryOKMS)+"=none")); len(m) != 7 {
		t.Errorf("measures with a time that is none %v", m)
	}
}
