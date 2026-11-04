package rangevm

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// What a sensor-down trial (sensor_down_s, ADR 0059) reports of each stage it fails: "yes" when the stage's process
// exited after its signal, the floor showed healthy again and the collector stayed the same process, or why not;
// the store's health at the stamp taken right before the signal; and the first health record not OK after the stamp
// up to the floor's recovery, its state and its time in ms after the stamp, each CanaryNone without one.
const (
	SensorDone      = "done"
	SensorHealth    = "health"
	SensorReason    = "reason"
	SensorUnknownMS = "unknown_ms"
)

// The last part of a sensor-down trial: auditctl -e 0 under -e 2, then audit's enabled as auditctl -s reads it and
// "yes" when the store holds the kernel's CONFIG_CHANGE refusing it (audit_enabled=0 res=0) from the attempt on.
const (
	FactSensorE0Enabled  = "sensor_e0_enabled"
	FactSensorE0Recorded = "sensor_e0_recorded"
)

// sensorDownMS is sensor_down_s: from the stamp to the first UNKNOWN the failure causes.
const sensorDownMS = 10_000

// SensorStage is a stage a sensor-down trial fails, and the health states its failure leads to: anything else
// first is a failure of another part.
type SensorStage struct {
	Name, Kind string
	Reasons    []string
}

// SensorStages are Laurel, SIGKILLed, and auditd, SIGTERMed: Laurel's end closes its socket, and auditd's ends
// Laurel and leaves auditstat's report without its pid. A reconnect within one writer tick reads canary-pending.
func SensorStages() []SensorStage {
	return []SensorStage{
		{"laurel", StatusFreezeLaurel, []string{"UNKNOWN laurel-disconnected", "UNKNOWN canary-pending"}},
		{"auditd", StatusFreezeAuditd, []string{"UNKNOWN laurel-disconnected", "UNKNOWN canary-pending", "UNKNOWN auditd-down"}},
	}
}

// SensorFact is the fact of what a sensor-down trial reports of stage.
func SensorFact(stage, what string) string { return "sensor_" + stage + "_" + what }

func sensorFacts() []string {
	names := []string{FactTrial, FactPhase, FactKernel, FactSensorE0Enabled, FactSensorE0Recorded}
	for _, s := range SensorStages() {
		for _, what := range []string{SensorDone, SensorHealth, SensorReason, SensorUnknownMS} {
			names = append(names, SensorFact(s.Name, what))
		}
	}
	return names
}

// judgeSensorDown judges a sensor-down trial. A report with an unknown or repeated fact, or of another trial or
// kernel, is INVALID. A stage whose first health not OK after the stamp is none, another state than its failure
// leads to, or over 10 s after the stamp, audit enabled other than 2 after -e 0, or no record of the refusal, is a
// MISS. A fact missing, a stage not done, or health not OK at the stamp is INVALID; every MISS the facts show is
// found before an INVALID is returned.
func judgeSensorDown(tr rangejob.Trial, o Outcome) (string, string) {
	f, missing, why := knownFacts(tr, o, sensorFacts())
	if why != "" {
		return Invalid, why
	}
	var misses, unproven []string
	if missing != "" {
		unproven = append(unproven, missing)
	}
	for _, s := range SensorStages() {
		m, u := failedStage(s, f)
		for _, why := range m {
			misses = append(misses, s.Name+": "+why)
		}
		for _, why := range u {
			unproven = append(unproven, s.Name+": "+why)
		}
	}
	if e, reported := f[FactSensorE0Enabled]; reported && e != "2" {
		misses = append(misses, fmt.Sprintf("audit enabled \"%s\" after auditctl -e 0, not 2", Printable(e, 32)))
	}
	if r, reported := f[FactSensorE0Recorded]; reported && r != "yes" {
		misses = append(misses, "the store holds no record of the kernel refusing auditctl -e 0")
	}
	switch {
	case len(misses) > 0:
		return Miss, strings.Join(misses, "; ")
	case len(unproven) > 0:
		return Invalid, strings.Join(unproven, "; ")
	}
	return Pass, fmt.Sprintf("UNKNOWN %s ms after Laurel was killed and %s ms after auditd was stopped; -e 0 refused and recorded",
		f[SensorFact("laurel", SensorUnknownMS)], f[SensorFact("auditd", SensorUnknownMS)])
}

// failedStage is why a stage is a MISS, and why it proves nothing.
func failedStage(s SensorStage, f map[string]string) (misses, unproven []string) {
	if done, reported := f[SensorFact(s.Name, SensorDone)]; reported && done != "yes" {
		unproven = append(unproven, fmt.Sprintf("the failure is not proven: \"%s\"", Printable(done, 256)))
	}
	if h, reported := f[SensorFact(s.Name, SensorHealth)]; reported && h != StoreOK {
		unproven = append(unproven, fmt.Sprintf("the store's health at the stamp was \"%s\"", Printable(h, 32)))
	}
	reason, reported := f[SensorFact(s.Name, SensorReason)]
	if !reported {
		return misses, unproven
	}
	unknown, err := msOrNone(f[SensorFact(s.Name, SensorUnknownMS)])
	switch {
	case reason == CanaryNone:
		misses = append(misses, "no health record other than OK until the floor was healthy again")
	case !slices.Contains(s.Reasons, reason):
		misses = append(misses, fmt.Sprintf("health \"%s\" first, not one the failure leads to", Printable(reason, 64)))
	case err != nil || unknown < 0:
		unproven = append(unproven, "UNKNOWN's time is not a plain number")
	case unknown > sensorDownMS:
		misses = append(misses, fmt.Sprintf("UNKNOWN %d ms after the stamp, over %d", unknown, sensorDownMS))
	}
	return misses, unproven
}

// What a sensor-down rules trial (ADR 0059, point 5) reports: "yes" when auditctl, as root, shows the injected rules
// file loaded and audit locked, or why not; how long it watched from the collector's first health record; and the
// collector's health states over the watch, each once per change, joined by StatesSep.
const (
	FactRulesProof   = "rules_proof"
	FactRulesWatchMS = "rules_watch_ms"
	FactRulesStates  = "rules_states"
	StatesSep        = "|"
)

// RulesWatch is how long a rules trial's guest watches the collector's health: two canaries' deadlines.
const RulesWatch = 60 * time.Second

// The states a rules trial is judged by: the collector's wait for its first canary over a connection, which every
// other audit reason waits for, and the reason the rules must give.
const (
	stateCanaryPending = "UNKNOWN canary-pending"
	stateRulesDiffer   = "UNKNOWN rules-differ"
)

func rulesFacts() []string {
	return []string{FactTrial, FactPhase, FactKernel, FactRulesProof, FactRulesWatchMS, FactRulesStates}
}

// judgeRulesDiffer judges a sensor-down rules trial. A report with an unknown or repeated fact, or of another trial
// or kernel, is INVALID. Health OK at any time, no rules-differ, a state other than canary-pending right before the
// first one, so it came later than the tick that stored the first canary, or a last state other than rules-differ is
// a MISS. A fact missing, the injection not proven or a watch under RulesWatch is INVALID, after every MISS.
func judgeRulesDiffer(tr rangejob.Trial, o Outcome) (string, string) {
	f, missing, why := knownFacts(tr, o, rulesFacts())
	if why != "" {
		return Invalid, why
	}
	var misses, unproven []string
	if missing != "" {
		unproven = append(unproven, missing)
	}
	if p, reported := f[FactRulesProof]; reported && p != "yes" {
		unproven = append(unproven, fmt.Sprintf("the injection is not proven: \"%s\"", Printable(p, 256)))
	}
	if w, reported := f[FactRulesWatchMS]; reported {
		if ms, err := plainNumber(w); err != nil || ms < uint64(RulesWatch/time.Millisecond) {
			unproven = append(unproven, fmt.Sprintf("watched \"%s\" ms, under %d", Printable(w, 32), RulesWatch/time.Millisecond))
		}
	}
	if s, reported := f[FactRulesStates]; reported {
		states := strings.Split(s, StatesSep)
		first := slices.Index(states, stateRulesDiffer)
		switch {
		case slices.Contains(states, "OK"):
			misses = append(misses, "health OK with rules that differ")
		case first < 0:
			misses = append(misses, "no rules-differ")
		case first == 0 || states[first-1] != stateCanaryPending:
			misses = append(misses, "rules-differ not right after the first canary was stored")
		case states[len(states)-1] != stateRulesDiffer:
			misses = append(misses, fmt.Sprintf("health \"%s\" last, not rules-differ", Printable(states[len(states)-1], 64)))
		}
	}
	switch {
	case len(misses) > 0:
		return Miss, strings.Join(misses, "; ")
	case len(unproven) > 0:
		return Invalid, strings.Join(unproven, "; ")
	}
	return Pass, "never OK; rules-differ from the first stored canary to the end of the watch"
}
