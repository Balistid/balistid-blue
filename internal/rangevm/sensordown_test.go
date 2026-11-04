package rangevm

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sensorRun is a sound report of a sensor-down trial, changed by name=value; a name without "=" is left out, an
// unknown one added.
func sensorRun(change ...string) Outcome {
	base := map[string]string{FactSensorE0Enabled: "2", FactSensorE0Recorded: "yes"}
	for _, s := range SensorStages() {
		base[SensorFact(s.Name, SensorDone)] = "yes"
		base[SensorFact(s.Name, SensorHealth)] = StoreOK
		base[SensorFact(s.Name, SensorReason)] = s.Reasons[0]
		base[SensorFact(s.Name, SensorUnknownMS)] = "260"
	}
	return probeRun("sensor-down-1", sensorFacts(), base, change...)
}

// Every path to PASS with a false or missing fact: the report, a stage not done or not begun OK, a time not a
// number are INVALID; no UNKNOWN, an UNKNOWN for a reason the failure does not cause, one over 10 s, audit enabled
// after -e 0 or the refusal not stored are a MISS, and no INVALID, of the same stage or another, hides one.
func TestJudgeSensorDown(t *testing.T) {
	invalid := []string{"canary=seen", "trial=canary", "kernel=6.0.0"}
	invalid = append(invalid, sensorFacts()...) // each fact left out
	miss := []string{
		"sensor_e0_enabled=0", "sensor_e0_enabled=1", "sensor_e0_enabled=", "sensor_e0_enabled=2 ",
		"sensor_e0_recorded=no", "sensor_e0_recorded=", "sensor_e0_recorded=YES",
		// A MISS outranks an INVALID of another part.
		"sensor_e0_recorded=no,sensor_laurel_done=no", "sensor_e0_enabled=0,sensor_auditd_unknown_ms=x",
	}
	var pass []string
	for _, s := range SensorStages() {
		f := func(what, v string) string { return SensorFact(s.Name, what) + "=" + v }
		for _, bad := range []string{"x", "-1", "0260", "260 ", "", "+260", "260.0", "18446744073709551615", "18446744073709551616", "none", "NONE"} {
			invalid = append(invalid, f(SensorUnknownMS, bad))
		}
		invalid = append(invalid,
			f(SensorDone, "no exit"), f(SensorDone, ""), f(SensorDone, "yes "),
			f(SensorHealth, StoreUnknown), f(SensorHealth, StoreMixed), f(SensorHealth, StoreNone), f(SensorHealth, ""),
		)
		miss = append(miss,
			f(SensorReason, CanaryNone), f(SensorReason, CanaryNone)+","+f(SensorUnknownMS, "none"),
			f(SensorReason, "OK"), f(SensorReason, "UNKNOWN canary-missed"), f(SensorReason, "UNKNOWN audit-stale"),
			f(SensorReason, "UNKNOWN store: closed"), f(SensorReason, "UNKNOWN auditd-restarted"),
			f(SensorReason, "UNKNOWN dispatcher-overflow"), f(SensorReason, "UNKNOWN laurel-disconnected "),
			f(SensorReason, ""), f(SensorUnknownMS, "10001"),
			// A MISS in a stage outranks an INVALID of the same stage.
			f(SensorUnknownMS, "10001")+","+f(SensorDone, "no"), f(SensorReason, CanaryNone)+","+f(SensorHealth, StoreUnknown),
		)
		pass = append(pass, f(SensorUnknownMS, "10000"), f(SensorUnknownMS, "0"), f(SensorUnknownMS, "9999"))
		for _, r := range s.Reasons {
			pass = append(pass, f(SensorReason, r))
		}
	}
	// Laurel's end never empties auditstat's report of auditd's pid.
	miss = append(miss, SensorFact("laurel", SensorReason)+"=UNKNOWN auditd-down")
	judgeCases(t, "sensor-down-1", sensorRun, map[string][]string{Miss: miss, Invalid: invalid, Pass: pass})
}

// The judge's bound is acceptance sensor_down_s, and its method names what each run fails.
func TestSensorDownBoundIsTheAcceptance(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^id = "sensor_down_s"\nmax = (\d+)\n(?:.*\n){3}method = "(.*)"$`).FindSubmatch(data)
	if m == nil || string(m[1]) != strconv.Itoa(sensorDownMS/1000) {
		t.Fatalf("acceptance sensor_down_s %q, the judge's bound %d ms", m, sensorDownMS)
	}
	for _, says := range []string{"kill Laurel", "SIGTERM auditd", "auditctl -e 0", "laurel-disconnected", "auditd-down"} {
		if !strings.Contains(string(m[2]), says) {
			t.Errorf("sensor_down_s's method does not say %q", says)
		}
	}
}

// Each state a stage accepts is one the collector sets, so a renamed reason fails here, not as a MISS in the range.
func TestSensorReasonsAreTheCollectorsHealth(t *testing.T) {
	var src strings.Builder
	for _, f := range []string{"../collector/writer.go", "../collector/audit.go"} {
		b, err := os.ReadFile(f) //nolint:gosec // the two fixed sources above
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	for _, s := range SensorStages() {
		for _, r := range s.Reasons {
			if !strings.Contains(src.String(), strconv.Quote(r)) {
				t.Errorf("%s: the collector sets no health %q", s.Name, r)
			}
		}
	}
}

// A sensor-down run keeps each stage's time, but not a time that is none.
func TestMeasuresOfASensorDownTrial(t *testing.T) {
	tr := trial(t, "sensor-down-1")
	m := Measures(tr, sensorRun(SensorFact("auditd", SensorUnknownMS)+"=4100"))
	if len(m) != 2 || m[SensorFact("laurel", SensorUnknownMS)] != 260 || m[SensorFact("auditd", SensorUnknownMS)] != 4100 {
		t.Errorf("measures %v", m)
	}
	if m := Measures(tr, sensorRun(SensorFact("laurel", SensorUnknownMS)+"=none")); len(m) != 1 {
		t.Errorf("measures with a time that is none %v", m)
	}
}

const pending = "UNKNOWN canary-pending"

// rulesRun is a sound report of a rules trial, changed by name=value as sensorRun.
func rulesRun(change ...string) Outcome {
	base := map[string]string{FactRulesProof: "yes", FactRulesWatchMS: "60004", FactRulesDifferMS: "1250",
		FactRulesStates: strings.Join([]string{"UNKNOWN store: starting", "UNKNOWN laurel-disconnected", pending,
			"UNKNOWN audit-stale", stateRulesDiffer}, StatesSep)}
	return probeRun("sensor-down-rules-extra-1", rulesFacts(), base, change...)
}

// Every path to PASS with a false or missing fact: the report, the injection not proven, a watch too short, a time
// not a number are INVALID; OK at any time, no rules-differ, one not timed from a stored canary or over 10 s after it,
// or another state last are a MISS, and no INVALID hides one.
func TestJudgeRulesDiffer(t *testing.T) {
	join := func(s ...string) string { return FactRulesStates + "=" + strings.Join(s, StatesSep) }
	invalid := []string{"canary=seen", "trial=sensor-down-1", "kernel=6.0.0",
		"rules_proof=", "rules_proof=7 rules loaded, not 8", "rules_proof=yes ",
		"rules_watch_ms=59999", "rules_watch_ms=none", "rules_watch_ms=x", "rules_watch_ms=", "rules_watch_ms=-1",
		"rules_differ_ms=x", "rules_differ_ms=", "rules_differ_ms=-1", "rules_differ_ms=1250 ",
		"rules_differ_ms=18446744073709551615",
		// A state no collector writes proves nothing, empty or near one it writes.
		join("GARBAGE", stateRulesDiffer), join("OK ", stateRulesDiffer), join("", stateRulesDiffer),
		join(pending, "UNKNOWN store: ", stateRulesDiffer), join(pending, "UNKNOWN store: x\x00", stateRulesDiffer),
		join(pending, "unknown audit-stale", stateRulesDiffer),
	}
	invalid = append(invalid, rulesFacts()...)
	miss := []string{
		join("OK"), join(pending, "OK", stateRulesDiffer), join(pending, stateRulesDiffer, "OK"),
		join("OK", pending, stateRulesDiffer), join(pending), join(""), FactRulesStates + "=",
		join(pending, stateRulesDiffer, "UNKNOWN canary-missed"),
		join(pending, "UNKNOWN rules-differ "), join(pending, "ok"),
		"rules_differ_ms=none", "rules_differ_ms=10001",
		// A MISS outranks an INVALID.
		join("OK") + ",rules_proof=no", join(pending) + ",rules_watch_ms=1", "rules_differ_ms=10001,rules_proof=no",
	}
	pass := []string{
		join(pending, stateRulesDiffer), join(stateRulesDiffer), "rules_differ_ms=10000", "rules_differ_ms=0",
		join(pending, stateRulesDiffer, "UNKNOWN laurel-disconnected", pending, stateRulesDiffer),
		join(pending, "UNKNOWN store: starting", "UNKNOWN ledger-stream", "UNKNOWN auditd-restarted", stateRulesDiffer),
		"rules_watch_ms=60000",
	}
	judgeCases(t, "sensor-down-rules-extra-1", rulesRun, map[string][]string{Miss: miss, Invalid: invalid, Pass: pass})
}

// The states a rules trial is judged by are the collector's.
func TestRulesStatesAreTheCollectorsHealth(t *testing.T) {
	var src strings.Builder
	for _, f := range []string{"../collector/writer.go", "../collector/audit.go", "../collector/ledger.go"} {
		b, err := os.ReadFile(f) //nolint:gosec // the fixed sources above
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	if !strings.Contains(src.String(), `"`+storeState+`" + `) {
		t.Errorf("the collector writes no %q state", storeState)
	}
	for _, s := range []string{stateRulesDiffer, "UNKNOWN starting", "UNKNOWN laurel-disconnected", "UNKNOWN canary-missed",
		"UNKNOWN canary-pending", "UNKNOWN dispatcher-overflow", "UNKNOWN auditd-down", "UNKNOWN auditd-restarted",
		"UNKNOWN audit-stale", "UNKNOWN ledger-stream"} {
		if !collectorState(s) {
			t.Errorf("%q is not a collector state", s)
		}
		if !strings.Contains(src.String(), strconv.Quote(s)) {
			t.Errorf("the collector sets no health %q", s)
		}
	}
}
