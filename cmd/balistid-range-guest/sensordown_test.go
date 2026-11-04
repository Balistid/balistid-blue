package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// A stage is timed by the first health record not OK after its stamp and up to the floor's recovery: OK records
// after the stamp, and anything at or before it or after the recovery, do not count.
func TestSensorFactsTimeTheStage(t *testing.T) {
	sec := func(v int64) int64 { return v * int64(time.Second) }
	h := func(at int64, state string) health { return health{kind: "health", state: state, at: sec(at)} }
	fl := sensorFailure{done: "yes", at: sec(1000), until: sec(1060)}
	facts := func(tl healthTimeline) map[string]string {
		got := map[string]string{}
		for _, f := range fl.facts(tl) {
			got[f[0]] = f[1]
		}
		return got
	}
	got := facts(healthTimeline{h(900, "OK"), h(1000, "UNKNOWN canary-missed"), h(1000, "OK"), h(1001, "OK"),
		h(1003, "UNKNOWN laurel-disconnected"), h(1004, "UNKNOWN canary-pending"), h(1040, "OK")})
	want := map[string]string{rangevm.SensorDone: "yes", rangevm.SensorHealth: rangevm.StoreOK,
		rangevm.SensorReason: "UNKNOWN laurel-disconnected", rangevm.SensorUnknownMS: "3000"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("facts %v\nwant  %v", got, want)
	}
	got = facts(healthTimeline{h(990, "UNKNOWN audit-stale"), h(1061, "UNKNOWN laurel-disconnected")})
	if got[rangevm.SensorHealth] != rangevm.StoreUnknown || got[rangevm.SensorReason] != rangevm.CanaryNone ||
		got[rangevm.SensorUnknownMS] != rangevm.CanaryNone {
		t.Errorf("UNKNOWN before the stamp, none in the watch: facts %v", got)
	}
}

// Only Laurel's event of the kernel refusing audit_enabled=0 counts, by its audit time.
func TestRefusedDisableIsTheKernelsRefusal(t *testing.T) {
	rec := func(change string) rawrecord.Record {
		line := `{"ID":"1791460800.123:42","CONFIG_CHANGE":[{"op":"set","audit_enabled":` + change + `,"old":2,"auid":0,"ses":1,"res":0}]}`
		return rawrecord.New(1, store.SensorProvider, 1, 1, []byte(line))
	}
	if at, ok := refusedDisable(rec("0")); !ok || at != int64(1791460800)*int64(time.Second)+123*int64(time.Millisecond) {
		t.Errorf("refusal: %d %v", at, ok)
	}
	for name, x := range map[string]rawrecord.Record{
		"enable 1":      rec("1"),
		"accepted":      rawrecord.New(1, store.SensorProvider, 1, 1, []byte(`{"ID":"1791460800.123:42","CONFIG_CHANGE":[{"audit_enabled":0,"res":1}]}`)),
		"no ID":         rawrecord.New(1, store.SensorProvider, 1, 1, []byte(`{"CONFIG_CHANGE":[{"audit_enabled":0,"res":0}]}`)),
		"bad ID":        rawrecord.New(1, store.SensorProvider, 1, 1, []byte(`{"ID":"x","CONFIG_CHANGE":[{"audit_enabled":0,"res":0}]}`)),
		"health record": rawrecord.New(1, store.HealthProvider, 1, 1, rec("0").Data),
	} {
		if _, ok := refusedDisable(x); ok {
			t.Errorf("%s: counted as the refusal", name)
		}
	}
}

// The proof needs audit locked and auditctl's list to show exactly the injected change, and nothing else of them.
func TestRulesProofShowsTheInjection(t *testing.T) {
	shipped := strings.Join([]string{
		"-a always,exit -F arch=b64 -S execve,execveat -F key=balistid-exec",
		"-a always,exit -F arch=b32 -S execve,execveat -F key=balistid-exec",
		"-a always,exit -F arch=b64 -S ptrace,process_vm_writev -F key=balistid-inject",
		"-a always,exit -F arch=b32 -S ptrace,process_vm_writev -F key=balistid-inject",
		"-a always,exit -F arch=b64 -S memfd_create -F key=balistid-memfd",
		"-a always,exit -F arch=b32 -S memfd_create -F key=balistid-memfd",
		"-w /var/lib/balistid/collector/canary -p w -k balistid-canary",
	}, "\n")
	extra := shipped + "\n-a always,exit -F arch=b64 -S openat -F uid=4242 -F key=" + extraKey
	missing := strings.Replace(shipped, "-a always,exit -F arch=b32 -S memfd_create -F key=balistid-memfd\n", "", 1)
	locked := map[string]string{"enabled": "2", "backlog_limit": "65536"}
	small := map[string]string{"enabled": "2", "backlog_limit": "8192"}
	for _, c := range []struct {
		inject, list string
		status       map[string]string
		want         string
	}{
		{rangejob.InjectRulesExtra, extra, locked, "yes"},
		{rangejob.InjectRulesMissing, missing, locked, "yes"},
		{rangejob.InjectRulesStatus, shipped, small, "yes"},
		{rangejob.InjectRulesExtra, shipped, locked, "7 rules loaded, not 8"},
		{rangejob.InjectRulesExtra, strings.Replace(extra, extraKey, "other", 1), locked, "extra rule loaded no"},
		{rangejob.InjectRulesMissing, shipped, locked, "7 rules loaded, not 6"},
		{rangejob.InjectRulesMissing, strings.Replace(shipped, "-a always,exit -F arch=b64 -S memfd_create -F key=balistid-memfd\n", "", 1),
			locked, "b32 memfd rule loaded yes"},
		{rangejob.InjectRulesStatus, shipped, locked, "backlog_limit"},
		{rangejob.InjectRulesExtra, extra, small, "backlog_limit"},
		{rangejob.InjectRulesExtra, extra, map[string]string{"enabled": "1", "backlog_limit": "65536"}, "not locked"},
		{rangejob.InjectRulesStatus, "No rules", small, "0 rules loaded"},
	} {
		if got := rulesProof(c.inject, c.list, c.status); !strings.Contains(got, c.want) || (c.want == "yes") != (got == "yes") {
			t.Errorf("%s: %q, want %q", c.inject, got, c.want)
		}
	}
}

// The states are each change once, up to until, the watch runs from the first record, and rules-differ is timed from
// the change away from the last canary-pending before it, the tick that stored the canary.
func TestHealthStatesOnceEachUpToTheWatchEnd(t *testing.T) {
	ms := func(v int64) int64 { return v * int64(time.Millisecond) }
	h := func(at int64, state string) health { return health{kind: "health", state: state, at: ms(at)} }
	watch, states, differ := healthTimeline{h(0, "UNKNOWN x"), h(10000, "UNKNOWN store: starting"), h(11000, canaryPending),
		h(11500, "UNKNOWN laurel-disconnected"), h(12000, canaryPending), h(12100, canaryPending),
		h(13250, "UNKNOWN audit-stale"), h(14000, rulesDiffer), h(15000, "UNKNOWN laurel-disconnected"),
		h(16000, canaryPending), h(17000, rulesDiffer), h(80000, "OK")}.states(ms(71000))
	if watch != "61000" || differ != "750" || states != "UNKNOWN store: starting|"+canaryPending+"|UNKNOWN laurel-disconnected|"+
		canaryPending+"|UNKNOWN audit-stale|"+rulesDiffer+"|UNKNOWN laurel-disconnected|"+canaryPending+"|"+rulesDiffer {
		t.Errorf("watch %s, differ %s, states %q", watch, differ, states)
	}
	if _, _, differ := (healthTimeline{h(1, rulesDiffer), h(2, canaryPending)}).states(ms(9)); differ != rangevm.CanaryNone {
		t.Errorf("rules-differ before any canary: %s", differ)
	}
	if watch, states, differ := (healthTimeline{}).states(ms(71000)); watch != rangevm.CanaryNone || states != "" ||
		differ != rangevm.CanaryNone {
		t.Errorf("no records: %s %q %s", watch, states, differ)
	}
}

// The guest does not link the collector, so the states it times are checked against the collector's source.
func TestRulesStatesAreTheCollectorsHealth(t *testing.T) {
	var src []byte
	for _, f := range []string{"../../internal/collector/writer.go", "../../internal/collector/audit.go"} {
		b, err := os.ReadFile(f) //nolint:gosec // the two fixed sources above
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, b...)
	}
	for _, s := range []string{canaryPending, rulesDiffer} {
		if !strings.Contains(string(src), strconv.Quote(s)) {
			t.Errorf("the collector sets no health %q", s)
		}
	}
}

// Every rules trial of the table writes its file, and nothing else does: a self-test or another trial loads only
// the repository's rules.
func TestOnlyRulesTrialsWriteRules(t *testing.T) {
	for _, tr := range append(rangejob.Trials(), rangejob.Trial{}) {
		text, ok := rulesFor(tr)
		if want := tr.Method() == rangejob.MethodSensorDownRules; ok != want || want && text == "" {
			t.Errorf("%s: writes %v %q", tr.Name, ok, text)
		}
	}
}
