package main

import (
	"fmt"
	"testing"
	"time"

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
