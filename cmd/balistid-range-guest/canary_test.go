package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// canaryLaurel is a canary record shaped as Laurel writes it with enrich on: the "PID" object and "UID" name
// beside the numbers, key and path as given.
func canaryLaurel(id string, uid, pid int, success, key, path string) rawrecord.Record {
	line := fmt.Sprintf(`{"ID":%q,"SYSCALL":{"syscall":"openat","success":%q,"uid":%d,"UID":"balistid-collector",`+
		`"pid":%d,"PID":{"EVENT_ID":"1.1:1","comm":"balistid-collec"},"key":%s},"PATH":[{"name":"/var/lib/balistid/`+
		`collector/canary","nametype":"PARENT"},{"name":%q,"nametype":"CREATE"}]}`, id, success, uid, pid, key, path)
	return rawrecord.New(1, store.SensorProvider, 1, 1, []byte(line))
}

var owner = canaryOwner{uid: "998", pid: "4242"}

func TestCanarySentReadsTheAuditTimeOfTheCollectorsProbe(t *testing.T) {
	at := int64(1791460800)*int64(time.Second) + 123*int64(time.Millisecond)
	for name, x := range map[string]rawrecord.Record{
		"one key":      canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary"`, "c-7"),
		"several keys": canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"other\u0001balistid-canary"`, "c-7"),
		"a key list":   canaryLaurel("1791460800.123:42", 998, 4242, "yes", `["other","balistid-canary"]`, "c-7"),
		"full path":    canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary"`, "/var/lib/balistid/collector/canary/c-7"),
	} {
		if n, got, ok := canarySent(x, owner); !ok || n != 7 || got != at {
			t.Errorf("%s: probe %d at %d, %v; want 7 at %d", name, n, got, ok, at)
		}
	}
}

// Only the collector's own successful create of c-<n> under the canary's key is a canary, as Observe takes one.
func TestCanarySentIgnoresEverythingElse(t *testing.T) {
	ok := func(id string) rawrecord.Record {
		return canaryLaurel(id, 998, 4242, "yes", `"balistid-canary"`, "c-7")
	}
	truncated := ok("1791460800.123:42")
	truncated.OrigLen++
	health := ok("1791460800.123:42")
	health.Provider = store.HealthProvider
	for name, x := range map[string]rawrecord.Record{
		"another key":        canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary-not"`, "c-7"),
		"no key":             canaryLaurel("1791460800.123:42", 998, 4242, "yes", `null`, "c-7"),
		"another uid":        canaryLaurel("1791460800.123:42", 0, 4242, "yes", `"balistid-canary"`, "c-7"),
		"another pid":        canaryLaurel("1791460800.123:42", 998, 4243, "yes", `"balistid-canary"`, "c-7"),
		"a failed syscall":   canaryLaurel("1791460800.123:42", 998, 4242, "no", `"balistid-canary"`, "c-7"),
		"another basename":   canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary"`, "x-7"),
		"no number":          canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary"`, "c-"),
		"a padded number":    canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary"`, "c-07"),
		"a number and more":  canaryLaurel("1791460800.123:42", 998, 4242, "yes", `"balistid-canary"`, "c-7x"),
		"a short ms":         ok("1791460800.12:42"),
		"a long ms":          ok("1791460800.1234:42"),
		"a signed ms":        ok("1791460800.+12:42"),
		"no ms":              ok("1791460800:42"),
		"no serial":          ok("1791460800.123"),
		"a bad serial":       ok("1791460800.123:x"),
		"a signed second":    ok("+1791460800.123:42"),
		"a padded second":    ok("01791460800.123:42"),
		"a negative second":  ok("-1.123:42"),
		"no ID":              ok(""),
		"a truncated record": truncated,
		"a health record":    health,
	} {
		if n, at, found := canarySent(x, owner); found {
			t.Errorf("%s: counted as probe %d at %d", name, n, at)
		}
	}
	if _, _, found := canarySent(rawrecord.New(1, store.SensorProvider, 1, 1, []byte(`{"ID":"1.123:1"}`)), owner); found {
		t.Error("a record without a syscall counted")
	}
}

func TestCanaryGapsCoverThePhase(t *testing.T) {
	s := func(sec ...int64) []int64 {
		out := make([]int64, len(sec))
		for i, v := range sec {
			out[i] = v * int64(time.Second)
		}
		return out
	}
	from, to := 100*int64(time.Second), 250*int64(time.Second)
	for _, c := range []struct {
		name  string
		sent  []int64
		count int
		gap   int64
	}{
		{"every 29 s", s(90, 119, 148, 177, 206, 235, 264), 5, 29},
		{"late after the start", s(131, 160, 189, 218, 247), 5, 31},
		{"stopped before the end", s(110, 139, 168, 197), 4, 53},
		{"none", nil, 0, 150},
		{"one missing", s(110, 139, 197, 226), 4, 58},
	} {
		count, gap := canaryGaps(c.sent, from, to)
		if count != c.count || gap != c.gap*int64(time.Second) {
			t.Errorf("%s: %d canaries, longest gap %s; want %d, %d s", c.name, count, time.Duration(gap), c.count, c.gap)
		}
	}
}

// A stage times the first canary sent from the freeze on, the first canary-missed after that, and the first OK
// after both SIGCONT and that UNKNOWN; anything before the freeze or after the watch is not its.
func TestFreezeFactsTimeTheStage(t *testing.T) {
	sec := func(v int64) int64 { return v * int64(time.Second) }
	fr := canaryFreeze{stopped: "yes", from: sec(1000), thaw: sec(1100), until: sec(1145)}
	h := func(at int64, state string) health { return health{kind: "health", state: state, at: sec(at)} }
	sent := []int64{sec(990), sec(1019), sec(1048), sec(1077), sec(1106)}
	timeline := healthTimeline{
		h(900, "OK"), h(995, canaryMissed), h(996, "OK"), h(1030, "UNKNOWN audit-stale"), h(1050, "OK"),
		h(1077, canaryMissed), h(1101, "UNKNOWN audit-stale"), h(1102, "OK"), h(1200, canaryMissed),
	}
	got := map[string]string{}
	for _, f := range fr.facts(sent, timeline) {
		got[f[0]] = f[1]
	}
	want := map[string]string{
		rangevm.CanaryStopped: "yes", rangevm.CanaryHealth: rangevm.StoreOK, rangevm.CanaryFrozenMS: "100000",
		rangevm.CanaryAfterMS: "45000", rangevm.CanaryFirstMS: "19000", rangevm.CanaryUnknownMS: "77000",
		rangevm.CanaryOKMS: "2000",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("facts %v\nwant  %v", got, want)
	}
	// OK while still frozen is no recovery; nothing in the watch leaves each time none.
	got = map[string]string{}
	for _, f := range fr.facts(nil, healthTimeline{h(990, "OK"), h(1060, canaryMissed), h(1090, "OK")}) {
		got[f[0]] = f[1]
	}
	if got[rangevm.CanaryFirstMS] != rangevm.CanaryNone || got[rangevm.CanaryUnknownMS] != "60000" ||
		got[rangevm.CanaryOKMS] != rangevm.CanaryNone {
		t.Errorf("facts %v", got)
	}
	got = map[string]string{}
	for _, f := range fr.facts([]int64{sec(1146)}, healthTimeline{h(1000, "OK")}) {
		got[f[0]] = f[1]
	}
	if got[rangevm.CanaryFirstMS] != rangevm.CanaryNone || got[rangevm.CanaryUnknownMS] != rangevm.CanaryNone ||
		got[rangevm.CanaryHealth] != rangevm.StoreOK {
		t.Errorf("facts %v", got)
	}
}

// The guest does not link the collector, so the health it looks for is checked against the collector's source.
func TestCanaryMissedIsTheCollectorsHealth(t *testing.T) {
	src, err := os.ReadFile("../../internal/collector/writer.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "h = "+strconv.Quote(canaryMissed)+"\n") {
		t.Errorf("the collector's writer sets no health %q", canaryMissed)
	}
}
