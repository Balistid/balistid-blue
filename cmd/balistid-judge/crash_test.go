package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const base = 1_800_000_000 * int64(time.Second)

func sensorAt(serial uint64, at int64) rawrecord.Record {
	return rawrecord.New(0, store.SensorProvider, serial, at, otherLine(serial, "k"))
}

func healthAt(at int64, state string) rawrecord.Record {
	return own(store.HealthProvider, at, `{"schema_version":1,"kind":"health","state":"`+state+`"}`)
}

// TestHealthIsCarried: before the first health record the state is not known, a change away from OK counts from
// itself, and across midnight the seconds are split between the two days.
func TestHealthIsCarried(t *testing.T) {
	sec := int64(time.Second)
	day := (base/dayNS + 1) * dayNS // a midnight after base
	rows := rowsOf(readerOf(t, sensorAt(1, day-100*sec), healthAt(day-90*sec, "OK"), sensorAt(2, day-60*sec),
		healthAt(day-50*sec, "UNKNOWN canary-missed"), sensorAt(3, day+30*sec), healthAt(day+40*sec, "OK"),
		sensorAt(4, day+100*sec)))
	if len(rows) != 2 {
		t.Fatalf("days %+v", rows)
	}
	if r := rows[0]; r.NotKnown != 10 || r.NotOK != 50 {
		t.Errorf("before midnight: not known %v s, not OK %v s", r.NotKnown, r.NotOK)
	}
	if r := rows[1]; r.NotKnown != 0 || r.NotOK != 40 {
		t.Errorf("after midnight: not known %v s, not OK %v s", r.NotKnown, r.NotOK)
	}
}

// TestAChangeIsDatedByItsOwnTime: an UNKNOWN the collector noted at 20 s and the store took at 50 s is not OK from
// 20 s, in the seconds and in the list of changes; an OK noted early counts nothing back.
func TestAChangeIsDatedByItsOwnTime(t *testing.T) {
	sec := int64(time.Second)
	recs := []rawrecord.Record{healthAt(base, "OK")}
	for i := int64(1); i <= 49; i++ {
		recs = append(recs, sensorAt(uint64(i), base+i*sec))
	}
	recs = append(recs, own(store.HealthProvider, base+50*sec, `{"schema_version":1,"kind":"health","state":"UNKNOWN store: x","at":`+
		strconv.FormatInt(base+20*sec, 10)+`,"note_seq":2}`),
		own(store.HealthProvider, base+60*sec, `{"schema_version":1,"kind":"health","state":"OK","at":`+
			strconv.FormatInt(base+55*sec, 10)+`,"note_seq":3}`), sensorAt(50, base+70*sec))
	rd := readerOf(t, recs...)
	if r := rowsOf(rd)[0]; r.NotOK != 40 {
		t.Errorf("not OK %v s, want 20 to 60", r.NotOK)
	}
	if got := rd.trans[1].At; got != timeText(base+20*sec) {
		t.Errorf("the change is dated %s", got)
	}
}

// TestACrashIsAStart: a collector that died with no stopping record and started again is a start in the changes,
// and the time until its next OK is not OK.
func TestACrashIsAStart(t *testing.T) {
	sec := int64(time.Second)
	recs := []rawrecord.Record{healthAt(base, "OK")}
	for i := int64(1); i <= 30; i++ {
		recs = append(recs, sensorAt(uint64(i), base+i*sec))
	}
	recs = append(recs, own(store.HealthProvider, base+40*sec, `{"schema_version":1,"kind":"started","info":{"boot_id":"x"}}`),
		healthAt(base+45*sec, "OK"), sensorAt(31, base+50*sec))
	rd := readerOf(t, recs...)
	if r := rowsOf(rd)[0]; r.NotOK != 5 || rd.trans[1].Kind != "started" {
		t.Errorf("not OK %v s, changes %+v", r.NotOK, rd.trans)
	}
}

// TestLagsByDay: the store's largest lag is the day's, and the arrival lag is the receive time less Laurel's ID.
func TestLagsByDay(t *testing.T) {
	sec := int64(time.Second)
	line := []byte(`{"ID":"` + strconv.FormatInt(base/sec-5, 10) + `.250:7","SYSCALL":{"syscall":257,"key":"k"}}`)
	rows := rowsOf(readerOf(t, own(store.HealthProvider, base, `{"schema_version":1,"kind":"stats","max_lag_ms":1500}`),
		own(store.HealthProvider, base+sec, `{"schema_version":1,"kind":"lag","lag_ms":120000}`),
		rawrecord.New(0, store.SensorProvider, 7, base, line)))
	r := rows[0]
	if r.StoreLag == nil || *r.StoreLag != 120000 || r.ArrivalLag == nil || *r.ArrivalLag != 4750 {
		t.Errorf("store lag %v, arrival lag %v", r.StoreLag, r.ArrivalLag)
	}
}

// TestAnOwnRecordOfAnUnknownKind: a kind the judge does not know may have been a health change, so after it the
// health is not known until the next change, never still OK.
func TestAnOwnRecordOfAnUnknownKind(t *testing.T) {
	sec := int64(time.Second)
	rows := rowsOf(readerOf(t, healthAt(base, "OK"), sensorAt(1, base+10*sec),
		own(store.HealthProvider, base+20*sec, `{"schema_version":1,"kind":"newkind"}`), sensorAt(2, base+50*sec),
		healthAt(base+60*sec, "OK"), sensorAt(3, base+70*sec)))
	if r := rows[0]; r.OwnUnknown != 1 || r.NotKnown != 40 || r.NotOK != 0 {
		t.Errorf("own unknown %d, not known %v s, not OK %v s", r.OwnUnknown, r.NotKnown, r.NotOK)
	}
}

// TestHealthRecordsThatGaveWay: lost_health is the collector run's running total: 0 to 7 is 7 given way, a start
// sets it back, and a fall without a start read begins a run too.
func TestHealthRecordsThatGaveWay(t *testing.T) {
	sec := int64(time.Second)
	stats := func(at int64, n int) rawrecord.Record {
		return own(store.HealthProvider, at, `{"schema_version":1,"kind":"stats","lost_health":`+strconv.Itoa(n)+`}`)
	}
	rows := rowsOf(readerOf(t, stats(base, 0), stats(base+60*sec, 7), stats(base+120*sec, 7),
		own(store.HealthProvider, base+130*sec, `{"schema_version":1,"kind":"started","info":{"boot_id":"x"}}`),
		stats(base+190*sec, 2), stats(base+250*sec, 1)))
	if got := rows[0].HealthLost; got != 10 {
		t.Errorf("health records lost %d, want 7, 2 and 1", got)
	}
}

// TestAProbeIsOneRun: a name with many runs is a program's, never a probe's, however all of them are under agents.
func TestAProbeIsOneRun(t *testing.T) {
	agent := "1795340222.001:1"
	at := time.Date(2026, 11, 28, 10, 0, 1, 0, time.UTC)
	runs := []execRun{{Schema: 1, Name: "claude", Agent: true, Process: procKey{EventID: agent}, eventAt: at}}
	for i := range 50 {
		runs = append(runs, execRun{Schema: 1, Name: "make", PID: 7, eventAt: at,
			Process: procKey{EventID: "1795340222.002:" + strconv.Itoa(i+2)}, SpawnedBy: &spawner{procKey: procKey{EventID: agent}}})
	}
	probes := []probe{{Name: "make", Kind: kindDirect, At: at.Format(time.RFC3339Nano), Ran: true}}
	p := checkProbes(probes, runs, assign(runs), true, false)
	if p.Direct.Assigned != 0 || p.Each[0].Runs != 50 || p.Each[0].Why != moreThanOne {
		t.Errorf("probes %+v", p)
	}
	p = checkProbes(probes, runs[:2], assign(runs[:2]), true, false)
	if p.Direct.Assigned != 1 {
		t.Errorf("one run: %+v", p)
	}
}

// TestProbeRules: a probe is assigned only in a COMPLETE read, as one run under an agent within 5 s of its
// manifest's time; every other probe says why not.
func TestProbeRules(t *testing.T) {
	agent := "1795340222.001:1"
	at := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	run := func(name string, off time.Duration, underAgent bool) execRun {
		r := execRun{Schema: 1, Name: name, PID: 7, eventAt: at.Add(off), Process: procKey{EventID: "1795340222.002:" + name},
			SpawnedBy: &spawner{procKey: procKey{EventID: agent}}}
		if !underAgent {
			r.SpawnedBy = &spawner{procKey: procKey{StartTime: "1.000"}}
		}
		return r
	}
	runs := []execRun{{Schema: 1, Name: "claude", Agent: true, Process: procKey{EventID: agent}},
		run("in", 4*time.Second, true), run("early", -6*time.Second, true), run("outside", 0, false)}
	named := func(name string) probe {
		return probe{Name: name, Kind: kindDirect, At: at.Format(time.RFC3339Nano), Ran: true}
	}
	probes := []probe{named("in"), named("early"), named("outside"), named("gone"), {Name: "in2", Kind: kindDirect,
		At: at.Format(time.RFC3339Nano)}}
	want := map[string]string{"in": "", "early": timeOff, "outside": notUnderAgent, "gone": absent, "in2": notRun}
	p := checkProbes(probes, runs, assign(runs), true, false)
	for _, e := range p.Each {
		if e.Why != want[e.Name] || e.Assigned != (want[e.Name] == "") {
			t.Errorf("%s: %+v", e.Name, e)
		}
	}
	if p.Direct != (kindCount{Count: 5, Found: 3, Assigned: 1}) {
		t.Errorf("direct %+v", p.Direct)
	}
	for _, e := range checkProbes(probes, runs, assign(runs), false, false).Each {
		if e.Assigned || e.Why != notComplete {
			t.Errorf("a read not complete: %+v", e)
		}
	}
}

// TestACycleIsBroken: process keys that spawn each other end as broken, never under an agent or looping.
func TestACycleIsBroken(t *testing.T) {
	runs := []execRun{
		{Schema: 1, Name: "a", Process: procKey{EventID: "1.000:1"}, SpawnedBy: &spawner{procKey: procKey{EventID: "1.000:2"}}},
		{Schema: 1, Name: "b", Process: procKey{EventID: "1.000:2"}, SpawnedBy: &spawner{procKey: procKey{EventID: "1.000:1"}}},
		{Schema: 1, Name: "c", Process: procKey{EventID: "1.000:3"}, SpawnedBy: &spawner{procKey: procKey{EventID: "1.000:3"}}},
	}
	if got := assign(runs); !reflect.DeepEqual(got, []string{broken, broken, broken}) {
		t.Errorf("%v", got)
	}
}

// TestAnAmbiguousSpawnerBreaksTheChain: an event id two runs of other pids carry, as a Laurel restart can write,
// is no link; nor is a spawner whose pid is not the matched run's.
func TestAnAmbiguousSpawnerBreaksTheChain(t *testing.T) {
	agent := execRun{Schema: 1, Name: "claude", PID: 10, Agent: true, Process: procKey{EventID: "1.000:1"}}
	other := execRun{Schema: 1, Name: "vim", PID: 11, Process: procKey{EventID: "1.000:1"}}
	child := execRun{Schema: 1, Name: "make", PID: 12, Process: procKey{EventID: "1.000:2"},
		SpawnedBy: &spawner{procKey: procKey{EventID: "1.000:1"}, PID: 10}}
	if got := assign([]execRun{agent, child}); got[1] != underAgent {
		t.Fatalf("one run of the id: %v", got)
	}
	if got := assign([]execRun{agent, other, child}); got[2] != broken {
		t.Errorf("two runs of the id with other pids: %v", got)
	}
	child.SpawnedBy.PID = 99
	if got := assign([]execRun{agent, child}); got[1] != broken {
		t.Errorf("a spawner pid that is not the run's: %v", got)
	}
}

// TestViewDoesNotNeedTheOrder: exec.jsonl in reversed line order gives the same view.
func TestViewDoesNotNeedTheOrder(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	path := filepath.Join(out, execFile)
	b, err := os.ReadFile(path) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	forward := viewOf(t, out)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil { //nolint:gosec // as the judge writes it
		t.Fatal(err)
	}
	if backward := viewOf(t, out); !reflect.DeepEqual(forward, backward) {
		t.Errorf("forward %+v\nbackward %+v", forward, backward)
	}
}

func TestAUnitsProbesAreRefused(t *testing.T) {
	m := strings.Replace(manifestOf("t", false, time.Now(), [2]string{"a", kindDirect}), `"unit_probes": false`, `"unit_probes": true`, 1)
	if _, err := decodeManifest([]byte(m)); err == nil || !bytes.Contains([]byte(err.Error()), []byte("unit")) {
		t.Errorf("unit_probes true: %v", err)
	}
}
