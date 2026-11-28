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

// oneShard is the state of one shard read whole.
func oneShard(t *testing.T, recs []rawrecord.Record) stateDoc {
	t.Helper()
	st := newState([]store.Seal{{Name: "one"}}, 0, 0, 90)
	st.merge("one", accOf(t, recs...))
	return st.render(0)
}

func cleanAt(d stateDoc, at int64) bool {
	for _, iv := range d.Clean.Intervals {
		from, _ := time.Parse(time.RFC3339Nano, iv.From)
		to, _ := time.Parse(time.RFC3339Nano, iv.To)
		if from.UnixNano() <= at && at <= to.UnixNano() {
			return true
		}
	}
	return false
}

// healthOK and the records every 5 s from 1 s to last, at base.
func everyFive(last int64, between func(i int64) []rawrecord.Record) []rawrecord.Record {
	recs := []rawrecord.Record{own(store.HealthProvider, base, `{"schema_version":1,"kind":"health","state":"OK"}`)}
	serial := uint64(1)
	for i := int64(1); i <= last; i += 5 {
		recs = append(recs, sensorAt(serial, base+i*int64(time.Second)))
		serial++
		recs = append(recs, between(i)...)
	}
	return recs
}

// TestACrashIsNotClean: the collector died after 30 s with no stopping record and its unit started it again at
// 40 s, well inside the 90 s silence: the time it did not run is not clean.
func TestACrashIsNotClean(t *testing.T) {
	sec := int64(time.Second)
	recs := []rawrecord.Record{own(store.HealthProvider, base, `{"schema_version":1,"kind":"health","state":"OK"}`)}
	for i := int64(1); i <= 30; i++ {
		recs = append(recs, sensorAt(uint64(i), base+i*sec))
	}
	recs = append(recs, own(store.HealthProvider, base+40*sec, `{"schema_version":1,"kind":"started","info":{"boot_id":"x"}}`),
		own(store.HealthProvider, base+41*sec, `{"schema_version":1,"kind":"health","state":"OK"}`),
		sensorAt(31, base+50*sec))
	if d := oneShard(t, recs); cleanAt(d, base+35*sec) || !cleanAt(d, base+45*sec) {
		t.Errorf("clean %+v", d.Clean.Intervals)
	}
}

// TestAChangeIsDatedByItsOwnTime: an UNKNOWN the collector noted at 20 s and the store took at 50 s is not clean
// from 20 s.
func TestAChangeIsDatedByItsOwnTime(t *testing.T) {
	sec := int64(time.Second)
	recs := []rawrecord.Record{own(store.HealthProvider, base, `{"schema_version":1,"kind":"health","state":"OK"}`)}
	for i := int64(1); i <= 49; i++ {
		recs = append(recs, sensorAt(uint64(i), base+i*sec))
		if i == 10 {
			recs = append(recs, own(store.HealthProvider, base+10*sec, `{"schema_version":1,"kind":"stats","max_lag_ms":0}`))
		}
	}
	recs = append(recs, own(store.HealthProvider, base+50*sec, `{"schema_version":1,"kind":"health","state":"UNKNOWN store: x","at":`+
		strconv.FormatInt(base+20*sec, 10)+`,"note_seq":2}`),
		own(store.HealthProvider, base+55*sec, `{"schema_version":1,"kind":"health","state":"OK"}`), sensorAt(50, base+60*sec))
	if d := oneShard(t, recs); cleanAt(d, base+15*sec) || cleanAt(d, base+30*sec) || !cleanAt(d, base+58*sec) {
		t.Errorf("clean %+v", d.Clean.Intervals)
	}
}

// TestALongLagIsNotClean: a lag of 120 s reported at 150 s spans the records it delayed; one of 30 s, under the
// stats period, does not cut by itself.
func TestALongLagIsNotClean(t *testing.T) {
	sec := int64(time.Second)
	for lagMS, clean := range map[int]bool{120000: false, 30000: true} {
		d := oneShard(t, everyFive(200, func(i int64) []rawrecord.Record {
			if i != 146 {
				return nil
			}
			return []rawrecord.Record{own(store.HealthProvider, base+150*sec,
				`{"schema_version":1,"kind":"stats","max_lag_ms":`+strconv.Itoa(lagMS)+`}`)}
		}))
		if cleanAt(d, base+100*sec) != clean {
			t.Errorf("lag %d ms: clean %+v", lagMS, d.Clean.Intervals)
		}
	}
}

// TestHealthRecordsThatGaveWay: lost_health rising from 0 to 7 between two stats is counted, and not clean.
func TestHealthRecordsThatGaveWay(t *testing.T) {
	sec := int64(time.Second)
	d := oneShard(t, everyFive(150, func(i int64) []rawrecord.Record {
		switch i {
		case 61:
			return []rawrecord.Record{own(store.HealthProvider, base+62*sec, `{"schema_version":1,"kind":"stats","lost_health":0}`)}
		case 121:
			return []rawrecord.Record{own(store.HealthProvider, base+122*sec, `{"schema_version":1,"kind":"stats","lost_health":7}`)}
		}
		return nil
	}))
	if d.HealthLost != 7 || cleanAt(d, base+100*sec) || !cleanAt(d, base+30*sec) {
		t.Errorf("lost %d, clean %+v", d.HealthLost, d.Clean.Intervals)
	}
}

// TestNotEveryShardReadIsNotClean: under a read limit, and with an older shard not read whose boundary may hold a
// gap, the clean intervals are UNKNOWN with the reason.
func TestNotEveryShardReadIsNotClean(t *testing.T) {
	ts := threeShards(t)
	status, out, _ := judgeOnce(t, ts.dir, stepClock(20*time.Minute))
	if d := readStateDoc(t, out); status != statusPartial || d.Clean.State != statusUnknown || d.Clean.Reason == "" {
		t.Errorf("status %s, clean %+v", status, d.Clean)
	}
	sec := int64(time.Second)
	newer := []rawrecord.Record{own(store.HealthProvider, base+20*sec, `{"schema_version":1,"kind":"health","state":"OK"}`)}
	for s := uint64(20); s <= 30; s++ {
		newer = append(newer, sensorAt(s, base+int64(s+20)*sec))
	}
	st := newState([]store.Seal{{Name: "older"}, {Name: "newer"}}, 0, 0, 90)
	st.merge("newer", accOf(t, newer...))
	if d := st.render(0); d.Clean.State != statusUnknown || len(d.Clean.Intervals) != 0 {
		t.Errorf("the older shard not read: clean %+v", d.Clean)
	}
}

// TestAProbeIsOneRun: a name with many runs is a program's, never a probe's, however all of them are under agents.
func TestAProbeIsOneRun(t *testing.T) {
	agent := "1795340222.001:1"
	runs := []execRun{{Schema: 1, Time: "2026-11-28T10:00:00Z", Name: "claude", Agent: true, Process: procKey{EventID: agent}}}
	for i := range 50 {
		runs = append(runs, execRun{Schema: 1, Time: "2026-11-28T10:00:01Z", Name: "make",
			Process: procKey{EventID: "1795340222.002:" + strconv.Itoa(i+2)}, SpawnedBy: &spawner{procKey: procKey{EventID: agent}}})
	}
	period := &periodDoc{From: "2026-11-28T00:00:00Z", To: "2026-11-28T23:00:00Z"}
	p := checkProbes([]probe{{Name: "make", Kind: kindDirect, At: "2026-11-28T10:00:01Z", Ran: true}}, runs, assign(runs), period)
	if p.Direct.Assigned != 0 || p.Each[0].Runs != 50 {
		t.Errorf("probes %+v", p)
	}
	p = checkProbes([]probe{{Name: "make", Kind: kindDirect, At: "2026-11-28T10:00:01Z", Ran: true}}, runs[:2], assign(runs[:2]), period)
	if p.Direct.Assigned != 1 {
		t.Errorf("one run: %+v", p)
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

// TestViewDoesNotNeedTheOrder: exec.jsonl in reversed line order gives the same view, and view passes on what the
// judge counted and did not list.
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
	if d := readStateDoc(t, out); forward.Covers.Exec != d.Exec.execCounts || forward.Covers.Exec.System != 1 {
		t.Errorf("covers %+v, state %+v", forward.Covers.Exec, d.Exec)
	}
}

func TestAUnitsProbesAreRefused(t *testing.T) {
	m := strings.Replace(manifestOf("t", false, time.Now(), [2]string{"a", kindDirect}), `"unit_probes": false`, `"unit_probes": true`, 1)
	if _, err := decodeManifest([]byte(m)); err == nil || !bytes.Contains([]byte(err.Error()), []byte("unit")) {
		t.Errorf("unit_probes true: %v", err)
	}
}
