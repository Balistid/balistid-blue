package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

// tally is a store counted record by record straight from shard.Read, without the judge's reader: what its days
// must add up to, and the runs exec.jsonl must hold.
type tally struct {
	records map[string]uint64
	bytes   uint64
	loss    map[string]uint64
	keys    map[string]keyCount
	exec    execCounts // Listed holds every run of a user, listed or not
	runs    map[string][]string
	from    string // the newest seal's UTC day less 7
}

func tallyOf(t *testing.T, dir string) tally {
	t.Helper()
	seals, err := store.ReadSeals(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	c := tally{records: map[string]uint64{}, loss: map[string]uint64{}, keys: map[string]keyCount{},
		runs: map[string][]string{}}
	if n := len(seals); n > 0 {
		c.from = time.Unix(seals[n-1].Sealed, 0).UTC().AddDate(0, 0, -7).Format(time.DateOnly)
	}
	for _, l := range seals {
		err := shard.Read(t.Context(), dir+"/"+l.Name, l.SHA256, shard.Scratch{Dir: t.TempDir(), Max: 600 << 20},
			func(r rawrecord.Record) error { c.add(t, r); return nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func (c *tally) add(t *testing.T, r rawrecord.Record) {
	day := time.Unix(0, r.Received).UTC().Format(time.DateOnly)
	c.bytes += r.OrigLen
	var own struct {
		Kind    string `json:"kind"`
		Stage   string `json:"stage"`
		Count   uint64 `json:"count"`
		Dropped uint64 `json:"dropped"`
	}
	switch r.Provider {
	case store.SensorProvider, store.HealthProvider, store.LossProvider:
		c.records[r.Provider]++
	default:
		c.records["other"]++
	}
	switch {
	case r.Provider == store.HealthProvider && json.Unmarshal(r.Data, &own) == nil && own.Kind == "lost" && own.Count > 0:
		if own.Stage == "dispatcher" {
			own.Count = 1
		}
		c.loss[own.Stage] += own.Count
	case r.Provider == store.LossProvider && json.Unmarshal(r.Data, &own) == nil && own.Dropped > 0:
		c.loss["cap"] += own.Dropped
	case r.Provider == store.SensorProvider && r.Truncated():
		c.loss["truncated"]++
	case r.Provider == store.SensorProvider:
		c.sensor(t, r, day)
	}
}

func (c *tally) sensor(t *testing.T, r rawrecord.Record, day string) {
	rec, err := decodeLine(r.Data)
	if err != nil {
		return
	}
	k := c.keys[rec.Key]
	k.Records, k.Bytes = k.Records+1, k.Bytes+r.OrigLen
	c.keys[rec.Key] = k
	switch {
	case rec.Refused != "":
		c.exec.Refused++
	case rec.Unlisted == unlistedExecveat:
		c.exec.Execveat++
	case rec.Unlisted == unlistedOtherArch:
		c.exec.OtherArch++
	}
	switch {
	case !rec.Exec:
		return
	case !rec.Whole:
		c.exec.Partial++
	case rec.Run.UID < minUID:
		c.exec.System++
	default:
		c.exec.Listed++
		line := rec.Run
		line.EventTime, line.Received, line.Serial = timeText(rec.EventNS), timeText(r.Received), r.ProviderSeq
		b, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		c.runs[day] = append(c.runs[day], string(b))
	}
	c.exec.Successful++
}

// listed is the runs received on the window's days, sorted.
func (c *tally) listed() []string {
	var out []string
	for d, runs := range c.runs {
		if d >= c.from {
			out = append(out, runs...)
		}
	}
	slices.Sort(out)
	return out
}

// checkSums is the judge's output in out against the store's tally.
func checkSums(t *testing.T, dir, out string) {
	t.Helper()
	c := tallyOf(t, dir)
	d := readStateDoc(t, out)
	all := totalOf(d.Days)
	if !reflect.DeepEqual(all.Records, c.records) || all.Bytes != c.bytes {
		t.Errorf("records %v, %d bytes; the store holds %v, %d", all.Records, all.Bytes, c.records, c.bytes)
	}
	if !reflect.DeepEqual(all.Loss, c.loss) {
		t.Errorf("loss %v, the store's %v", all.Loss, c.loss)
	}
	users := all.Exec
	users.Listed, users.Outside, users.OverCap = users.Listed+users.Outside+users.OverCap, 0, 0
	if users != c.exec {
		t.Errorf("exec %+v, the store's %+v", all.Exec, c.exec)
	}
	keys := map[string]keyCount{}
	for k, v := range d.Keys {
		keys[k] = *v
	}
	if !reflect.DeepEqual(keys, c.keys) {
		t.Errorf("by rule key %v, the store's %v", keys, c.keys)
	}
	var lines []string
	for _, r := range readExec(t, out) {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	slices.Sort(lines)
	if want := c.listed(); !slices.Equal(lines, want) {
		t.Errorf("exec.jsonl holds %d runs, the store's window %d", len(lines), len(want))
	}
}

// nineDays is a store of runs received on 9 days, the oldest first: one day more than the window.
func nineDays(t *testing.T) *testStore {
	t.Helper()
	ts := newTestStore(t, 16<<20)
	now := time.Now()
	for d := range 9 {
		ts.laurelAt(uint64(d+1), now.Add(time.Duration(d-8)*24*time.Hour).UnixNano(), tool(uint64(d+1), 1000, "d"+strconv.Itoa(d)))
	}
	ts.seal(true)
	return ts
}

// TestDaysAddUpToTheStore: on every fixture store the days add up to what the store holds, counted apart.
func TestDaysAddUpToTheStore(t *testing.T) {
	for name, build := range map[string]func(*testing.T) *testStore{"three shards": threeShards, "agent tree": agentTree,
		"nine days": nineDays, "planned": func(t *testing.T) *testStore { return plannedStore(t, func(int) bool { return true }) }} {
		t.Run(name, func(t *testing.T) {
			ts := build(t)
			status, out, err := judgeOnce(t, ts.dir, nil)
			if status != statusComplete || err != nil {
				t.Fatal(status, err)
			}
			checkSums(t, ts.dir, out)
		})
	}
}

// plannedStore is a store of three shards: an agent's tree of runs, health changes, losses, stats with lost_health,
// a cut line and a new boot. keep says which of its steps are written: one dropped is a record the store lost.
func plannedStore(t *testing.T, keep func(int) bool) *testStore {
	t.Helper()
	ts := newTestStore(t, 16<<20)
	ev := func(s uint64) string { return `"EVENT_ID":"` + eventOf(s) + `"` }
	var steps []func()
	run := func(e execSpec) {
		e.ok = true
		if e.uid == 0 {
			e.uid = 1000
		}
		steps = append(steps, func() { ts.laurel(e.serial, e.line()) })
	}
	note := func(kind string, f map[string]any) { steps = append(steps, func() { ts.own(kind, f) }) }
	note("started", map[string]any{"info": map[string]string{"boot_id": "b1"}})
	note("health", map[string]any{"state": "OK"})
	run(execSpec{serial: 10, pid: 110, ppid: 50, exe: agentExe, spawner: `"START_TIME":"1795340000.000"`, spawnPID: 50, spawnExe: "/usr/bin/bash"})
	for s := uint64(11); s < 40; s++ {
		run(execSpec{serial: s, pid: uint32(s + 100), ppid: uint32(s + 99), exe: "/usr/bin/p" + strconv.Itoa(int(s%4)),
			spawner: ev(s - 1), spawnPID: uint32(s + 99), spawnExe: "/usr/bin/bash"})
	}
	note("stats", map[string]any{"lost_health": 2, "max_lag_ms": 40})
	steps = append(steps, func() { ts.seal(false) })
	note("lost", map[string]any{"stage": "queue", "count": 3, "bytes": 300, "first_seq": 0, "last_seq": 0, "first_at": 1, "last_at": 2})
	for s := uint64(40); s < 60; s++ {
		steps = append(steps, func() { ts.laurel(s, otherLine(s, "balistid-open")) })
	}
	steps = append(steps, func() {
		ts.laurel(60, append([]byte(`{"ID":"1.000:60",`), bytes.Repeat([]byte("a"), rawrecord.MaxBytes)...))
	})
	note("health", map[string]any{"state": "UNKNOWN canary-missed"})
	note("stats", map[string]any{"lost_health": 5, "max_lag_ms": 70})
	note("health", map[string]any{"state": "OK"})
	steps = append(steps, func() { ts.seal(false) })
	note("started", map[string]any{"info": map[string]string{"boot_id": "b2"}})
	for s := uint64(1); s < 20; s++ { // the new boot's serials, with event ids of their own
		run(execSpec{serial: s, pid: uint32(s + 500), ppid: 1, exe: "/usr/bin/q" + strconv.Itoa(int(s%3)), spawner: ev(10),
			spawnPID: 110, spawnExe: agentExe, proc: `"EVENT_ID":"1795349999.000:` + strconv.Itoa(int(s)) + `"`})
	}
	note("stats", map[string]any{"lost_health": 1})
	for i, step := range steps {
		if keep(i) {
			step()
		}
	}
	ts.seal(true)
	return ts
}

// atLeast is every number of a judge's output named or meant as a lower bound, by day and name.
func atLeast(t *testing.T, out string) map[string]uint64 {
	t.Helper()
	n := map[string]uint64{}
	d := readStateDoc(t, out)
	for _, r := range d.Days {
		for k, v := range r.Records {
			n[r.Day+" records "+k] = v
		}
		for k, v := range r.Loss {
			n[r.Day+" loss "+k] = v
		}
		n[r.Day+" bytes"], n[r.Day+" successful"], n[r.Day+" listed"] = r.Bytes, r.Exec.Successful, r.Exec.Listed
	}
	n["health records lost"] = totalOf(d.Days).HealthLost
	v := viewOf(t, out)
	for _, day := range v.Days {
		if day.Read {
			n[day.Day+" runs"], n[day.Day+" under agent"] = day.Runs, day.UnderAgent
		}
	}
	for _, nc := range v.Top {
		n["top "+nc.Name] = nc.Count
	}
	return n
}

// TestDroppedRecordsRaiseNoLowerBound: a store that lost records, for several choices of which, gives no lower
// bound above the whole store's, in state.json or in view.
func TestDroppedRecordsRaiseNoLowerBound(t *testing.T) {
	_, out, err := judgeOnce(t, plannedStore(t, func(int) bool { return true }).dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	whole := atLeast(t, out)
	for seed := range 6 {
		ts := plannedStore(t, func(i int) bool { return (i*7919+seed*104729)%5 != 0 })
		_, out, err := judgeOnce(t, ts.dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range atLeast(t, out) {
			if v > whole[k] {
				t.Errorf("seed %d: %s is %d, %d in the whole store", seed, k, v, whole[k])
			}
		}
	}
}

// startDays is records over 5 UTC days: serials with holes, runs, health changes, losses, stats and a new boot.
func startDays() []rawrecord.Record {
	sec := int64(time.Second)
	var recs []rawrecord.Record
	serial := uint64(1)
	for d := range int64(5) {
		at := base + d*dayNS
		if d == 0 || d == 3 {
			boot := "b" + strconv.Itoa(int(d))
			recs = append(recs, own(store.HealthProvider, at, `{"schema_version":1,"kind":"started","info":{"boot_id":"`+boot+`"}}`))
			if d == 3 {
				serial = 1
			}
		}
		recs = append(recs, healthAt(at+sec, "OK"))
		for i := range int64(40) {
			if i%13 != 5 {
				recs = append(recs, rawrecord.New(0, store.SensorProvider, serial, at+(i+2)*sec, tool(serial, 1000, "t"+strconv.Itoa(int(i%3)))))
			}
			serial++
		}
		recs = append(recs, own(store.HealthProvider, at+50*sec, `{"schema_version":1,"kind":"stats","max_lag_ms":`+strconv.Itoa(int(d)*10)+
			`,"lost_health":`+strconv.Itoa(int(d%3)*2)+`}`),
			own(store.HealthProvider, at+51*sec, `{"schema_version":1,"kind":"lost","stage":"kernel","count":2,"bytes":0,"first_seq":0,`+
				`"last_seq":0,"first_at":0,"last_at":0,"at":1,"note_seq":1}`),
			healthAt(at+52*sec, "UNKNOWN canary-missed"), healthAt(at+3600*sec, "OK"), sensorAt(serial, at+3601*sec))
		serial++
	}
	return recs
}

// TestTheStartChangesNoLaterDay: a read that starts at day k gives the days after it as a read from the first,
// listed runs too, but for the health carried into them, which the later start does not know.
func TestTheStartChangesNoLaterDay(t *testing.T) {
	recs := startDays()
	listFrom := dayOf(base) + 2
	whole := rowsOf(readerFrom(t, listFrom, recs...))
	if whole[1].Exec.Outside == 0 || whole[1].Exec.Listed != 0 || whole[2].Exec.Listed == 0 {
		t.Fatalf("the window is not between days 1 and 2: %+v, %+v", whole[1].Exec, whole[2].Exec)
	}
	for k := 1; k <= 3; k++ {
		day := dayOf(base) + int64(k)
		i := slices.IndexFunc(recs, func(r rawrecord.Record) bool { return dayOf(r.Received) >= day })
		late := rowsOf(readerFrom(t, listFrom, recs[i:]...))
		for j := range late[1:] {
			a, b := whole[k+1+j], late[1+j]
			a.NotOK, a.NotKnown, b.NotOK, b.NotKnown = 0, 0, 0, 0
			if !reflect.DeepEqual(a, b) {
				t.Errorf("start at day %d, day %s:\nwhole %+v\nlate  %+v", k, a.Day, a, b)
			}
		}
	}
}

// TestAnotherBootsSerialsAcrossShards: boot b1 holds 9, 10 and 12, a late 9 in a shard of its own; boot b2 holds 11
// and 13, its started record last in a shard or first in the next. A serial fills a hole only in its own run: two
// runs of the counter and two serials missing, one in each.
func TestAnotherBootsSerialsAcrossShards(t *testing.T) {
	for name, lateShard := range map[string]bool{"started last in a shard": false, "a late serial between": true} {
		ts := newTestStore(t, 16<<20)
		ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b1"}})
		ts.laurel(10, otherLine(10, "k"))
		ts.laurel(12, otherLine(12, "k"))
		if lateShard {
			ts.seal(false)
			ts.laurel(9, otherLine(9, "k"))
			ts.seal(false)
			ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b2"}})
		} else {
			ts.laurel(9, otherLine(9, "k"))
			ts.own("started", map[string]any{"info": map[string]string{"boot_id": "b2"}})
			ts.seal(false)
		}
		ts.laurel(11, otherLine(11, "k"))
		ts.laurel(13, otherLine(13, "k"))
		ts.seal(true)
		_, out, err := judgeOnce(t, ts.dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		d := readStateDoc(t, out)
		if all := totalOf(d.Days); d.Serials.Segments != 2 || all.Gaps != 2 || all.Missing != 2 {
			t.Errorf("%s: %d segments, %d gaps, %d missing", name, d.Serials.Segments, all.Gaps, all.Missing)
		}
	}
}

// TestTheLastShardPastTheLimitIsPartial: a short last shard whose read takes the judge past the limit, with no
// look at the clock inside it, is PARTIAL, never COMPLETE.
func TestTheLastShardPastTheLimitIsPartial(t *testing.T) {
	ts := newTestStore(t, 16<<20)
	ts.laurel(1, otherLine(1, "k"))
	ts.seal(true)
	calls := 0
	start := time.Now()
	clock := func() time.Time {
		calls++
		if calls > 4 { // the start, the first files, the shard's check, its state.json
			return start.Add(2 * readLimit)
		}
		return start
	}
	status, out, err := judgeOnce(t, ts.dir, clock)
	if d := readStateDoc(t, out); status != statusPartial || err == nil || d.Status != statusPartial || len(d.Read) != 1 {
		t.Errorf("status %s, on disk %s, read %d, %v", status, d.Status, len(d.Read), err)
	}
	// Every shard was read whole: the state and view say so, not that something is unread.
	d := readStateDoc(t, out)
	if v := viewOf(t, out); len(d.NotRead) != 0 || !strings.Contains(d.Reason, "while the last shard was read") ||
		!strings.Contains(v.Covers.Partial, "no sealed shard it lists is unread") {
		t.Errorf("reason %q, not read %v, view %q", d.Reason, d.NotRead, v.Covers.Partial)
	}
}

// TestAStoreWithNoSealIsUnknown: a store whose index holds no seal gives nothing read, which is UNKNOWN, never
// COMPLETE (R6).
func TestAStoreWithNoSealIsUnknown(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a store directory, as the collector keeps it
		t.Fatal(err)
	}
	status, out, err := judgeOnce(t, dir, nil)
	if d := readStateDoc(t, out); status != statusUnknown || err == nil || d.Status != statusUnknown ||
		d.Reason != "the store holds no sealed shard" {
		t.Errorf("status %s, on disk %s %q, %v", status, d.Status, d.Reason, err)
	}
}

// TestAProbeOnlyInAnUnsealedShardIsSaid: in a COMPLETE read beside an unsealed shard, a probe with no run may be in
// that shard: its reason says so, and it is not assigned.
func TestAProbeOnlyInAnUnsealedShardIsSaid(t *testing.T) {
	ts := agentTree(t)
	_, out, _ := judgeOnce(t, ts.dir, nil)
	editState(t, out, func(d *stateDoc) { d.Unsealed = []string{"00000000000000000099.db"} })
	v := viewOf(t, out, treeManifests(t, false)...)
	for _, e := range v.Probes.Each {
		if e.Name == "s1p-t-d01" && (e.Assigned || e.Why != absentSealed) {
			t.Errorf("a probe the sealed shards lack: %+v", e)
		}
		if e.Name == "s1p-t-d00" && !e.Assigned {
			t.Errorf("the probe the store holds: %+v", e)
		}
	}
}

// TestTheBudgetPicksTheStart: the read starts at the first shard of the oldest UTC day whose shards to the newest fit
// the byte budget; when the newest day alone does not fit, at its first shard.
func TestTheBudgetPicksTheStart(t *testing.T) {
	day := int64(86400)
	seals := []store.Seal{{Sealed: day}, {Sealed: 2 * day}, {Sealed: 2*day + 1}, {Sealed: 3 * day}}
	for _, c := range []struct {
		sizes []int64
		want  int
	}{
		{[]int64{1, 1, 1, 1}, 0},
		{[]int64{budgetBytes, 1, 1, 1}, 1},
		{[]int64{1, budgetBytes - 1, 1, 1}, 3},
		{[]int64{1, 1, 1, budgetBytes + 1}, 3},
	} {
		if got := startOf(seals, c.sizes); got != c.want {
			t.Errorf("sizes %v: start %d, want %d", c.sizes, got, c.want)
		}
	}
	if startOf(nil, nil) != 0 {
		t.Error("no seal")
	}
}

// TestShardsBeforeTheStartAreNamed: those before the start are not read, with the reason, and the oldest day read
// says shards before it were not.
func TestShardsBeforeTheStartAreNamed(t *testing.T) {
	ts := threeShards(t)
	seals, err := store.ReadSeals(t.Context(), ts.dir)
	if err != nil {
		t.Fatal(err)
	}
	st := newState(seals, 0, 2, 90)
	rd := readerOf(t, sensorAt(1, base))
	d := st.render(rd, 0)
	if len(d.NotRead) != 4 || !strings.Contains(d.NotRead[0].Reason, "byte budget") || !strings.Contains(d.NotRead[1].Reason, "byte budget") ||
		d.NotRead[2].Reason != "not read yet" || !d.Days[0].Earlier || !d.Days[0].Later {
		t.Errorf("not read %+v, days %+v", d.NotRead, d.Days)
	}
}
