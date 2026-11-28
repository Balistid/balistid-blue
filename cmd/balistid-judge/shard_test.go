package main

import (
	"bufio"
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

func accOf(t *testing.T, recs ...rawrecord.Record) *shardAcc {
	t.Helper()
	a := newShardAcc(0, bufio.NewWriter(io.Discard))
	for i, r := range recs {
		r.Seq = uint64(i + 1)
		if err := a.add(r); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func own(provider string, at int64, data string) rawrecord.Record {
	return rawrecord.New(0, provider, 0, at, []byte(data))
}

// TestLossAsLossOfCountsIt: the store's loss record, the collector's lost record, a truncated sensor record and an
// unknown provider are each a loss lossOf would count or refuse; anything the judge cannot decode is a span too.
func TestLossAsLossOfCountsIt(t *testing.T) {
	sec := int64(time.Second)
	long := append([]byte(`{"ID":"1.000:9",`), bytes.Repeat([]byte("a"), rawrecord.MaxBytes)...)
	a := accOf(t,
		own(store.HealthProvider, 1*sec, `{"schema_version":1,"kind":"health","state":"OK","at":1,"note_seq":1}`),
		own(store.LossProvider, 2*sec, `{"schema_version":1,"dropped":5,"first_received":500000000,"last_received":600000000}`),
		own(store.HealthProvider, 3*sec, `{"schema_version":1,"kind":"lost","stage":"dispatcher","count":9,"bytes":0,`+
			`"first_seq":0,"last_seq":0,"first_at":0,"last_at":0,"at":3,"note_seq":2}`),
		own(store.HealthProvider, 4*sec, `{"schema_version":1,"kind":"lost","stage":"elsewhere","count":1,"bytes":0,`+
			`"first_seq":0,"last_seq":0,"first_at":0,"last_at":0,"at":4,"note_seq":3}`),
		own(store.HealthProvider, 5*sec, `{"schema_version":1,"kind":"lost","stage":"queue","count":2,"extra":1}`),
		own(store.HealthProvider, 6*sec, `{"schema_version":1,"kind":"newkind"}`),
		own(store.HealthProvider, 7*sec, `{"schema_version":2,"kind":"health","state":"OK"}`),
		rawrecord.New(0, store.SensorProvider, 9, 8*sec, long),
		own("someone", 9*sec, `{}`),
	)
	if a.loss["cap"] != 5 || a.loss["dispatcher"] != 1 || a.loss["truncated"] != 1 || len(a.loss) != 3 {
		t.Errorf("loss %v", a.loss)
	}
	if a.lossErrors != 3 || a.ownUnknown != 2 {
		t.Errorf("loss records not decoded %d, own unknown %d", a.lossErrors, a.ownUnknown)
	}
	want := []span{{From: 1 * sec, To: 2 * sec}, {From: 1 * sec, To: 3 * sec}, {From: 3 * sec, To: 4 * sec},
		{From: 4 * sec, To: 5 * sec}, {From: 5 * sec, To: 6 * sec}, {From: 6 * sec, To: 7 * sec},
		{From: 7 * sec, To: 8 * sec}, {From: 8 * sec, To: 9 * sec}}
	want[0].From = 500000000 // the store's first drop, before the last own record
	if len(a.spans) != len(want) {
		t.Fatalf("spans %+v", a.spans)
	}
	for i := range want {
		if a.spans[i] != want[i] {
			t.Errorf("span %d %+v, want %+v", i, a.spans[i], want[i])
		}
	}
}

// TestALossBeforeAnyOwnRecordStartsInTheOlderShard: its span starts at the older shard's last own record.
func TestALossBeforeAnyOwnRecordStartsInTheOlderShard(t *testing.T) {
	sec := int64(time.Second)
	older := accOf(t, own(store.HealthProvider, 10*sec, `{"schema_version":1,"kind":"health","state":"OK"}`),
		rawrecord.New(0, store.SensorProvider, 1, 11*sec, otherLine(1, "k")))
	newer := accOf(t, own(store.HealthProvider, 20*sec, `{"schema_version":1,"kind":"lost","stage":"queue","count":1,`+
		`"bytes":0,"first_seq":0,"last_seq":0,"first_at":0,"last_at":0,"at":3,"note_seq":2}`),
		rawrecord.New(0, store.SensorProvider, 2, 21*sec, otherLine(2, "k")))
	st := newState([]store.Seal{{Name: "older"}, {Name: "newer"}}, 0, 0, 90)
	st.merge("newer", newer)
	if len(st.open) != 1 {
		t.Fatalf("open spans %+v", st.open)
	}
	st.merge("older", older)
	if len(st.open) != 0 || !containsSpan(st.spans, span{From: 10 * sec, To: 20 * sec}) {
		t.Errorf("open %+v, spans %+v", st.open, st.spans)
	}
	d := st.render(0)
	if d.Clean.State != "KNOWN" || len(d.Clean.Intervals) != 1 || d.Clean.Intervals[0].From != timeText(20*sec) {
		t.Errorf("clean %+v", d.Clean)
	}
}

func containsSpan(spans []span, s span) bool {
	for _, x := range spans {
		if x == s {
			return true
		}
	}
	return false
}

func TestSilenceAndClockSteps(t *testing.T) {
	sec := int64(time.Second)
	a := accOf(t, own(store.HealthProvider, 10*sec, `{"schema_version":1,"kind":"health","state":"OK"}`),
		rawrecord.New(0, store.SensorProvider, 1, 200*sec, otherLine(1, "k")),
		rawrecord.New(0, store.SensorProvider, 2, 150*sec, otherLine(2, "k")))
	if a.silences != 1 || a.clockBack != 1 || !containsSpan(a.spans, span{From: 10 * sec, To: 200 * sec}) ||
		!containsSpan(a.spans, span{From: 150 * sec, To: 200 * sec}) {
		t.Errorf("silences %d, clock back %d, spans %+v", a.silences, a.clockBack, a.spans)
	}
}

func TestSerialGaps(t *testing.T) {
	sec := int64(time.Second)
	cases := map[string]struct {
		add                 func(*serials)
		gaps, missing, held uint64
		segments            int
		duplicates          uint64
	}{
		"late fills": {add: func(s *serials) {
			for i, n := range []uint64{1, 2, 4, 3, 5} {
				s.add(n, int64(i)*sec)
			}
		}, segments: 1},
		"a gap long before the end, one near it": {add: func(s *serials) {
			for i, n := range []uint64{1, 2, 5, 6} {
				s.add(n, int64(i)*sec)
			}
			s.add(8, 200*sec)
		}, gaps: 1, missing: 2, held: 1, segments: 1},
		"a duplicate": {add: func(s *serials) {
			s.add(1, 0)
			s.add(2, 0)
			s.add(2, 0)
		}, segments: 1, duplicates: 1},
		"a new boot": {add: func(s *serials) {
			s.started("b1")
			s.add(100, 0)
			s.started("b2")
			s.add(1, 300*sec)
		}, segments: 2},
		"a restart on the same boot loses serials": {add: func(s *serials) {
			s.started("b1")
			s.add(100, 0)
			s.started("b1")
			s.add(110, 1*sec)
			s.add(111, 300*sec)
		}, gaps: 1, missing: 9, segments: 1},
		"a restart below the highest is another run": {add: func(s *serials) {
			s.add(100, 0)
			s.started("")
			s.add(3, 300*sec)
		}, segments: 2},
		"the counter wraps": {add: func(s *serials) {
			s.add(1<<32-2, 0)
			s.add(1, 300*sec)
		}, segments: 2},
	}
	for name, c := range cases {
		var s serials
		c.add(&s)
		var got gapCount
		last := s.segs[len(s.segs)-1]
		for _, g := range s.segs {
			got.add(g, last.ranges[len(last.ranges)-1].hiAt-gapHold)
		}
		if got.gaps != c.gaps || got.missing != c.missing || got.held != c.held || len(s.segs) != c.segments ||
			got.duplicate != c.duplicates {
			t.Errorf("%s: %+v in %d segments", name, got, len(s.segs))
		}
	}
}

// TestSerialsPastTheCap: past maxHeld holes the oldest is counted at once, so memory stays bounded and none is lost.
func TestSerialsPastTheCap(t *testing.T) {
	var s serials
	for i := uint64(0); i <= maxHeld+10; i++ {
		s.add(2*i, 0)
	}
	g := s.segs[0]
	var c gapCount
	c.add(g, 1)
	if len(g.ranges) > maxHeld || c.gaps != maxHeld+10 || c.overCap != 11 || c.missing != maxHeld+10 {
		t.Errorf("%d ranges, %d gaps, %d at the cap, %d missing", len(g.ranges), c.gaps, c.overCap, c.missing)
	}
}
