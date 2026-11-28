package main

import (
	"bufio"
	"bytes"
	"io"
	"math"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// readerOf is the reader after recs, numbered in order, as one pass reads them, listing runs of every day.
func readerOf(t *testing.T, recs ...rawrecord.Record) *reader {
	t.Helper()
	return readerFrom(t, math.MinInt64, recs...)
}

// readerFrom is readerOf listing the runs of listFrom's day and later only.
func readerFrom(t *testing.T, listFrom int64, recs ...rawrecord.Record) *reader {
	t.Helper()
	rd := newReader(listFrom)
	rd.out = bufio.NewWriter(io.Discard)
	for i, r := range recs {
		r.Seq = uint64(i + 1)
		if err := rd.add(r); err != nil {
			t.Fatal(err)
		}
	}
	return rd
}

// rowsOf is the reader's days as state.json has them.
func rowsOf(rd *reader) []dayRow {
	return newState(nil, 0, 0, 90).render(rd, 0).Days
}

func own(provider string, at int64, data string) rawrecord.Record {
	return rawrecord.New(0, provider, 0, at, []byte(data))
}

// TestLossAsLossOfCountsIt: the store's loss record, the collector's lost record, a truncated sensor record and an
// unknown provider are each a loss lossOf would count or refuse, on the day the store took it.
func TestLossAsLossOfCountsIt(t *testing.T) {
	sec := int64(time.Second)
	long := append([]byte(`{"ID":"1.000:9",`), bytes.Repeat([]byte("a"), rawrecord.MaxBytes)...)
	rows := rowsOf(readerOf(t,
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
		own(store.HealthProvider, 2*dayNS, `{"schema_version":1,"kind":"lost","stage":"kernel","count":4,"bytes":0,`+
			`"first_seq":0,"last_seq":0,"first_at":0,"last_at":0,"at":3,"note_seq":4}`),
	))
	// The day between holds no record; its row holds the seconds the health was not known, carried through it.
	if len(rows) != 3 || rows[0].Day != "1970-01-01" || rows[1].Records["laurel"] != 0 || rows[1].NotKnown != 86400 || rows[2].Day != "1970-01-03" {
		t.Fatalf("days %+v", rows)
	}
	if l := rows[0].Loss; l["cap"] != 5 || l["dispatcher"] != 1 || l["truncated"] != 1 || len(l) != 3 {
		t.Errorf("loss %v", l)
	}
	if r := rows[0]; r.LossErrors != 3 || r.OwnUnknown != 2 || r.Records["other"] != 1 {
		t.Errorf("loss records not decoded %d, own unknown %d, records %v", r.LossErrors, r.OwnUnknown, r.Records)
	}
	if l := rows[2].Loss; l["kernel"] != 4 || len(l) != 1 {
		t.Errorf("the third day's loss %v", l)
	}
}

func TestSilenceAndClockSteps(t *testing.T) {
	sec := int64(time.Second)
	rows := rowsOf(readerOf(t, own(store.HealthProvider, 10*sec, `{"schema_version":1,"kind":"health","state":"OK"}`),
		rawrecord.New(0, store.SensorProvider, 1, 200*sec, otherLine(1, "k")),
		rawrecord.New(0, store.SensorProvider, 2, 150*sec, otherLine(2, "k")),
		rawrecord.New(0, store.SensorProvider, 3, 160*sec, otherLine(3, "k"))))
	if r := rows[0]; r.Silences != 1 || r.ClockBack != 1 {
		t.Errorf("silences %d, clock back %d", r.Silences, r.ClockBack)
	}
}

// gapsOf counts the holes add leaves in s, those of the run being read too.
func gapsOf(s *serials, add func(func(uint64, int64))) (gaps, missing uint64) {
	count := func(m uint64, _ int64) { gaps, missing = gaps+1, missing+m }
	add(count)
	if s.cur != nil {
		s.cur.holes(count)
	}
	return gaps, missing
}

func TestSerialGaps(t *testing.T) {
	sec := int64(time.Second)
	cases := map[string]struct {
		add           func(*serials, func(uint64, int64))
		gaps, missing uint64
		segments      int
		duplicates    uint64
	}{
		"late fills": {add: func(s *serials, g func(uint64, int64)) {
			for i, n := range []uint64{1, 2, 4, 3, 5} {
				s.add(n, int64(i)*sec, g)
			}
		}, segments: 1},
		"a gap, however late its end": {add: func(s *serials, g func(uint64, int64)) {
			for i, n := range []uint64{1, 2, 5, 6} {
				s.add(n, int64(i)*sec, g)
			}
			s.add(8, 200*sec, g)
		}, gaps: 2, missing: 3, segments: 1},
		"a duplicate": {add: func(s *serials, g func(uint64, int64)) {
			s.add(1, 0, g)
			s.add(2, 0, g)
			s.add(2, 0, g)
		}, segments: 1, duplicates: 1},
		"a new boot": {add: func(s *serials, g func(uint64, int64)) {
			s.started("b1")
			s.add(100, 0, g)
			s.started("b2")
			s.add(1, 300*sec, g)
		}, segments: 2},
		"a restart on the same boot loses serials": {add: func(s *serials, g func(uint64, int64)) {
			s.started("b1")
			s.add(100, 0, g)
			s.started("b1")
			s.add(110, 1*sec, g)
			s.add(111, 300*sec, g)
		}, gaps: 1, missing: 9, segments: 1},
		"a restart of a boot not known is another run": {add: func(s *serials, g func(uint64, int64)) {
			s.add(100, 0, g)
			s.started("b1")
			s.add(110, 1*sec, g)
		}, segments: 2},
		"a restart below the highest is another run": {add: func(s *serials, g func(uint64, int64)) {
			s.started("b1")
			s.add(100, 0, g)
			s.started("b1")
			s.add(3, 300*sec, g)
		}, segments: 2},
		"the counter wraps": {add: func(s *serials, g func(uint64, int64)) {
			s.add(1<<32-2, 0, g)
			s.add(1, 300*sec, g)
		}, segments: 2},
		// A serial fills a hole only in its own run: 11 after the new boot is the new run's, not the 11 the old missed.
		"another boot's serial fills no hole": {add: func(s *serials, g func(uint64, int64)) {
			s.started("b1")
			s.add(10, 0, g)
			s.add(12, 0, g)
			s.started("b2")
			s.add(11, 1*sec, g)
			s.add(13, 2*sec, g)
		}, gaps: 2, missing: 2, segments: 2},
	}
	for name, c := range cases {
		var s serials
		gaps, missing := gapsOf(&s, func(g func(uint64, int64)) { c.add(&s, g) })
		if gaps != c.gaps || missing != c.missing || s.segments != c.segments || s.duplicate != c.duplicates {
			t.Errorf("%s: %d gaps, %d missing, %d segments, %d duplicates", name, gaps, missing, s.segments, s.duplicate)
		}
	}
}

// TestSerialsPastTheCap: past maxHeld holes the oldest is counted at once, so memory stays bounded and none is lost.
func TestSerialsPastTheCap(t *testing.T) {
	var s serials
	gaps, missing := gapsOf(&s, func(g func(uint64, int64)) {
		for i := uint64(0); i <= maxHeld+10; i++ {
			s.add(2*i, 0, g)
		}
	})
	if len(s.cur.ranges) > maxHeld || gaps != maxHeld+10 || s.overCap != 11 || missing != maxHeld+10 {
		t.Errorf("%d ranges, %d gaps, %d at the cap, %d missing", len(s.cur.ranges), gaps, s.overCap, missing)
	}
}

// TestAGapIsCountedOnTheDayOfItsLaterEnd: serial 2 missing between one received on day 0 and one on day 1 is day 1's.
func TestAGapIsCountedOnTheDayOfItsLaterEnd(t *testing.T) {
	rows := rowsOf(readerOf(t, sensorAt(1, dayNS-int64(time.Second)), sensorAt(3, dayNS+int64(time.Second))))
	if len(rows) != 2 || rows[0].Gaps != 0 || rows[1].Gaps != 1 || rows[1].Missing != 1 {
		t.Errorf("days %+v", rows)
	}
}

// TestTooManyDaysIsAnError: records on more than maxDays UTC days stop the read instead of growing it.
func TestTooManyDaysIsAnError(t *testing.T) {
	rd := newReader(math.MinInt64)
	var err error
	for d := int64(0); d <= maxDays && err == nil; d++ {
		err = rd.add(sensorAt(uint64(d+1), d*dayNS))
	}
	if err == nil || len(rd.rows) > maxDays {
		t.Errorf("%d days, %v", len(rd.rows), err)
	}
}
