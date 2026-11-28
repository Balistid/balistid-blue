package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
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
	if len(rows) != 2 || rows[0].Day != "1970-01-01" || rows[1].Day != "1970-01-03" {
		t.Fatalf("days %+v", rows)
	}
	if l := rows[0].Loss; l["cap"] != 5 || l["dispatcher"] != 1 || l["truncated"] != 1 || len(l) != 3 {
		t.Errorf("loss %v", l)
	}
	if r := rows[0]; r.LossErrors != 3 || r.OwnUnknown != 2 || r.Records["other"] != 1 {
		t.Errorf("loss records not decoded %d, own unknown %d, records %v", r.LossErrors, r.OwnUnknown, r.Records)
	}
	if l := rows[1].Loss; l["kernel"] != 4 || len(l) != 1 {
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

// TestSerialSteps: neighbouring sensor records' serials, auditd's own lines and records without a serial left out:
// 9 after 6 jumps over 2, 7 after 9 and 7 again step back, 8 after 7 goes on.
func TestSerialSteps(t *testing.T) {
	sec := int64(time.Second)
	daemon := rawrecord.New(0, store.SensorProvider, 100, base+4*sec, []byte(`{"ID":"1.000:100","DAEMON_END":{}}`))
	rows := rowsOf(readerOf(t, sensorAt(5, base), sensorAt(6, base+sec), sensorAt(9, base+2*sec), daemon,
		sensorAt(7, base+5*sec), rawrecord.New(0, store.SensorProvider, 0, base+6*sec, otherLine(0, "k")),
		sensorAt(7, base+7*sec), sensorAt(8, base+8*sec)))
	if r := rows[0]; r.Jumps != 1 || r.Skipped != 2 || r.StepsBack != 2 || r.Undecoded["no serial"] != 1 {
		t.Errorf("%d jumps over %d, %d steps back, undecoded %v", r.Jumps, r.Skipped, r.StepsBack, r.Undecoded)
	}
}

// TestHealthChangesAsStored: a change is listed with both its times as they are, the earlier one not chosen; a
// day's lost_health_max is the largest a stats record of it carried, and absent on a day with none.
func TestHealthChangesAsStored(t *testing.T) {
	sec := int64(time.Second)
	stats := func(at int64, n int) rawrecord.Record {
		return own(store.HealthProvider, at, `{"schema_version":1,"kind":"stats","lost_health":`+strconv.Itoa(n)+`}`)
	}
	rd := readerOf(t, own(store.HealthProvider, base+50*sec, `{"schema_version":1,"kind":"health","state":"UNKNOWN store: x","at":`+
		strconv.FormatInt(base+20*sec, 10)+`}`), stats(base+60*sec, 3), stats(base+70*sec, 7), stats(base+80*sec, 2),
		sensorAt(1, base+dayNS))
	if h := rd.trans[0]; h.Received != timeText(base+50*sec) || h.At != timeText(base+20*sec) || h.State != "UNKNOWN store: x" {
		t.Errorf("the change %+v", h)
	}
	rows := rowsOf(rd)
	if rows[0].LostHealth == nil || *rows[0].LostHealth != 7 || rows[1].LostHealth != nil {
		t.Errorf("lost_health_max %v, %v", rows[0].LostHealth, rows[1].LostHealth)
	}
	b, err := json.Marshal(rows[1])
	if err != nil || bytes.Contains(b, []byte("lost_health_max")) {
		t.Errorf("a day with no stats: %s %v", b, err)
	}
}

// TestALongHealthStateIsCut: a state of 4 KiB of bytes JSON escapes is listed as printable ASCII, cut at maxState
// bytes and marked, so maxEvents of the largest change, encoded, stay under what view reads of state.json.
func TestALongHealthStateIsCut(t *testing.T) {
	long := "a\\u0001<é" + strings.Repeat("\\u0000", 600)
	rd := readerOf(t, own(store.HealthProvider, base, `{"schema_version":1,"kind":"health","state":"`+long+`"}`))
	s := rd.trans[0].State
	if len(s) != maxState+len(cutMark) || !strings.HasPrefix(s, "a?????") || !strings.HasSuffix(s, cutMark) {
		t.Errorf("state of %d bytes: %q", len(s), s)
	}
	worst := rd.trans[0]
	worst.Seq, worst.Received, worst.At = math.MaxUint64, timeText(math.MinInt64), timeText(math.MinInt64)
	one, err := json.Marshal(worst)
	if err != nil || bytes.ContainsRune(one, '\\') {
		t.Fatalf("%s %v", one, err)
	}
	b, err := json.MarshalIndent(stateDoc{Health: slices.Repeat([]transition{worst}, maxEvents)}, "", " ")
	if err != nil || len(b) > stateMax {
		t.Errorf("%d changes of a cut state are %d bytes, view reads %d (%v)", maxEvents, len(b), stateMax, err)
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

// TestANoteThatDoesNotDecodeGivesNothing: a stats or lag note that does not decode is an own record not known, and
// neither its lags nor its lost_health are the day's.
func TestANoteThatDoesNotDecodeGivesNothing(t *testing.T) {
	for _, kind := range []string{"stats", "lag"} {
		rows := rowsOf(readerOf(t, own(store.HealthProvider, base,
			`{"schema_version":1,"kind":"`+kind+`","max_lag_ms":"x","lag_ms":99,"lost_health":99}`)))
		if r := rows[0]; r.OwnUnknown != 1 || r.StoreLag != nil || r.LostHealth != nil {
			t.Errorf("%s: unknown %d, lag %v, lost_health %v", kind, r.OwnUnknown, r.StoreLag, r.LostHealth)
		}
	}
}

// TestAnEmptyHealthStateIsNotListed: a health note with no state is an own record not known, not a change.
func TestAnEmptyHealthStateIsNotListed(t *testing.T) {
	rd := readerOf(t, healthAt(base, ""))
	if rows := rowsOf(rd); len(rd.trans) != 0 || rows[0].OwnUnknown != 1 {
		t.Errorf("changes %v, unknown %d", rd.trans, rows[0].OwnUnknown)
	}
}

// TestRuleKeysAreCappedByDay: a day counts maxKeys rule keys and the records of any later key apart; the next day's
// keys are its own, whatever came first.
func TestRuleKeysAreCappedByDay(t *testing.T) {
	var recs []rawrecord.Record
	for i := range maxKeys + 2 {
		recs = append(recs, rawrecord.New(0, store.SensorProvider, uint64(i+1), base, otherLine(uint64(i+1), strconv.Itoa(i))))
	}
	next := uint64(maxKeys + 3)
	recs = append(recs, rawrecord.New(0, store.SensorProvider, next, base+dayNS, otherLine(next, "late")))
	rows := rowsOf(readerOf(t, recs...))
	if len(rows[0].Keys) != maxKeys || rows[0].KeysOver != 2 || rows[0].Keys["0"] == nil {
		t.Errorf("first day: %d keys, %d over", len(rows[0].Keys), rows[0].KeysOver)
	}
	if k := rows[1].Keys; len(k) != 1 || k["late"] == nil || k["late"].Records != 1 || rows[1].KeysOver != 0 {
		t.Errorf("second day: %v, %d over", k, rows[1].KeysOver)
	}
}
