package main

import (
	"fmt"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

func healthAt(received int64, data string) rawrecord.Record {
	return rawrecord.New(1, store.HealthProvider, 0, received, []byte(data))
}

func refusedAt(received, firstAt, at int64, count, uid int) rawrecord.Record {
	return healthAt(received, fmt.Sprintf(`{"schema_version":1,"kind":"refused","socket":"collector.sock","count":%d,`+
		`"causes":{"uid":%d},"first_at":%d,"last_at":%d,"at":%d,"rule_version":"adr-0004-v2","last_uid":0,"last_error":""}`,
		count, uid, firstAt, at, at))
}

// Summaries before and behind the barrier add up; the longest wait from a first refusal to its record
// counts; health records of other kinds during the flood are counted, before or after it they are not.
func TestRefusalScan(t *testing.T) {
	s := refusalScan{from: 1000, to: 2000}
	for _, x := range []rawrecord.Record{
		refusedAt(1500, 1000, 1400, 10, 10),
		healthAt(1600, `{"schema_version":1,"kind":"stats","lost":0,"lost_health":0}`),
		healthAt(1700, `{"schema_version":1,"kind":"connection","causes":{"start":1}}`),
		healthAt(1800, `{"schema_version":1,"event":"recovered"}`),
		rawrecord.New(1, store.LossProvider, 0, 1900, []byte(`{}`)),
		rawrecord.New(1, store.SensorProvider, 1, 1900, []byte(`{"ID":"1.0:1"}`)),
		healthAt(2500, `{"schema_version":1,"kind":"connection","causes":{"eof":1}}`),
	} {
		_ = s.before(x)
	}
	_ = s.after(refusedAt(2600, 1450, 2600, 5, 4))
	_ = s.after(healthAt(2700, `{"schema_version":1,"kind":"stopping"}`))
	if s.count != 15 || s.uid != 14 || s.summaries != 2 || s.latency != 1150 || s.missing != "" || s.other != 3 {
		t.Errorf("scan %+v", s)
	}
}

// A summary without a field the acceptance method names is reported by that field, and not counted.
func TestRefusalScanNamesAMissingField(t *testing.T) {
	for field, data := range map[string]string{
		"rule_version":       `{"schema_version":1,"kind":"refused","socket":"s","count":1,"causes":{"uid":1},"first_at":1,"at":2,"last_uid":0}`,
		"socket":             `{"schema_version":1,"kind":"refused","count":1,"causes":{"uid":1},"first_at":1,"at":2,"rule_version":"r","last_uid":0}`,
		"causes":             `{"schema_version":1,"kind":"refused","socket":"s","count":1,"first_at":1,"at":2,"rule_version":"r","last_uid":0}`,
		"last_uid":           `{"schema_version":1,"kind":"refused","socket":"s","count":1,"causes":{"uid":1},"first_at":1,"at":2,"rule_version":"r"}`,
		"first_at before at": `{"schema_version":1,"kind":"refused","socket":"s","count":1,"causes":{"uid":1},"first_at":3,"at":2,"rule_version":"r","last_uid":0}`,
	} {
		s := refusalScan{}
		_ = s.after(healthAt(1, data))
		if s.missing != field || s.count != 0 || s.summaries != 1 {
			t.Errorf("%s: %+v", field, s)
		}
	}
}
