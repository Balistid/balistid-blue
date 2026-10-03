package rangevm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func stream(t testing.TB, recs ...Record) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range recs {
		if err := Append(&buf, r); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func fact(name, value string) Record {
	return Record{SchemaVersion: SchemaVersion, Kind: KindFact, Name: name, Value: value}
}

func end(n int) Record { return Record{SchemaVersion: SchemaVersion, Kind: KindEnd, Count: n} }

func raw(body string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body))) //nolint:gosec // test bodies are far below 4 GiB
	return append(n[:], body...)
}

func TestParseAcceptsCompleteStream(t *testing.T) {
	data := append(stream(t, fact("kernel", "k"), fact("net", "lo"), end(2)), make([]byte, 64)...)
	facts, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 || facts[1].Value != "lo" {
		t.Fatalf("facts = %+v", facts)
	}
}

func TestParseRejects(t *testing.T) {
	qcow2 := append([]byte("QFI\xfb\x00\x00\x00\x03"), make([]byte, 504)...) // read as a length, the magic is far over the cap
	cases := map[string][]byte{
		"empty disk":                 make([]byte, 1024),
		"length prefix out of range": qcow2,
		"fact after the end":         append(stream(t, end(0)), stream(t, fact("net", "eth0"))...),
		"second end":                 stream(t, end(0), end(999)),
		"no end record":              stream(t, fact("kernel", "k")),
		"wrong end count":            stream(t, fact("kernel", "k"), end(2)),
		"truncated body":             stream(t, fact("kernel", "k"), end(1))[:10],
		"oversized record":           append(raw(`{"schema_version":1,"kind":"fact","name":"n","value":"`+strings.Repeat("x", MaxRecordBytes)+`"}`), stream(t, end(1))...),
		"unknown field":              raw(`{"schema_version":1,"kind":"end","count":0,"x":1}`),
		"unknown kind":               raw(`{"schema_version":1,"kind":"verdict","name":"a"}`),
		"future schema":              raw(`{"schema_version":2,"kind":"end"}`),
		"trailing data":              raw(`{"schema_version":1,"kind":"end"} {}`),
		"fact without name":          append(raw(`{"schema_version":1,"kind":"fact","value":"v"}`), stream(t, end(1))...),
		"end with name":              raw(`{"schema_version":1,"kind":"end","name":"x"}`),
		"not json":                   raw(`kernel=7`),
		"end beyond the limit":       stream(t, fact("kernel", strings.Repeat("k", 100)), end(1)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			limit := int64(len(data))
			if name == "end beyond the limit" {
				limit = 50
			}
			if facts, err := Parse(bytes.NewReader(data), limit); err == nil {
				t.Fatalf("accepted: %+v", facts)
			}
		})
	}
}

func TestAppendRefusesOversizedRecord(t *testing.T) {
	var buf bytes.Buffer
	if err := Append(&buf, fact("kernel", strings.Repeat("k", MaxRecordBytes))); err == nil {
		t.Fatal("oversized record encoded")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(stream(f, fact("kernel", "k"), fact("net", "lo"), end(2)))
	f.Add(raw(`{"schema_version":1,"kind":"end"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		facts, err := Parse(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		for _, r := range facts {
			if r.Kind != KindFact || r.Name == "" || r.SchemaVersion != SchemaVersion {
				t.Fatalf("accepted malformed fact %+v", r)
			}
		}
	})
}
