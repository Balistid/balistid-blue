// Package rangevm runs one attack-range VM as decided in ADR 0009 and reads what the guest reported.
package rangevm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SchemaVersion is the only record schema readers accept.
const SchemaVersion = 1

// MaxRecordBytes caps one record body; the guest is hostile input (THREAT_MODEL T30).
const MaxRecordBytes = 64 << 10

// Record kinds. A stream is facts followed by exactly one end record.
const (
	KindFact = "fact"
	KindEnd  = "end"
)

// Record is one length-prefixed entry on the results disk.
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Name          string `json:"name,omitempty"`
	Value         string `json:"value,omitempty"`
	Count         int    `json:"count,omitempty"`
}

// Append encodes rec as a 4-byte big-endian length followed by its JSON body.
func Append(buf *bytes.Buffer, rec Record) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	if len(body) > MaxRecordBytes {
		return fmt.Errorf("record of %d bytes exceeds %d", len(body), MaxRecordBytes)
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body))) //nolint:gosec // bounded by MaxRecordBytes above
	buf.Write(n[:])
	buf.Write(body)
	return nil
}

// Parse reads at most limit bytes and returns the facts before the end record. Anything else
// than well-formed facts closed by an end record with the right count is an error, so a crashed,
// truncated, oversized or forged stream can never read as a complete one (R6).
func Parse(r io.Reader, limit int64) ([]Record, error) {
	lr := io.LimitReader(r, limit)
	var facts []Record
	for {
		var n [4]byte
		if _, err := io.ReadFull(lr, n[:]); err != nil {
			return nil, fmt.Errorf("stream ends without an end record after %d facts: %w", len(facts), err)
		}
		size := binary.BigEndian.Uint32(n[:])
		if size == 0 || size > MaxRecordBytes {
			return nil, fmt.Errorf("record %d has length %d, want 1..%d", len(facts), size, MaxRecordBytes)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(lr, body); err != nil {
			return nil, fmt.Errorf("record %d is truncated: %w", len(facts), err)
		}
		rec, err := decode(body)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", len(facts), err)
		}
		if rec.Kind == KindEnd {
			if rec.Count != len(facts) {
				return nil, fmt.Errorf("end record counts %d facts, stream has %d", rec.Count, len(facts))
			}
			return facts, nil
		}
		facts = append(facts, rec)
	}
}

func decode(body []byte) (Record, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return Record{}, fmt.Errorf("decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("trailing data after the JSON object")
	}
	if rec.SchemaVersion != SchemaVersion {
		return Record{}, fmt.Errorf("schema_version %d, want %d", rec.SchemaVersion, SchemaVersion)
	}
	switch rec.Kind {
	case KindFact:
		if rec.Name == "" || rec.Count != 0 {
			return Record{}, errors.New("a fact needs a name and no count")
		}
	case KindEnd:
		if rec.Name != "" || rec.Value != "" {
			return Record{}, errors.New("an end record carries only the count")
		}
	default:
		return Record{}, fmt.Errorf("unknown kind %q", rec.Kind)
	}
	return rec, nil
}
