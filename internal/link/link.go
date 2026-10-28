// Package link is the wire between the collector and the ledger (ADR 0027, points 2 and 3): typed,
// length-prefixed frames of at most MaxFrame bytes, decoded strictly. Both ends treat the other as
// untrusted input (T19), so Read accepts exactly what Write produces.
package link

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/Balistid/balistid-blue/internal/entry"
)

const (
	// MaxFrame bounds a frame's body.
	MaxFrame = 64 << 10
	// MaxRecords bounds the records of one frame: each takes at most 50 bytes.
	MaxRecords = 1024
)

// The frame types. Hello goes from the ledger; the others from the collector.
const (
	typeHello   = 1
	typeRecords = 2
	typeSeal    = 3
	typeHealth  = 4
)

// Hello is where the ledger's log resumes: after Last, the last seq of its last batch, whose First and
// Root the collector checks against its own leaves.
type Hello struct {
	Last, First uint64
	Root        [32]byte
}

// Record is a committed record's seq and leaf, with the loss it carries, if any.
type Record struct {
	Seq  uint64
	Leaf [32]byte
	Loss *entry.Loss // Loss.Seq is Seq
}

// Records are consecutive records, at least one, at most MaxRecords.
type Records []Record

// Message is what a frame carries: Hello, Records, entry.Seal or entry.Health.
type Message any

// Write sends m as one frame.
func Write(w io.Writer, m Message) error {
	b, err := encode(m)
	if err != nil {
		return err
	}
	if _, err := w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b)))); err != nil { //nolint:gosec // encode bounds b by MaxFrame
		return fmt.Errorf("link: write: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("link: write: %w", err)
	}
	return nil
}

// Read takes one frame off r and decodes it; anything Write could not have produced is an error.
func Read(r io.Reader) (Message, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("link: read: %w", err)
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("link: frame of %d bytes", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("link: read: %w", err)
	}
	return Decode(b)
}

func encode(m Message) ([]byte, error) {
	if err := check(m); err != nil {
		return nil, err
	}
	switch m := m.(type) {
	case Hello:
		b := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64([]byte{typeHello}, m.Last), m.First)
		return append(b, m.Root[:]...), nil
	case Records:
		b := binary.BigEndian.AppendUint16([]byte{typeRecords}, uint16(len(m))) //nolint:gosec // check bounds it by MaxRecords
		for _, r := range m {
			b = append(binary.BigEndian.AppendUint64(b, r.Seq), r.Leaf[:]...)
			if r.Loss == nil {
				b = append(b, 0)
				continue
			}
			b = binary.BigEndian.AppendUint64(append(b, 1, byte(r.Loss.Stage)), r.Loss.Records)
		}
		return b, nil
	case entry.Seal:
		b := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64([]byte{typeSeal}, m.First), m.Last)
		return append(b, m.SHA256[:]...), nil
	case entry.Health:
		return binary.BigEndian.AppendUint64([]byte{typeHealth, byte(m.State), byte(m.Reason)}, m.Unstored), nil
	}
	return nil, errors.New("link: not a message")
}

// check refuses what the ledger could not log: the fields of loss, seal and health follow entry's
// rules, and records are consecutive.
func check(m Message) error {
	var bodies []entry.Body
	switch m := m.(type) {
	case Hello:
		if (m.Last == 0) != (m.First == 0 && m.Root == [32]byte{}) {
			return errors.New("link: hello of an empty log with a batch, or the reverse")
		}
		if m.Last != 0 {
			bodies = append(bodies, entry.Batch{First: m.First, Last: m.Last, Root: m.Root})
		}
	case Records:
		if len(m) == 0 || len(m) > MaxRecords {
			return fmt.Errorf("link: %d records in a frame", len(m))
		}
		for i, r := range m {
			if i > 0 && r.Seq != m[i-1].Seq+1 {
				return errors.New("link: records out of sequence")
			}
			// A batch of the one record checks its seq (the leaf is any hash, so a one stands in).
			bodies = append(bodies, entry.Batch{First: r.Seq, Last: r.Seq, Root: [32]byte{1}})
			if r.Loss != nil {
				if r.Loss.Seq != r.Seq {
					return errors.New("link: a record carries another record's loss")
				}
				bodies = append(bodies, *r.Loss)
			}
		}
	case entry.Seal, entry.Health:
		bodies = append(bodies, m.(entry.Body))
	default:
		return errors.New("link: not a message")
	}
	for _, b := range bodies {
		if _, err := (entry.Entry{Body: b}).Encode(); err != nil {
			return fmt.Errorf("link: %w", err)
		}
	}
	return nil
}

// Frame sizes: hello and seal are a type, two seqs and a hash; health a type, two bytes and a count; a
// record a seq, a leaf and a flag, and a loss's stage and count when the flag is set.
const (
	rangeFrame  = 1 + 8 + 8 + 32
	healthFrame = 1 + 1 + 1 + 8
	recordBytes = 8 + 32 + 1
	lossBytes   = 1 + 8
)

// Decode returns the message in a frame's body.
func Decode(b []byte) (Message, error) {
	if len(b) == 0 {
		return nil, errors.New("link: empty frame")
	}
	u64 := func(i int) uint64 { return binary.BigEndian.Uint64(b[i : i+8]) }
	var m Message
	switch t := b[0]; {
	case (t == typeHello || t == typeSeal) && len(b) == rangeFrame:
		if t == typeHello {
			m = Hello{Last: u64(1), First: u64(9), Root: [32]byte(b[17:49])}
		} else {
			m = entry.Seal{First: u64(1), Last: u64(9), SHA256: [32]byte(b[17:49])}
		}
	case t == typeHealth && len(b) == healthFrame:
		m = entry.Health{State: entry.State(b[1]), Reason: entry.Reason(b[2]), Unstored: u64(3)}
	case t == typeRecords && len(b) >= 3:
		recs, err := decodeRecords(b)
		if err != nil {
			return nil, err
		}
		m = recs
	default:
		return nil, errors.New("link: unknown frame type or size")
	}
	if err := check(m); err != nil {
		return nil, err
	}
	return m, nil
}

func decodeRecords(b []byte) (Records, error) {
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if n > MaxRecords {
		return nil, fmt.Errorf("link: %d records in a frame", n)
	}
	recs, i := make(Records, 0, n), 3
	for range n {
		if len(b)-i < recordBytes {
			return nil, errors.New("link: frame ends inside a record")
		}
		rec := Record{Seq: binary.BigEndian.Uint64(b[i : i+8]), Leaf: [32]byte(b[i+8 : i+40])}
		flag := b[i+40]
		i += recordBytes
		switch {
		case flag == 1 && len(b)-i >= lossBytes:
			rec.Loss = &entry.Loss{Seq: rec.Seq, Stage: entry.Stage(b[i]), Records: binary.BigEndian.Uint64(b[i+1 : i+9])}
			i += lossBytes
		case flag != 0:
			return nil, errors.New("link: bad record flag or a loss cut short")
		}
		recs = append(recs, rec)
	}
	if i != len(b) {
		return nil, errors.New("link: bytes after the records")
	}
	return recs, nil
}
