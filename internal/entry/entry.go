// Package entry is the encoding of the ledger's log entries (ADR 0026): one typed event per entry,
// hashes and ranges only, never a record body. The Pi decodes what root on the host wrote (T16), so
// Decode accepts exactly what Encode produces and nothing else.
package entry

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"regexp"
)

const (
	// Label starts every encoding; a change of any field needs a new label (ADR 0026, point 1).
	Label = "balistid/entry/v1"
	// MaxBytes bounds an encoding; the largest entry is far below it.
	MaxBytes = 256
	// MaxOrigin bounds a final entry's origin.
	MaxOrigin = 128
	// MaxSeq is the highest seq the store issues; it issues none below 1.
	MaxSeq = math.MaxInt64
)

// Type is an entry's type byte.
type Type byte

// The entry types of ADR 0026, point 1, with loss and health from ADR 0027, point 6.
const (
	TypeBatch    Type = 1
	TypeSeal     Type = 2
	TypeLoss     Type = 3
	TypeHealth   Type = 4
	TypeAnnounce Type = 5
	TypeFinal    Type = 6
)

// Entry is one log entry. At is the host's time in nanoseconds since 1970 UTC: information only, it
// never decides a security question (T22).
type Entry struct {
	At   int64
	Body Body
}

// Body is what an entry says: a Batch, Seal, Loss, Health, Announce or Final.
type Body interface {
	Type() Type
	check() error
	append(b []byte) []byte
}

// Batch anchors the records First to Last: Root is the RFC 6962 root over their rawrecord leaves.
type Batch struct {
	First, Last uint64
	Root        [32]byte
}

// Seal is a sealed shard of the store's index: its seq range and SHA-256. Its name follows from First.
type Seal struct {
	First, Last uint64
	SHA256      [32]byte
}

// Stage is where records were lost (ADR 0027, point 6). A new stage widens Decode: the Pi gets it first.
type Stage byte

// The stages: the store's cap or a full filesystem, the collector's queue, framing, store and shutdown
// losses, and a record stored truncated.
const (
	StageCap       Stage = 1
	StageQueue     Stage = 2
	StageFraming   Stage = 3
	StageStore     Stage = 4
	StageShutdown  Stage = 5
	StageTruncated Stage = 6
)

// Loss counts records lost at one stage; Seq is the stored record that says so, which for a truncated
// record is the record itself.
type Loss struct {
	Seq     uint64
	Stage   Stage
	Records uint64
}

// State is the collector's health.
type State byte

// The states: OK, or UNKNOWN for a Reason.
const (
	StateOK      State = 1
	StateUnknown State = 2
)

// Reason says why the collector is UNKNOWN; OK has none. A new reason widens Decode: the Pi gets it first.
type Reason byte

// The reasons of the collector's health (ADR 0017, ADR 0027 point 6).
const (
	ReasonNone               Reason = 0
	ReasonStarting           Reason = 1
	ReasonStoreDown          Reason = 2
	ReasonLaurelDisconnected Reason = 3
	ReasonCanaryMissed       Reason = 4
	ReasonCanaryPending      Reason = 5
)

// Health is the collector's state, sent beside the store (ADR 0017, point 7); Unstored counts the
// records it counted lost and has not stored yet.
type Health struct {
	State    State
	Reason   Reason
	Unstored uint64
}

// Announcement is what an announce entry tells the Pi to expect.
type Announcement byte

// Announcements of a clean stop (ADR 0006, point 3).
const (
	AnnounceShutdown Announcement = 1
	AnnounceSuspend  Announcement = 2
)

// Announce says the host is about to shut down or suspend.
type Announce struct{ Kind Announcement }

// Final is the last entry of a yearly log; NextOrigin names the log that follows it.
type Final struct{ NextOrigin string }

// Type is the body's type byte.
func (Batch) Type() Type    { return TypeBatch }
func (Seal) Type() Type     { return TypeSeal }
func (Loss) Type() Type     { return TypeLoss }
func (Health) Type() Type   { return TypeHealth }
func (Announce) Type() Type { return TypeAnnounce }
func (Final) Type() Type    { return TypeFinal }

// An origin is visible ASCII without '+', which C2SP signed notes keep out of key names (ADR 0026).
var originPattern = regexp.MustCompile(fmt.Sprintf(`^[!-*,-~]{1,%d}$`, MaxOrigin))

func (b Batch) check() error { return checkRange("batch", b.First, b.Last, b.Root) }

func (s Seal) check() error { return checkRange("seal", s.First, s.Last, s.SHA256) }

// checkRange refuses seqs the store never issues, a range that ends before it starts, and an all-zero
// hash: no SHA-256 is zero in practice, so zero is a field never filled in.
func checkRange(kind string, first, last uint64, hash [32]byte) error {
	switch {
	case first < 1 || last > MaxSeq:
		return fmt.Errorf("entry: %s seq outside 1 to %d", kind, uint64(MaxSeq))
	case first > last:
		return fmt.Errorf("entry: %s first after last", kind)
	case hash == [32]byte{}:
		return fmt.Errorf("entry: %s hash is zero", kind)
	}
	return nil
}

func (l Loss) check() error {
	switch {
	case l.Seq < 1 || l.Seq > MaxSeq:
		return fmt.Errorf("entry: loss seq outside 1 to %d", uint64(MaxSeq))
	case l.Stage < StageCap || l.Stage > StageTruncated:
		return errors.New("entry: unknown loss stage")
	case l.Records == 0:
		return errors.New("entry: loss of no records")
	case l.Stage == StageTruncated && l.Records != 1:
		return errors.New("entry: a truncated loss is its one record")
	}
	return nil
}

func (h Health) check() error {
	switch {
	case h.State == StateOK && h.Reason == ReasonNone:
	case h.State == StateUnknown && h.Reason >= ReasonStarting && h.Reason <= ReasonCanaryPending:
	default:
		return errors.New("entry: health state and reason do not match")
	}
	return nil
}

func (a Announce) check() error {
	if a.Kind != AnnounceShutdown && a.Kind != AnnounceSuspend {
		return errors.New("entry: unknown announcement")
	}
	return nil
}

func (f Final) check() error {
	if !originPattern.MatchString(f.NextOrigin) {
		return fmt.Errorf("entry: next origin is not 1 to %d visible ASCII bytes without '+'", MaxOrigin)
	}
	return nil
}

func (b Batch) append(out []byte) []byte {
	out = binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(out, b.First), b.Last)
	return append(out, b.Root[:]...)
}

func (s Seal) append(out []byte) []byte {
	out = binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint64(out, s.First), s.Last)
	return append(out, s.SHA256[:]...)
}

func (l Loss) append(out []byte) []byte {
	out = append(binary.BigEndian.AppendUint64(out, l.Seq), byte(l.Stage))
	return binary.BigEndian.AppendUint64(out, l.Records)
}

func (h Health) append(out []byte) []byte {
	return binary.BigEndian.AppendUint64(append(out, byte(h.State), byte(h.Reason)), h.Unstored)
}

func (a Announce) append(out []byte) []byte { return append(out, byte(a.Kind)) }

func (f Final) append(out []byte) []byte { return appendString(out, f.NextOrigin) }

// appendString appends s with its one-byte length; check has bounded every string far below 256.
func appendString(out []byte, s string) []byte {
	return append(append(out, byte(len(s))), s...) //nolint:gosec // check bounded s below 256 bytes
}

// Encode returns the label, a zero byte, the type byte, At big-endian, then the body's fields in
// declaration order: integers as 8 big-endian bytes, a stage, state, reason or announcement as one byte, strings as
// a length byte and the bytes. It refuses an entry Decode would refuse, so the ledger never logs one.
func (e Entry) Encode() ([]byte, error) {
	// Only the body values Decode returns: a pointer would panic when nil and come back as a value.
	switch e.Body.(type) {
	case Batch, Seal, Loss, Health, Announce, Final:
	default:
		return nil, errors.New("entry: no body, or a body that is not one of the entry values")
	}
	if err := e.Body.check(); err != nil {
		return nil, err
	}
	out := append(append(make([]byte, 0, MaxBytes), Label...), 0, byte(e.Body.Type()))
	out = binary.BigEndian.AppendUint64(out, uint64(e.At)) //nolint:gosec // two's complement keeps every int64 distinct
	return e.Body.append(out), nil
}

// Decode returns the entry encoded in b. Anything Encode could not have produced is refused: another
// label or type, a field out of range, a short or trailing byte, more than MaxBytes. Errors never quote b.
func Decode(b []byte) (Entry, error) {
	if len(b) > MaxBytes {
		return Entry{}, fmt.Errorf("entry: over %d bytes", MaxBytes)
	}
	r := reader{b: b}
	if label := r.take(len(Label) + 1); string(label) != Label+"\x00" {
		return Entry{}, errors.New("entry: not a balistid/entry/v1 encoding")
	}
	t := Type(r.u8())
	e := Entry{At: int64(r.u64())} //nolint:gosec // the inverse of Encode
	switch t {
	case TypeBatch:
		e.Body = Batch{First: r.u64(), Last: r.u64(), Root: r.hash()}
	case TypeSeal:
		e.Body = Seal{First: r.u64(), Last: r.u64(), SHA256: r.hash()}
	case TypeLoss:
		e.Body = Loss{Seq: r.u64(), Stage: Stage(r.u8()), Records: r.u64()}
	case TypeHealth:
		e.Body = Health{State: State(r.u8()), Reason: Reason(r.u8()), Unstored: r.u64()}
	case TypeAnnounce:
		e.Body = Announce{Kind: Announcement(r.u8())}
	case TypeFinal:
		e.Body = Final{NextOrigin: r.str()}
	default:
		return Entry{}, errors.New("entry: unknown type")
	}
	switch {
	case r.short:
		return Entry{}, errors.New("entry: encoding ends inside a field")
	case len(r.b) != 0:
		return Entry{}, errors.New("entry: bytes after the entry")
	}
	if err := e.Body.check(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// reader takes fields off the front of b; past its end it gives zero values and sets short.
type reader struct {
	b     []byte
	short bool
}

func (r *reader) take(n int) []byte {
	if n > len(r.b) {
		r.short, r.b = true, nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (r *reader) hash() (h [32]byte) {
	copy(h[:], r.take(32))
	return h
}

func (r *reader) str() string { return string(r.take(int(r.u8()))) }
