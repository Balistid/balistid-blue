// Package rawrecord is the evidence unit of ADR 0005: the bytes a sensor delivered with our sequence
// number, the provider's and the receive time, and the leaf hash the Merkle log anchors.
package rawrecord

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	// Label starts every encoding; a change of Encode needs a new label (ADR 0005, point 2).
	Label = "balistid/raw/v1"
	// MaxBytes of sensor data kept per record (acceptance record_max_kib).
	MaxBytes = 2048 << 10
)

// Record is one stored record. OrigLen and OrigSHA256 describe the data as delivered; Data holds all
// of it, or its first and last MaxBytes/2 bytes when it was longer than MaxBytes.
type Record struct {
	Seq         uint64
	Provider    string
	ProviderSeq uint64
	Received    int64 // nanoseconds since 1970 UTC
	Data        []byte
	OrigLen     uint64
	OrigSHA256  [32]byte
}

// New returns the record of a copy of data, received at received nanoseconds since 1970 UTC.
func New(seq uint64, provider string, providerSeq uint64, received int64, data []byte) Record {
	r := Record{
		Seq: seq, Provider: provider, ProviderSeq: providerSeq, Received: received,
		OrigLen: uint64(len(data)), OrigSHA256: sha256.Sum256(data),
	}
	if half := MaxBytes / 2; len(data) > MaxBytes {
		r.Data = keep(data[:half], data[len(data)-half:])
	} else {
		r.Data = append([]byte(nil), data...)
	}
	return r
}

// FromParts returns the record of data longer than MaxBytes that the caller never held whole (ADR 0016,
// point 2): its first and last MaxBytes/2 bytes, its length and its SHA-256. For the same data it equals
// New. Parts that New could not have produced are refused, so a record never claims more than it keeps.
func FromParts(seq uint64, provider string, providerSeq uint64, received int64, head, tail []byte,
	origLen uint64, origSHA256 [32]byte,
) (Record, error) {
	half := MaxBytes / 2
	if len(head) != half || len(tail) != half || origLen <= MaxBytes {
		return Record{}, fmt.Errorf("rawrecord: parts of %d and %d bytes for %d delivered bytes, want %d each above %d",
			len(head), len(tail), origLen, half, MaxBytes)
	}
	r := Record{
		Seq: seq, Provider: provider, ProviderSeq: providerSeq, Received: received,
		Data: keep(head, tail), OrigLen: origLen, OrigSHA256: origSHA256,
	}
	if err := r.Check(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// keep returns a copy of what a truncated record holds: head and tail, MaxBytes/2 bytes each, as both
// callers cut or checked them; the capacity is the constant, never a sum of input lengths.
func keep(head, tail []byte) []byte {
	return append(append(make([]byte, 0, MaxBytes), head...), tail...)
}

// Check reports whether r is a record New or FromParts could have made that SQLite can store: provider
// seq and original length within int64, data whole up to MaxBytes or else exactly MaxBytes, and whole
// data matching its hash. Seq is the store's to assign and is not checked here.
func (r Record) Check() error {
	n := uint64(len(r.Data))
	switch {
	case r.ProviderSeq > math.MaxInt64 || r.OrigLen > math.MaxInt64:
		return fmt.Errorf("rawrecord: provider seq %d or length %d over int64", r.ProviderSeq, r.OrigLen)
	case (r.OrigLen <= MaxBytes && n != r.OrigLen) || (r.OrigLen > MaxBytes && n != MaxBytes):
		return fmt.Errorf("rawrecord: %d data bytes for %d delivered", n, r.OrigLen)
	case !r.Truncated() && sha256.Sum256(r.Data) != r.OrigSHA256:
		return errors.New("rawrecord: data does not match its SHA-256")
	}
	return nil
}

// Truncated reports whether Data holds less than the delivered data.
func (r Record) Truncated() bool { return r.OrigLen != uint64(len(r.Data)) }

// Encode returns the label, a zero byte, then big-endian: seq, provider length and bytes, provider
// seq, receive time, original length, original SHA-256, data length and bytes. Every field has a
// fixed width or a length prefix, so two different records never share an encoding.
func (r Record) Encode() []byte {
	b := make([]byte, 0, r.EncodedLen())
	b = append(append(b, Label...), 0)
	b = binary.BigEndian.AppendUint64(b, r.Seq)
	b = binary.BigEndian.AppendUint64(b, uint64(len(r.Provider)))
	b = append(b, r.Provider...)
	b = binary.BigEndian.AppendUint64(b, r.ProviderSeq)
	b = binary.BigEndian.AppendUint64(b, uint64(r.Received)) //nolint:gosec // two's complement keeps every int64 distinct
	b = binary.BigEndian.AppendUint64(b, r.OrigLen)
	b = append(b, r.OrigSHA256[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(r.Data)))
	return append(b, r.Data...)
}

// EncodedLen is len(r.Encode()), without encoding.
func (r Record) EncodedLen() int { return len(Label) + 1 + 8*6 + 32 + len(r.Provider) + len(r.Data) }

// Leaf is the SHA-256 of Encode; a batch entry's root is the RFC 6962 tree hash over leaves as data (ADR 0026).
func (r Record) Leaf() [32]byte { return sha256.Sum256(r.Encode()) }
