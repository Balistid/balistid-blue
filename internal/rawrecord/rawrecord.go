// Package rawrecord is the evidence unit of ADR 0005: the bytes a sensor delivered with our sequence
// number, the provider's and the receive time, and the leaf hash the Merkle log anchors.
package rawrecord

import (
	"crypto/sha256"
	"encoding/binary"
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
	if len(data) > MaxBytes {
		half := MaxBytes / 2
		r.Data = append(append(make([]byte, 0, MaxBytes), data[:half]...), data[len(data)-half:]...)
	} else {
		r.Data = append([]byte(nil), data...)
	}
	return r
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

// Leaf is the SHA-256 of Encode; the log adds its own domain prefix (ADR 0006).
func (r Record) Leaf() [32]byte { return sha256.Sum256(r.Encode()) }
