package rawrecord

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const noon = int64(1791460800000000000) // 2026-10-08T12:00:00Z

func leafHex(r Record) string {
	leaf := r.Leaf()
	return hex.EncodeToString(leaf[:])
}

// The vectors spell the encoding out field by field and pin leaves computed outside Go, so a change
// of Encode fails here and needs a new label (ADR 0005, point 2).
func TestVectors(t *testing.T) {
	cases := []struct {
		name      string
		seq, pseq uint64
		data      string
		encoding  []string
		leaf      string
	}{
		{"two bytes", 1, 42, "ab", []string{
			"62616c69737469642f7261772f763100", // label and its terminator
			"0000000000000001",                 // seq
			"0000000000000006", "6c617572656c", // provider "laurel"
			"000000000000002a", // provider seq
			"18dc8c1b25098000", // received, ns since 1970 UTC
			"0000000000000002", // original length
			"fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603", // original sha256
			"0000000000000002", "6162", // data
		}, "4c75014f195626154f3b5f0b5d5fba29d3c9534021cbba18e3e09d90694d2535"},
		{"empty", 0, 0, "", []string{
			"62616c69737469642f7261772f763100",
			"0000000000000000",
			"0000000000000006", "6c617572656c",
			"0000000000000000",
			"18dc8c1b25098000",
			"0000000000000000",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"0000000000000000",
		}, "da27b5313bd0b511b47df3c169e3bf1efb67ce12695ceee8d735531a13bbe245"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := New(c.seq, "laurel", c.pseq, noon, []byte(c.data))
			if got, want := hex.EncodeToString(r.Encode()), strings.Join(c.encoding, ""); got != want {
				t.Fatalf("Encode = %s, want %s", got, want)
			}
			if got := leafHex(r); got != c.leaf {
				t.Fatalf("Leaf = %s, want %s", got, c.leaf)
			}
		})
	}
}

// Values above 32 bits, a non-ASCII provider with spaces and data with a zero byte, all kept as given.
func TestWideVector(t *testing.T) {
	r := New(0x8000000000000001, "Laurel ü ", 0x0123456789abcdef, 0x4000000000000001, []byte("\x00a "))
	if got := leafHex(r); got != "9744a17f1d12c37627b0f16cf99b2514047058701729afd94c27b8ea879db12d" {
		t.Fatalf("Leaf = %s", got)
	}
}

// A record the shard reader builds directly is encoded as it is: a negative time and a length above
// 32 bits included.
func TestLiteralVector(t *testing.T) {
	r := Record{Received: -1, Data: []byte("ab"), OrigLen: 1<<32 | 2}
	want := "62616c69737469642f7261772f763100" + "0000000000000000" + "0000000000000000" + "0000000000000000" +
		"ffffffffffffffff" + "0000000100000002" + strings.Repeat("00", 32) + "0000000000000002" + "6162"
	if got := hex.EncodeToString(r.Encode()); got != want {
		t.Fatalf("Encode = %s, want %s", got, want)
	}
	if got := leafHex(r); got != "bae52a0d27327a7bd368a9ea541f71825ecbbc22991f8b9014c66f8acc5d5847" {
		t.Fatalf("Leaf = %s", got)
	}
}

// The leaf commits to the original length and hash, so a truncated record is not one that arrived short.
func TestTruncatedVector(t *testing.T) {
	big := make([]byte, MaxBytes+3)
	for i := range big {
		big[i] = byte(i)
	}
	if got := leafHex(New(1, "laurel", 42, noon, big)); got != "12ea2d334f64d4239e4057d7df0b8f18dbf1b1a5de0267f56d5d825582e6e95d" {
		t.Fatalf("Leaf = %s", got)
	}
}

// Length prefixes keep field boundaries in the bytes: moving one changes the leaf.
func TestDistinctRecordsHaveDistinctLeaves(t *testing.T) {
	leaves := map[[32]byte]string{}
	for name, r := range map[string]Record{
		"base":              New(7, "ab", 1, noon, []byte("c")),
		"boundary moved":    New(7, "a", 1, noon, []byte("bc")),
		"seq":               New(8, "ab", 1, noon, []byte("c")),
		"seq above 32 bits": New(7+1<<32, "ab", 1, noon, []byte("c")),
		"provider seq":      New(7, "ab", 2, noon, []byte("c")),
		"time":              New(7, "ab", 1, noon+1, []byte("c")),
		"time bit 62":       New(7, "ab", 1, noon^1<<62, []byte("c")),
		"provider case":     New(7, "AB", 1, noon, []byte("c")),
	} {
		leaf := r.Leaf()
		if other, ok := leaves[leaf]; ok {
			t.Fatalf("%s and %s share a leaf", name, other)
		}
		leaves[leaf] = name
	}
}

func TestTruncation(t *testing.T) {
	for _, n := range []int{MaxBytes, MaxBytes + 1, MaxBytes + 3} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 7)
		}
		checkRecord(t, New(1, "laurel", 1, noon, data), data)
	}
}

// The collector may reuse its read buffer; the record must not change with it.
func TestEncodedLen(t *testing.T) {
	for _, r := range []Record{
		{},
		New(1, "laurel", 1, noon, nil),
		New(1<<63, strings.Repeat("p", 300), 7, -1, []byte("x")),
		New(2, "laurel", 2, noon, bytes.Repeat([]byte("d"), MaxBytes)),
		New(3, "laurel", 3, noon, bytes.Repeat([]byte("d"), MaxBytes+1)), // truncated
	} {
		if got, want := r.EncodedLen(), len(r.Encode()); got != want {
			t.Errorf("EncodedLen = %d, len(Encode) = %d for a provider of %d and data of %d bytes", got, want, len(r.Provider), len(r.Data))
		}
	}
}

func TestNewKeepsACopy(t *testing.T) {
	data := []byte("ab")
	r := New(1, "laurel", 1, noon, data)
	data[0] ^= 1
	if string(r.Data) != "ab" {
		t.Fatalf("Data = %q after the caller changed its buffer", r.Data)
	}
}

// checkRecord fails unless r holds data whole up to MaxBytes, else its first and last MaxBytes/2 bytes,
// with the length and SHA-256 of all of it.
func checkRecord(t *testing.T, r Record, data []byte) {
	t.Helper()
	want := data
	if len(data) > MaxBytes {
		half := MaxBytes / 2
		want = append(append([]byte(nil), data[:half]...), data[len(data)-half:]...)
	}
	if !bytes.Equal(r.Data, want) || r.OrigLen != uint64(len(data)) || r.OrigSHA256 != sha256.Sum256(data) {
		t.Fatalf("record of %d bytes keeps %d bytes, OrigLen %d, or the wrong hash", len(data), len(r.Data), r.OrigLen)
	}
	if r.Truncated() != (len(data) > MaxBytes) {
		t.Fatalf("Truncated = %v for %d bytes", r.Truncated(), len(data))
	}
}

// fromData splits data the way a streaming reader would see it.
func fromData(data []byte) (head, tail []byte, n uint64, sum [32]byte) {
	half := MaxBytes / 2
	return data[:half], data[len(data)-half:], uint64(len(data)), sha256.Sum256(data)
}

func TestFromPartsEqualsNew(t *testing.T) {
	for _, n := range []int{MaxBytes + 1, MaxBytes + 3, 3 * MaxBytes} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i * 13)
		}
		head, tail, length, sum := fromData(data)
		got, err := FromParts(1, "laurel", 42, noon, head, tail, length, sum)
		if err != nil {
			t.Fatalf("FromParts of %d bytes: %v", n, err)
		}
		if want := New(1, "laurel", 42, noon, data); !bytes.Equal(got.Encode(), want.Encode()) {
			t.Fatalf("FromParts and New disagree for %d bytes", n)
		}
		checkRecord(t, got, data)
	}
}

func TestFromPartsRefusesWhatNewCannotProduce(t *testing.T) {
	half := MaxBytes / 2
	part := make([]byte, half)
	for name, c := range map[string]struct {
		head, tail []byte
		n          uint64
	}{
		"short head":          {part[1:], part, MaxBytes + 1},
		"long tail":           {part, append(part, 0), MaxBytes + 1},
		"no tail":             {part, nil, MaxBytes + 1},
		"length at the limit": {part, part, MaxBytes},
		"length below parts":  {part, part, 1},
		"uneven split":        {part[1:], append(part, 0), MaxBytes + 1},
		"length over int64":   {part, part, 1 << 63},
	} {
		if _, err := FromParts(1, "laurel", 1, noon, c.head, c.tail, c.n, [32]byte{}); err == nil {
			t.Fatalf("%s: FromParts accepted it", name)
		}
	}
}

func TestFromPartsKeepsACopy(t *testing.T) {
	data := make([]byte, MaxBytes+1)
	head, tail, n, sum := fromData(data)
	r, err := FromParts(1, "laurel", 1, noon, head, tail, n, sum)
	if err != nil {
		t.Fatal(err)
	}
	head[0], tail[0] = 1, 1
	if r.Data[0] != 0 || r.Data[MaxBytes/2] != 0 {
		t.Fatal("Data changed with the caller's buffers")
	}
}

func TestCheck(t *testing.T) {
	whole := New(1, "laurel", 1, noon, []byte("ab"))
	cut := New(1, "laurel", 1, noon, make([]byte, MaxBytes+1))
	if err := errors.Join(whole.Check(), cut.Check()); err != nil {
		t.Fatalf("Check refused what New made: %v", err)
	}
	for name, r := range map[string]Record{
		"provider seq over int64": New(1, "laurel", 1<<63, noon, []byte("ab")),
		"length over int64":       {Data: cut.Data, OrigLen: 1 << 63},
		"short data":              {Data: []byte("a"), OrigLen: 2, OrigSHA256: whole.OrigSHA256},
		"truncated, short data":   {Data: cut.Data[1:], OrigLen: cut.OrigLen},
		"whole, other hash":       {Data: []byte("ac"), OrigLen: 2, OrigSHA256: whole.OrigSHA256},
	} {
		if err := r.Check(); err == nil {
			t.Fatalf("%s: Check accepted it", name)
		}
	}
}

// Any parts either make a record New could have made from data of that length, or are refused.
func FuzzFromParts(f *testing.F) {
	f.Add(uint64(MaxBytes+1), MaxBytes/2, MaxBytes/2, byte(7))
	f.Add(uint64(MaxBytes), MaxBytes/2, MaxBytes/2, byte(0))
	f.Add(uint64(MaxBytes+1), 0, MaxBytes, byte(1))
	f.Fuzz(func(t *testing.T, n uint64, headLen, tailLen int, fill byte) {
		if headLen < 0 || tailLen < 0 || headLen > MaxBytes || tailLen > MaxBytes {
			return
		}
		head, tail := bytes.Repeat([]byte{fill}, headLen), bytes.Repeat([]byte{fill ^ 1}, tailLen)
		r, err := FromParts(1, "laurel", 1, noon, head, tail, n, [32]byte{})
		if err != nil {
			return
		}
		if !r.Truncated() || len(r.Data) != MaxBytes || r.OrigLen <= MaxBytes {
			t.Fatalf("accepted parts %d+%d for %d bytes", headLen, tailLen, n)
		}
	})
}

func FuzzNew(f *testing.F) {
	f.Add(uint64(1), "laurel", uint64(42), noon, []byte("ab"))
	f.Fuzz(func(t *testing.T, seq uint64, provider string, pseq uint64, received int64, data []byte) {
		r := New(seq, provider, pseq, received, data)
		if r.Seq != seq || r.Provider != provider || r.ProviderSeq != pseq || r.Received != received {
			t.Fatalf("New changed a field: %+v", r)
		}
		checkRecord(t, r, data)
	})
}
