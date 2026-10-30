package entry

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

const noon = int64(0x18dc8c1b25098000)

var (
	root  = [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	empty = mustHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
)

func mustHash(s string) (h [32]byte) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("bad hash literal")
	}
	copy(h[:], b)
	return h
}

const (
	label  = "62616c69737469642f656e7472792f763100" // label and its terminator
	atNoon = "18dc8c1b25098000"                     // host time, ns since 1970 UTC
)

// The vectors spell each type's encoding out field by field, computed outside Go from ADR 0026, so a
// change of Encode or Decode fails here and needs a new label.
var vectors = []struct {
	name     string
	entry    Entry
	encoding []string
}{
	{"batch", Entry{At: noon, Body: Batch{First: 1, Last: 2000, Root: root}}, []string{
		label, "01", atNoon,
		"0000000000000001", "00000000000007d0", // first, last
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", // root
	}},
	{"seal", Entry{At: noon, Body: Seal{First: 1, Last: 1 << 20, SHA256: empty}}, []string{
		label, "02", atNoon,
		"0000000000000001", "0000000000100000",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}},
	{"loss", Entry{At: noon, Body: Loss{Seq: 42, Stage: StageQueue, Records: 3}}, []string{
		label, "03", atNoon,
		"000000000000002a", "02", "0000000000000003", // seq, stage, records
	}},
	{"health", Entry{At: noon, Body: Health{State: StateUnknown, Reason: ReasonStoreDown, Unstored: 7}}, []string{
		label, "04", atNoon,
		"02", "02", "0000000000000007", // state, reason, unstored
	}},
	{"announce before the epoch", Entry{At: -1, Body: Announce{Kind: AnnounceSuspend}}, []string{
		label, "05", "ffffffffffffffff", "02",
	}},
	{"final", Entry{At: noon, Body: Final{NextOrigin: "balistid.dev/log/2027"}}, []string{
		label, "06", atNoon,
		"15", "62616c69737469642e6465762f6c6f672f32303237",
	}},
}

// The limits are part of v1: changing one changes what Decode accepts, so it needs a new label.
func TestLimitsAreV1s(t *testing.T) {
	if Label != "balistid/entry/v1" || MaxBytes != 256 || MaxOrigin != 128 || MaxSeq != math.MaxInt64 {
		t.Fatalf("v1 limits changed: %q %d %d %d", Label, MaxBytes, MaxOrigin, uint64(MaxSeq))
	}
}

func TestEntryVectors(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			want := strings.Join(v.encoding, "")
			got, err := v.entry.Encode()
			if err != nil || hex.EncodeToString(got) != want {
				t.Fatalf("Encode = %x, %v, want %s", got, err, want)
			}
			back, err := Decode(got)
			if err != nil || back != v.entry {
				t.Fatalf("Decode = %+v, %v, want %+v", back, err, v.entry)
			}
		})
	}
}

func vectorBytes(t *testing.T, name string) []byte {
	t.Helper()
	for _, v := range vectors {
		if v.name == name {
			b, err := hex.DecodeString(strings.Join(v.encoding, ""))
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatalf("no vector %s", name)
	return nil
}

// with returns a copy of b with the bytes at i replaced by r.
func with(b []byte, i int, r ...byte) []byte {
	out := bytes.Clone(b)
	copy(out[i:], r)
	return out
}

func TestDecodeRefusesWhatEncodeCannotProduce(t *testing.T) {
	head := len(label)/2 + 1 + 8 // label, type, time
	batch := vectorBytes(t, "batch")
	announce, final := vectorBytes(t, "announce before the epoch"), vectorBytes(t, "final")
	loss, health := vectorBytes(t, "loss"), vectorBytes(t, "health")
	const notV1, short = "not a balistid/entry/v1", "ends inside a field"
	for _, c := range []struct {
		name string
		b    []byte
		why  string
	}{
		{"empty", nil, notV1},
		{"other version", with(batch, len(label)/2-2, '2'), notV1},
		{"no terminator", with(batch, len(label)/2-1, 'x'), notV1},
		{"type zero", with(batch, len(label)/2, 0), "unknown type"},
		{"unknown type", with(batch, len(label)/2, 7), "unknown type"},
		{"batch read as loss", with(batch, len(label)/2, 3), "bytes after the entry"},
		{"loss seq zero", with(loss, head, 0, 0, 0, 0, 0, 0, 0, 0), "loss seq outside"},
		{"loss seq over MaxSeq", with(loss, head, 0x80), "loss seq outside"},
		{"loss stage zero", with(loss, head+8, 0), "unknown loss stage"},
		{"loss stage seven", with(loss, head+8, 7), "unknown loss stage"},
		{"loss of no records", with(loss, head+9+7, 0), "loss of no records"},
		{"truncated loss of two", with(with(loss, head+8, 6), head+9+7, 2), "truncated loss"},
		{"short loss", loss[:len(loss)-1], short},
		{"health OK with a reason", with(health, head, 1), "state and reason"},
		{"health UNKNOWN without a reason", with(health, head+1, 0), "state and reason"},
		{"health reason eight", with(health, head+1, 8), "state and reason"},
		{"health state three", with(health, head, 3), "state and reason"},
		{"health state zero", with(health, head, 0, 0), "state and reason"},
		{"short health", health[:len(health)-1], short},
		{"origin past input", with(final, head, 0xff), short},
		{"trailing byte", append(bytes.Clone(batch), 0), "bytes after the entry"},
		{"short hash", batch[:len(batch)-1], short},
		{"short time", batch[:head-1], short},
		{"first after last", with(batch, head, 0, 0, 0, 0, 0, 0, 0x10), "batch first after last"},
		{"first zero", with(batch, head, 0, 0, 0, 0, 0, 0, 0, 0), "batch seq outside"},
		{"last over MaxSeq", with(batch, head+8, 0x80, 0, 0, 0, 0, 0, 0, 0), "batch seq outside"},
		{"zero root", with(batch, head+16, make([]byte, 32)...), "batch hash is zero"},
		{"zero seal hash", with(vectorBytes(t, "seal"), head+16, make([]byte, 32)...), "seal hash is zero"},
		{"origin with plus", with(final, head+1+8, '+'), "next origin"},
		{"announcement zero", with(announce, len(announce)-1, 0), "unknown announcement"},
		{"announcement three", with(announce, len(announce)-1, 3), "unknown announcement"},
		{"origin with space", with(final, head+1+8, ' '), "next origin"},
		{"origin empty", append(bytes.Clone(final[:head]), 0), "next origin"},
		{"over MaxBytes", append(bytes.Clone(batch), make([]byte, MaxBytes)...), "over 256 bytes"},
	} {
		if e, err := Decode(c.b); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %+v, %v; want an error about %q", c.name, e, err, c.why)
		} else if strings.Contains(err.Error(), "balistid.dev") {
			t.Errorf("%s: error quotes the input: %v", c.name, err)
		}
	}
}

func TestEncodeRefusesWhatDecodeWouldRefuse(t *testing.T) {
	for _, e := range []Entry{
		{},
		{Body: &Batch{First: 1, Last: 1, Root: root}},
		{Body: (*Batch)(nil)},
		{Body: (*Final)(nil)},
		{Body: Batch{First: 2, Last: 1, Root: root}},
		{Body: Batch{First: 0, Last: 1, Root: root}},
		{Body: Batch{First: 1, Last: MaxSeq + 1, Root: root}},
		{Body: Batch{First: 1, Last: 1}},
		{Body: Seal{First: 2, Last: 1, SHA256: empty}},
		{Body: Seal{First: 0, Last: 0, SHA256: empty}},
		{Body: Seal{First: 1, Last: 1}},
		{Body: Final{NextOrigin: "balistid.dev/log+2027"}},
		{Body: Announce{}},
		{Body: Loss{}},
		{Body: &Loss{Seq: 1, Stage: StageCap, Records: 1}},
		{Body: Loss{Seq: 1, Stage: StageTruncated, Records: 2}},
		{Body: Health{}},
		{Body: Health{State: StateOK, Reason: ReasonStarting}},
		{Body: (*Health)(nil)},
		{Body: Final{NextOrigin: strings.Repeat("o", MaxOrigin+1)}},
		{Body: Final{NextOrigin: "a\nb"}},
	} {
		if b, err := e.Encode(); err == nil {
			t.Errorf("%+v: encoded %x", e, b)
		}
	}
	// One record is a range, the normal batch on a quiet host; the store's whole seq range is one too.
	for _, e := range []Entry{
		{Body: Batch{First: 5, Last: 5, Root: root}},
		{Body: Seal{First: 5, Last: 5, SHA256: empty}},
		{Body: Batch{First: 1, Last: MaxSeq, Root: root}},
		{Body: Loss{Seq: MaxSeq, Stage: StageTruncated, Records: 1}},
		{Body: Loss{Seq: 1, Stage: StageCap, Records: math.MaxUint64}},
		{Body: Health{State: StateOK, Unstored: math.MaxUint64}},
		{Body: Health{State: StateUnknown, Reason: ReasonCanaryPending}},
		{Body: Health{State: StateUnknown, Reason: ReasonStream}},
	} {
		b, err := e.Encode()
		if err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		if back, err := Decode(b); err != nil || back != e {
			t.Errorf("%+v: decoded %+v, %v", e, back, err)
		}
	}
	// The longest entry fits MaxBytes.
	if b, err := (Entry{Body: Final{NextOrigin: strings.Repeat("o", MaxOrigin)}}).Encode(); err != nil || len(b) > MaxBytes {
		t.Errorf("longest final: %d bytes, %v", len(b), err)
	}
}

// Whatever Decode accepts, Encode gives back byte for byte: one entry has one encoding.
func FuzzDecodeEntry(f *testing.F) {
	for _, v := range vectors {
		b, err := hex.DecodeString(strings.Join(v.encoding, ""))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := Decode(b)
		if err != nil {
			return
		}
		back, err := e.Encode()
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("Decode(%x) = %+v, encodes to %x, %v", b, e, back, err)
		}
	})
}
