package entry

import (
	"bytes"
	"encoding/hex"
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
	{"loss", Entry{At: noon, Body: Loss{Stage: "queue", Records: 3, Bytes: 4096}}, []string{
		label, "03", atNoon,
		"05", "7175657565", // stage
		"0000000000000003", "0000000000001000", // records, bytes
	}},
	{"health ok", Entry{At: noon, Body: Health{State: StateOK, Truncated: 1}}, []string{
		label, "04", atNoon,
		"01", "00", // state, empty reason
		"0000000000000001", "0000000000000000", // truncated, malformed
	}},
	{"health unknown", Entry{At: noon, Body: Health{State: StateUnknown, Reason: "laurel-disconnected", Malformed: 2}}, []string{
		label, "04", atNoon,
		"02", "13", "6c617572656c2d646973636f6e6e6563746564",
		"0000000000000000", "0000000000000002",
	}},
	{"announce before the epoch", Entry{At: -1, Body: Announce{Kind: AnnounceSuspend}}, []string{
		label, "05", "ffffffffffffffff", "02",
	}},
	{"final", Entry{At: noon, Body: Final{NextOrigin: "balistid.dev/log/2027"}}, []string{
		label, "06", atNoon,
		"15", "62616c69737469642e6465762f6c6f672f32303237",
	}},
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
	batch, loss, health := vectorBytes(t, "batch"), vectorBytes(t, "loss"), vectorBytes(t, "health unknown")
	announce, final := vectorBytes(t, "announce before the epoch"), vectorBytes(t, "final")
	stage := func(s string) []byte { // the loss vector with stage s
		return append(append(append(bytes.Clone(loss[:head]), byte(len(s))), s...), loss[head+1+len("queue"):]...) //nolint:gosec // short test stages
	}
	if !bytes.Equal(stage("queue"), loss) {
		t.Fatal("stage() does not rebuild the loss vector")
	}
	const notV1, short, stageWrong, noReason = "not a balistid/entry/v1", "ends inside a field", "loss stage", "needs a reason"
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
		{"trailing byte", append(bytes.Clone(batch), 0), "bytes after the entry"},
		{"short hash", batch[:len(batch)-1], short},
		{"short time", batch[:head-1], short},
		{"first after last", with(batch, head, 0, 0, 0, 0, 0, 0, 0x10), "batch first after last"},
		{"stage too long", stage(strings.Repeat("q", 17)), stageWrong},
		{"stage upper", stage("Queue"), stageWrong},
		{"stage empty", stage(""), stageWrong},
		{"stage with a dash", stage("re-sent"), stageWrong},
		{"no records", with(loss, head+6, 0, 0, 0, 0, 0, 0, 0, 0), "loss of no records"},
		{"state zero", with(health, head, 0), "unknown health state"},
		{"state three", with(health, head, 3), "unknown health state"},
		{"unknown, no reason", append(append(bytes.Clone(health[:head+1]), 0), health[head+2+19:]...), noReason},
		{"ok with a reason", with(health, head, 1), "OK with a reason"},
		{"reason control byte", with(health, head+2, '\n'), noReason},
		{"reason past input", with(health, head+1, 0xff), short},
		{"announcement zero", with(announce, len(announce)-1, 0), "unknown announcement"},
		{"announcement three", with(announce, len(announce)-1, 3), "unknown announcement"},
		{"origin with space", with(final, head+1+8, ' '), "next origin"},
		{"origin empty", append(bytes.Clone(final[:head]), 0), "next origin"},
		{"over MaxBytes", append(bytes.Clone(batch), make([]byte, MaxBytes)...), "over 256 bytes"},
	} {
		if e, err := Decode(c.b); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %+v, %v; want an error about %q", c.name, e, err, c.why)
		} else if strings.Contains(err.Error(), "laurel") {
			t.Errorf("%s: error quotes the input: %v", c.name, err)
		}
	}
}

func TestEncodeRefusesWhatDecodeWouldRefuse(t *testing.T) {
	long := strings.Repeat("a", MaxReason+1)
	for _, e := range []Entry{
		{},
		{Body: Batch{First: 2, Last: 1}},
		{Body: Seal{First: 2, Last: 1}},
		{Body: Loss{Stage: "Queue", Records: 1}},
		{Body: Loss{Stage: "queue"}},
		{Body: Loss{Stage: strings.Repeat("q", 17), Records: 1}},
		{Body: Health{State: StateOK, Reason: "x"}},
		{Body: Health{State: StateUnknown}},
		{Body: Health{State: StateUnknown, Reason: long}},
		{Body: Health{State: 3}},
		{Body: Announce{}},
		{Body: Final{NextOrigin: strings.Repeat("o", MaxOrigin+1)}},
		{Body: Final{NextOrigin: "a\nb"}},
	} {
		if b, err := e.Encode(); err == nil {
			t.Errorf("%+v: encoded %x", e, b)
		}
	}
	// The longest entries fit MaxBytes.
	for _, e := range []Entry{
		{Body: Health{State: StateUnknown, Reason: long[:MaxReason], Truncated: ^uint64(0), Malformed: ^uint64(0)}},
		{Body: Final{NextOrigin: strings.Repeat("o", MaxOrigin)}},
	} {
		if b, err := e.Encode(); err != nil || len(b) > MaxBytes {
			t.Errorf("%T: %d bytes, %v", e.Body, len(b), err)
		}
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
