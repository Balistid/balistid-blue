package link

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/entry"
)

var hash = sha256.Sum256([]byte("leaf"))

func messages() []Message {
	return []Message{
		Hello{},
		Hello{Last: 9, First: 4, Root: hash},
		Records{{Seq: 1, Leaf: hash}},
		Records{{Seq: 7, Leaf: hash, Loss: &entry.Loss{Seq: 7, Stage: entry.StageTruncated, Records: 1}}, {Seq: 8, Leaf: hash}},
		entry.Seal{First: 1, Last: 3, SHA256: hash},
		entry.Health{State: entry.StateUnknown, Reason: entry.ReasonCanaryMissed, Unstored: 12},
	}
}

func full(n int) Records {
	recs := make(Records, n)
	for i := range recs {
		recs[i] = Record{Seq: uint64(i) + 1, Leaf: hash, Loss: &entry.Loss{Seq: uint64(i) + 1, Stage: entry.StageCap, Records: 1}}
	}
	return recs
}

func TestMessagesRoundTrip(t *testing.T) {
	for _, m := range append(messages(), full(MaxRecords)) {
		var buf bytes.Buffer
		if err := Write(&buf, m); err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		if buf.Len() > 4+MaxFrame {
			t.Fatalf("%T: %d bytes", m, buf.Len())
		}
		got, err := Read(&buf)
		if err != nil || !reflect.DeepEqual(got, m) || buf.Len() != 0 {
			t.Fatalf("%T: read %+v, %v", m, got, err)
		}
	}
}

func frame(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) } //nolint:gosec // test frames are small

func encoded(t *testing.T, m Message) []byte {
	t.Helper()
	b, err := encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadRefusesWhatWriteCannotProduce(t *testing.T) {
	hello, recs := encoded(t, Hello{Last: 9, First: 4, Root: hash}), encoded(t, Records{{Seq: 1, Leaf: hash}, {Seq: 2, Leaf: hash}})
	health, seal := encoded(t, entry.Health{State: entry.StateOK}), encoded(t, entry.Seal{First: 1, Last: 3, SHA256: hash})
	set := func(b []byte, i int, v ...byte) []byte { out := bytes.Clone(b); copy(out[i:], v); return out }
	for name, b := range map[string][]byte{
		"empty frame":         {},
		"unknown type":        set(health, 0, 9),
		"hello cut short":     hello[:len(hello)-1],
		"hello trailing":      append(bytes.Clone(hello), 0),
		"hello first > last":  set(hello, 9, 0, 0, 0, 0, 0, 0, 0, 10),
		"hello half empty":    set(hello, 1, 0, 0, 0, 0, 0, 0, 0, 0),
		"seal zero hash":      set(seal, 17, make([]byte, 32)...),
		"health OK reason":    set(health, 2, 1),
		"health trailing":     append(bytes.Clone(health), 0),
		"no records":          {typeRecords, 0, 0},
		"count past records":  set(recs, 1, 0, 3),
		"count past max":      set(recs, 1, 0x04, 0x01),
		"records out of seq":  set(recs, 3+recordBytes, 0, 0, 0, 0, 0, 0, 0, 5),
		"record seq zero":     set(recs, 3, 0, 0, 0, 0, 0, 0, 0, 0),
		"record flag two":     set(recs, 3+40, 2),
		"loss cut short":      set(recs[:len(recs)-recordBytes], 3+40, 1),
		"records trailing":    append(bytes.Clone(recs), 0),
		"records header only": {typeRecords, 0},
	} {
		if m, err := Read(bytes.NewReader(frame(b))); err == nil {
			t.Errorf("%s: read %+v", name, m)
		} else if strings.Contains(err.Error(), "leaf") {
			t.Errorf("%s: error quotes the input: %v", name, err)
		}
	}
	for name, raw := range map[string][]byte{
		"zero length": {0, 0, 0, 0},
		"over max":    binary.BigEndian.AppendUint32(nil, MaxFrame+1),
		"short body":  {0, 0, 0, 5, typeHealth},
	} {
		if m, err := Read(bytes.NewReader(raw)); err == nil {
			t.Errorf("%s: read %+v", name, m)
		}
	}
}

func TestWriteRefusesWhatTheLedgerCouldNotLog(t *testing.T) {
	for _, m := range []Message{
		nil, &Hello{}, Records{}, full(MaxRecords + 1),
		Records{{Seq: 1, Leaf: hash}, {Seq: 3, Leaf: hash}},
		Records{{Seq: 1, Leaf: hash, Loss: &entry.Loss{Seq: 2, Stage: entry.StageCap, Records: 1}}},
		Records{{Seq: 1, Leaf: hash, Loss: &entry.Loss{Seq: 1, Stage: 9, Records: 1}}},
		Records{{Seq: entry.MaxSeq + 1, Leaf: hash}},
		Hello{Last: 3}, entry.Seal{First: 2, Last: 1, SHA256: hash}, entry.Health{}, entry.Batch{First: 1, Last: 1, Root: hash},
	} {
		if err := Write(&bytes.Buffer{}, m); err == nil {
			t.Errorf("%T %+v written", m, m)
		}
	}
}

// Whatever Decode accepts, encode gives back byte for byte.
func FuzzDecodeMessage(f *testing.F) {
	for _, m := range messages() {
		b, err := encode(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			return
		}
		back, err := encode(m)
		if err != nil || !bytes.Equal(back, b) {
			t.Fatalf("Decode(%x) = %+v, encodes to %x, %v", b, m, back, err)
		}
	})
}
