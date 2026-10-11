package collector

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const noon = int64(1791460800000000000)

func clock() time.Time { return time.Unix(0, noon) }

// event is a line shaped like Laurel's: ID first, then fields (written for these tests, not copied).
func event(serial int, extra string) string {
	return fmt.Sprintf(`{"ID":"1791460800.123:%d","SYSCALL":{"syscall":"execve","success":"yes"}%s}`, serial, extra)
}

// read runs one connection through a reader with a large queue and returns what it queued.
func read(t *testing.T, input string) ([]rawrecord.Record, Counts, *Losses) {
	t.Helper()
	loss := &Losses{}
	q := NewQueue(1<<30, loss)
	r := NewReader(q, clock)
	if err := r.ReadConn(t.Context(), strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	return q.Drain(), r.Counts(), loss
}

func TestWholeLinesStoredWithTheirSerial(t *testing.T) {
	recs, counts, _ := read(t, event(7, "")+"\n"+event(8, `,"x":1`)+"\n")
	if len(recs) != 2 || counts.Malformed != 0 || counts.Records != 2 {
		t.Fatalf("records %d, counts %+v", len(recs), counts)
	}
	for i, want := range []string{event(7, ""), event(8, `,"x":1`)} {
		r := recs[i]
		if string(r.Data) != want || r.ProviderSeq != uint64(7+i) || r.Provider != "laurel" || r.Received != noon {
			t.Fatalf("record %d = %+v", i, r)
		}
	}
}

func TestHeadCutByEOFStoredMalformed(t *testing.T) {
	head := event(9, "")[:20]
	recs, counts, _ := read(t, event(8, "")+"\n"+head)
	if len(recs) != 2 || counts.Malformed != 1 || string(recs[1].Data) != head || recs[1].ProviderSeq != 0 {
		t.Fatalf("records %+v, counts %+v", recs, counts)
	}
}

func TestTailOpeningConnStoredMalformed(t *testing.T) {
	tail := event(9, "")[20:]
	recs, counts, _ := read(t, tail+"\n"+event(10, "")+"\n")
	if len(recs) != 2 || counts.Malformed != 1 || string(recs[0].Data) != tail || recs[0].ProviderSeq != 0 ||
		recs[1].ProviderSeq != 10 {
		t.Fatalf("records %+v, counts %+v", recs, counts)
	}
}

func TestIDMismatchMalformedSeqZero(t *testing.T) {
	for name, l := range map[string]string{
		"second ID key":     `{"ID":"1.2:3","ID":"1.2:4"}`,
		"case-variant key":  `{"ID":"1.2:3","id":"1.2:4"}`,
		"not JSON":          `{"ID":"1.2:3",`,
		"ID not first":      `{"x":1,"ID":"1.2:3"}`,
		"no serial":         `{"ID":"1.2"}`,
		"serial over int63": `{"ID":"1.2:9223372036854775808"}`,
		"escaped ID":        `{"ID":"1.2:3\u0033"}`,
		"empty line":        ``,
	} {
		recs, counts, _ := read(t, l+"\n")
		if len(recs) != 1 || counts.Malformed != 1 || recs[0].ProviderSeq != 0 || string(recs[0].Data) != l {
			t.Fatalf("%s: records %+v, counts %+v", name, recs, counts)
		}
	}
}

func TestLineOver2MiBStoredTruncated(t *testing.T) {
	for _, size := range []int{rawrecord.MaxBytes + 1, 6 << 20, 18 << 20} {
		var b strings.Builder
		b.WriteString(`{"ID":"1791460800.123:42","ARGV":"`)
		for i := 0; b.Len() < size-2; i++ {
			b.WriteByte(byte('a' + i%26))
		}
		b.WriteString(`"}`)
		long := b.String()
		recs, counts, _ := read(t, long+"\n"+event(43, "")+"\n")
		want := rawrecord.New(0, "laurel", 42, noon, []byte(long))
		if len(recs) != 2 || !bytes.Equal(recs[0].Encode(), want.Encode()) || counts.Truncated != 1 || counts.Malformed != 0 {
			t.Fatalf("%d bytes: records %d, counts %+v", size, len(recs), counts)
		}
		if recs[1].ProviderSeq != 43 || string(recs[1].Data) != event(43, "") {
			t.Fatalf("%d bytes: the next line came out as %q", size, recs[1].Data)
		}
	}
}

func TestStreamedLineCutByEOFStoredMalformed(t *testing.T) {
	long := `{"ID":"1.2:5","A":"` + strings.Repeat("x", 3<<20)
	recs, counts, _ := read(t, long)
	if len(recs) != 1 || counts.Malformed != 1 || recs[0].ProviderSeq != 0 || recs[0].OrigLen != uint64(len(long)) {
		t.Fatalf("records %d, counts %+v", len(recs), counts)
	}
}

func TestFullQueueDropsWithoutBlocking(t *testing.T) {
	loss := &Losses{}
	one := rawrecord.New(0, "laurel", 1, noon, []byte(event(1, ""))).EncodedLen()
	q := NewQueue(2*one, loss)
	r := NewReader(q, clock)
	var in strings.Builder
	for i := 1; i <= 5; i++ {
		fmt.Fprintln(&in, event(i, ""))
	}
	done := make(chan error, 1)
	go func() { done <- r.ReadConn(t.Context(), strings.NewReader(in.String())) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the reader waited on a full queue")
	}
	got := loss.Take()[StageQueue]
	if recs := q.Drain(); len(recs) != 2 || got.Count != 3 || got.FirstSeq != 3 || got.LastSeq != 5 ||
		got.FirstAt != noon || got.Bytes == 0 {
		t.Fatalf("queued %d, lost %+v", len(recs), got)
	}
	if again := loss.Take(); len(again) != 0 {
		t.Fatalf("Take did not reset: %+v", again)
	}
}

func TestHighWaterResetsToCurrent(t *testing.T) {
	q := NewQueue(1<<20, &Losses{})
	q.Push(rawrecord.New(0, "laurel", 1, noon, []byte("ab")))
	size := q.HighWater()
	if size == 0 || q.HighWater() != size {
		t.Fatalf("high water %d, then %d with the record still queued", size, q.HighWater())
	}
	q.Drain()
	if q.HighWater() != size || q.HighWater() != 0 {
		t.Fatal("high water does not fall back after a drain")
	}
}

// Every input byte ends in exactly one record (its delivered length) or is a newline that ended one, and
// every record kept whole holds exactly its bytes of the input, in order.
func FuzzFraming(f *testing.F) {
	f.Add([]byte(event(1, "") + "\n" + event(2, "")))
	f.Add([]byte(":3\"}\n\n{\"ID\":\"1.2:4\",\"ID\":\"x\"}\n"))
	f.Add([]byte("\n\n\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		recs, counts, loss := read(t, string(input))
		var n uint64
		var whole []byte
		for _, r := range recs {
			n += r.OrigLen
			if !r.Truncated() {
				whole = append(append(whole, r.Data...), '\n')
			}
		}
		newlines := uint64(bytes.Count(input, []byte("\n"))) //nolint:gosec // a count is never negative
		if n+newlines != uint64(len(input)) || counts.Records != uint64(len(recs)) || len(loss.Take()) != 0 {
			t.Fatalf("%d record bytes + %d newlines for %d input bytes", n, newlines, len(input))
		}
		if counts.Truncated == 0 && !bytes.HasPrefix(append(input, '\n'), whole) {
			t.Fatal("whole records do not spell the input")
		}
	})
}

// A 1 KiB line must cost far less than the 100 µs that 10000 events/s leave (acceptance burst_rate).
func BenchmarkReadConn(b *testing.B) {
	l := event(1, `,"PATH":"`+strings.Repeat("p", 900)+`"`) + "\n"
	in := strings.Repeat(l, 1000)
	b.SetBytes(int64(len(in)))
	for b.Loop() {
		q := NewQueue(1<<30, &Losses{})
		if err := NewReader(q, clock).ReadConn(b.Context(), strings.NewReader(in)); err != nil {
			b.Fatal(err)
		}
	}
}
