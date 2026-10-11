package rangeguest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// diskFile is a file whose written bytes reach the disk only on Sync, as after a reset.
type diskFile struct {
	cache, disk bytes.Buffer
	fail        error
}

func (d *diskFile) Write(p []byte) (int, error) {
	if d.fail != nil {
		return 0, d.fail
	}
	return d.cache.Write(p)
}

func (d *diskFile) Sync() error {
	d.disk.Write(d.cache.Bytes())
	d.cache.Reset()
	return d.fail
}

// lost counts the numbers 1..h a file of records does not hold.
func lost(data []byte, h uint64) uint64 {
	seen := map[uint64]bool{}
	for i := 0; i+RecordSize <= len(data); i += RecordSize {
		seen[binary.LittleEndian.Uint64(data[i:])] = true
	}
	var n uint64
	for seq := uint64(1); seq <= h; seq++ {
		if !seen[seq] {
			n++
		}
	}
	return n
}

// run hands over rate numbers per second until failAt, ticking every millisecond, and returns H and
// the numbers up to it that a reset (only synced bytes) and a kill (all written bytes) lose.
func run(t *testing.T, pol Policy, rate int, failAt time.Duration) (h, resetLost, killLost uint64) {
	t.Helper()
	c := &fakeClock{now: time.Unix(0, 0)}
	start := c.now
	f := &diskFile{}
	w := NewWriter(f, pol, c)
	var hand Handover
	every := time.Second / time.Duration(rate)
	next, seq := start, uint64(0)
	for c.now.Before(start.Add(failAt)) {
		if !c.now.Before(next) {
			seq++
			if err := w.Append(seq); err != nil {
				t.Fatal(err)
			}
			hand.Add(c.now)
			next = next.Add(every)
		} else if err := w.Tick(); err != nil {
			t.Fatal(err)
		}
		c.now = c.now.Add(time.Millisecond)
	}
	h = hand.H(c.now)
	return h, lost(f.disk.Bytes(), h), lost(append(f.disk.Bytes(), f.cache.Bytes()...), h)
}

// The controls of ADR 0018 point 4: syncing every 250 ms loses nothing a reset must keep; a last
// sync 1500 ms before the reset, or holding records 2 s before write() under a kill, loses numbers
// handed over in time, so the trial must miss.
func TestWriterPoliciesAgainstH(t *testing.T) {
	fail := 10 * time.Second
	h, reset, _ := run(t, Policy{Sync: 250 * time.Millisecond}, 1000, fail)
	if h < 9000 || reset != 0 {
		t.Errorf("sync every 250 ms: H %d, %d lost to a reset; want H about 9100 and none", h, reset)
	}
	if _, reset, _ = run(t, Policy{Sync: 250 * time.Millisecond, StopAfter: 8500}, 1000, fail); reset == 0 {
		t.Error("last sync 1500 ms before the reset lost nothing")
	}
	if _, _, kill := run(t, Policy{Hold: 2 * time.Second}, 1000, fail); kill == 0 {
		t.Error("holding records 2 s before write() lost nothing to a kill")
	}
	if _, _, kill := run(t, Policy{}, 1000, fail); kill != 0 {
		t.Errorf("writing at once lost %d to a kill", kill)
	}
	if _, reset, _ = run(t, Policy{Sync: 5 * time.Second}, 1000, fail+2*time.Second); reset == 0 {
		t.Error("syncing every 5 s lost nothing to a reset 2 s after a sync")
	}
}

// Each number is written once, in the order handed.
func TestWriterWritesEachNumberOnce(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	f := &diskFile{}
	w := NewWriter(f, Policy{Hold: 3 * time.Millisecond}, c)
	for seq := uint64(1); seq <= 50; seq++ {
		if err := w.Append(seq); err != nil {
			t.Fatal(err)
		}
		c.now = c.now.Add(time.Millisecond)
	}
	c.now = c.now.Add(time.Second)
	if err := w.Tick(); err != nil {
		t.Fatal(err)
	}
	data := f.cache.Bytes()
	if len(data) != 50*RecordSize {
		t.Fatalf("stored %d bytes, want 50 records", len(data))
	}
	for i := 0; i < 50; i++ {
		if n := binary.LittleEndian.Uint64(data[i*RecordSize:]); n != uint64(i)+1 {
			t.Fatalf("record %d is %d", i, n)
		}
	}
}

func TestWriterReportsFileErrors(t *testing.T) {
	c := &fakeClock{now: time.Unix(0, 0)}
	w := NewWriter(&diskFile{fail: errors.New("disk gone")}, Policy{Sync: time.Millisecond}, c)
	if err := w.Append(1); err == nil {
		t.Error("a failed write went unreported")
	}
}

func TestHandoverH(t *testing.T) {
	t0 := time.Unix(100, 0)
	var h Handover
	for i := range 5 {
		h.Add(t0.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	// failAt t0+1300 ms: handed at or before t0+400 ms count, that is all five.
	if got := h.H(t0.Add(1300 * time.Millisecond)); got != 5 {
		t.Errorf("H = %d, want 5", got)
	}
	if got := h.H(t0.Add(1199 * time.Millisecond)); got != 3 {
		t.Errorf("H just before the fourth is due = %d, want 3", got)
	}
	if got := h.H(t0); got != 0 {
		t.Errorf("H at the first hand-over = %d, want 0", got)
	}
}

func TestStoredPrefix(t *testing.T) {
	rec := func(nums ...uint64) []byte {
		var b []byte
		for _, n := range nums {
			b = binary.LittleEndian.AppendUint64(b, n)
		}
		return b
	}
	cases := []struct {
		data          []byte
		prefix, count uint64
	}{
		{rec(1, 2, 3), 3, 3},
		{rec(2, 1, 4), 2, 3},
		{rec(1, 2, 2, 3), 3, 4},
		{append(rec(1, 2), 7, 0), 2, 2},
		{rec(0, 2), 0, 2},
		{nil, 0, 0},
	}
	for i, c := range cases {
		if p, n := StoredPrefix(c.data); p != c.prefix || n != c.count {
			t.Errorf("case %d: %d, %d; want %d, %d", i, p, n, c.prefix, c.count)
		}
	}
}

func TestServeWriterStoresWhatItIsHanded(t *testing.T) {
	var in bytes.Buffer
	for n := uint64(1); n <= 100; n++ {
		in.Write(binary.LittleEndian.AppendUint64(nil, n))
	}
	f := &diskFile{}
	if err := ServeWriter(&in, NewWriter(f, Policy{}, WallClock)); err != nil {
		t.Fatal(err)
	}
	if p, n := StoredPrefix(f.cache.Bytes()); p != 100 || n != 100 {
		t.Errorf("wrote %d through %d; want all 100", n, p)
	}
	if err := ServeWriter(bytes.NewReader([]byte{1, 0, 0}), NewWriter(&diskFile{}, Policy{}, WallClock)); err == nil {
		t.Error("a cut number was accepted")
	}
}

// Whatever a crash leaves in the file, every number up to the prefix is stored, and the prefix never
// exceeds the whole records.
func FuzzStoredPrefix(f *testing.F) {
	f.Add(binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, 1), 2))
	f.Add([]byte{1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		prefix, count := StoredPrefix(data)
		if count != uint64(len(data)/RecordSize) || prefix > count {
			t.Fatalf("prefix %d, count %d of %d bytes", prefix, count, len(data))
		}
		if lost(data, prefix) != 0 {
			t.Fatalf("prefix %d has a gap", prefix)
		}
	})
}
