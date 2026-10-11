package rangeguest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// RecordSize is one stored number: 8 bytes, little endian.
const RecordSize = 8

// HandLag is how long before a failure a number must have been handed over to count in H, the end
// of the contiguous numbers that must survive it (ADR 0018, point 3).
const HandLag = 900 * time.Millisecond

// Policy is how the measured writer of the failure controls stores what it is handed (ADR 0018,
// point 4): it keeps a number in memory for Hold before write(), and fsyncs every Sync until
// StopSync (zero: to the end). Sync 0 never syncs.
type Policy struct {
	Hold     time.Duration
	Sync     time.Duration
	StopSync time.Time
}

// SyncFile is the part of *os.File the writer uses; tests replace it.
type SyncFile interface {
	Write(p []byte) (int, error)
	Sync() error
}

// Writer stores numbers 1, 2, ... as records in one file under a Policy. It is driven by its
// caller: Append hands over the next number, Tick writes and syncs what is due, so a test can run
// it on a fake clock and the guest can kill it with everything it held.
type Writer struct {
	f        SyncFile
	pol      Policy
	clk      Clock
	pending  []handed
	next     uint64
	lastSync time.Time
	handedAt []time.Time
}

type handed struct {
	seq uint64
	at  time.Time
}

// NewWriter writes to f under pol.
func NewWriter(f SyncFile, pol Policy, clk Clock) *Writer {
	return &Writer{f: f, pol: pol, clk: clk, next: 1, lastSync: clk.Now()}
}

// Append hands over the next number and returns it once handed over, then writes what is due.
func (w *Writer) Append() (uint64, error) {
	seq, now := w.next, w.clk.Now()
	w.next++
	w.pending = append(w.pending, handed{seq, now})
	w.handedAt = append(w.handedAt, now)
	return seq, w.Tick()
}

// Tick writes every number held for Hold and fsyncs when Sync is due and StopSync not reached.
func (w *Writer) Tick() error {
	now := w.clk.Now()
	n := 0
	var buf []byte
	for ; n < len(w.pending) && now.Sub(w.pending[n].at) >= w.pol.Hold; n++ {
		buf = binary.LittleEndian.AppendUint64(buf, w.pending[n].seq)
	}
	if len(buf) > 0 {
		if _, err := w.f.Write(buf); err != nil {
			return fmt.Errorf("write: %w", err)
		}
		w.pending = w.pending[n:]
	}
	stopped := !w.pol.StopSync.IsZero() && !now.Before(w.pol.StopSync)
	if w.pol.Sync > 0 && !stopped && now.Sub(w.lastSync) >= w.pol.Sync {
		if err := w.f.Sync(); err != nil {
			return fmt.Errorf("sync: %w", err)
		}
		w.lastSync = now
	}
	return nil
}

// H is the end of the contiguous numbers handed over at least HandLag before failAt.
func (w *Writer) H(failAt time.Time) uint64 {
	var h uint64
	for h < uint64(len(w.handedAt)) && !w.handedAt[h].After(failAt.Add(-HandLag)) {
		h++
	}
	return h
}

// Stored reads the numbers a file of records holds, in order; a cut record is an error.
func Stored(data []byte) ([]uint64, error) {
	if len(data)%RecordSize != 0 {
		return nil, errors.New("cut record")
	}
	nums := make([]uint64, 0, len(data)/RecordSize)
	for i := 0; i < len(data); i += RecordSize {
		nums = append(nums, binary.LittleEndian.Uint64(data[i:]))
	}
	return nums, nil
}

// Lost counts the numbers up to h that stored does not hold: each of them was handed over before
// the failure in time to survive it.
func Lost(stored []uint64, h uint64) uint64 {
	seen := make(map[uint64]bool, len(stored))
	for _, n := range stored {
		seen[n] = true
	}
	var lost uint64
	for n := uint64(1); n <= h; n++ {
		if !seen[n] {
			lost++
		}
	}
	return lost
}
