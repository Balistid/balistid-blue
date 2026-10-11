package rangeguest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// Handover records when each number 1, 2, ... was handed over, as the side that hands them sees it.
type Handover struct{ at []time.Time }

// Add records the next number as handed over at t.
func (h *Handover) Add(t time.Time) { h.at = append(h.at, t) }

// H is the end of the contiguous numbers handed over at least HandLag before failAt.
func (h *Handover) H(failAt time.Time) uint64 {
	var n uint64
	for n < uint64(len(h.at)) && !h.at[n].After(failAt.Add(-HandLag)) {
		n++
	}
	return n
}

// StoredPrefix returns the longest run 1..N of numbers a file of records holds, ignoring a cut
// last record (a crash may leave one past N), and how many whole records it holds.
func StoredPrefix(data []byte) (prefix, count uint64) {
	nums, _ := Stored(data[:len(data)-len(data)%RecordSize])
	seen := make(map[uint64]bool, len(nums))
	for _, n := range nums {
		seen[n] = true
	}
	for seen[prefix+1] {
		prefix++
	}
	return prefix, uint64(len(nums))
}

// ServeWriter is the measured writer's process: it stores each 8-byte number read from r through a
// Writer, ticking every millisecond so held records are written and syncs happen on time, until r
// ends. A number out of sequence is an error.
func ServeWriter(r io.Reader, w *Writer) error {
	nums := make(chan uint64, 1024)
	readErr := make(chan error, 1)
	go func() {
		var b [RecordSize]byte
		for {
			if _, err := io.ReadFull(r, b[:]); err != nil {
				close(nums)
				if errors.Is(err, io.EOF) {
					err = nil
				}
				readErr <- err
				return
			}
			nums <- binary.LittleEndian.Uint64(b[:])
		}
	}()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case n, ok := <-nums:
			if !ok {
				if err := <-readErr; err != nil {
					return fmt.Errorf("read: %w", err)
				}
				return w.Flush()
			}
			seq, err := w.Append()
			if err != nil {
				return err
			}
			if seq != n {
				return fmt.Errorf("handed %d, expected %d", n, seq)
			}
		case <-tick.C:
			if err := w.Tick(); err != nil {
				return err
			}
		}
	}
}

// Flush writes everything held and syncs, at the end of a run nothing failed.
func (w *Writer) Flush() error {
	var buf []byte
	for _, p := range w.pending {
		buf = binary.LittleEndian.AppendUint64(buf, p.seq)
	}
	w.pending = nil
	if _, err := w.f.Write(buf); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	return nil
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
