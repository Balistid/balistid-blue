package rangeguest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"
)

// RecordSize is one stored number: 8 bytes, little endian.
const RecordSize = 8

// HandLag is how long before a failure a number must have been handed over to count in H, the end
// of the contiguous numbers that must survive it (ADR 0018, point 3).
const HandLag = 900 * time.Millisecond

// Policy is how the measured writer of the failure controls stores what it is handed (ADR 0018,
// point 4): it keeps a number in memory for Hold before write(), and fsyncs every Sync until it is
// told to stop (StopSync). Sync 0 never syncs.
type Policy struct {
	Hold time.Duration
	Sync time.Duration
}

// StopSyncing, handed over as a number, tells the writer to sync no more: the side that knows when
// the failure comes sends it, on its own clock (ADR 0020).
const StopSyncing = 0

// Freeze, handed over as a number, makes the writer write and sync nothing more and answer with
// Freeze and its final Synced: the failure then meets a writer whose synced state is known exactly
// (ADR 0020).
const Freeze = math.MaxUint64

// SyncFile is the part of *os.File the writer uses; tests replace it.
type SyncFile interface {
	Write(p []byte) (int, error)
	Sync() error
}

// Writer stores the numbers it is handed as records in one file under a Policy. It is driven by
// its caller: Append hands over a number, Tick writes and syncs what is due, so a test can run it on
// a fake clock and the guest can kill it with everything it held.
type Writer struct {
	f        SyncFile
	pol      Policy
	clk      Clock
	pending  []handed
	stopped  bool
	frozen   bool
	written  uint64
	lastSync time.Time
	// Synced is the highest number written before the last fsync that returned.
	Synced uint64
}

type handed struct {
	seq uint64
	at  time.Time
}

// NewWriter writes to f under pol.
func NewWriter(f SyncFile, pol Policy, clk Clock) *Writer {
	return &Writer{f: f, pol: pol, clk: clk, lastSync: clk.Now()}
}

// Append takes number seq and writes what is due; StopSyncing ends syncing instead.
func (w *Writer) Append(seq uint64) error {
	switch seq {
	case StopSyncing:
		w.stopped = true
		return w.Tick()
	case Freeze:
		w.frozen = true
		return nil
	}
	w.pending = append(w.pending, handed{seq, w.clk.Now()})
	return w.Tick()
}

// Tick writes every number held for Hold and fsyncs when Sync is due and syncing not stopped.
func (w *Writer) Tick() error {
	if w.frozen {
		return nil
	}
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
		w.written = max(w.written, w.pending[n-1].seq)
		w.pending = w.pending[n:]
	}
	if w.pol.Sync > 0 && !w.stopped && now.Sub(w.lastSync) >= w.pol.Sync {
		if err := w.f.Sync(); err != nil {
			return fmt.Errorf("sync: %w", err)
		}
		w.lastSync, w.Synced = now, w.written
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

// WindowMin is the fewest numbers handed over in any whole 10 s window from start to until, numbers
// due at rate per second from start and counted as Generate counts them (ADR 0019): in the window a
// number was due in if handed over at most grace after its end, else in the window it was handed over
// in. Without a whole window it is 0.
func (h *Handover) WindowMin(start, until time.Time, rate int) uint64 {
	counts := make([]uint64, until.Sub(start)/window)
	if len(counts) == 0 || rate < 1 {
		return 0
	}
	for i, at := range h.at {
		due := time.Duration(i) * time.Second / time.Duration(rate)
		w, done := int(due/window), at.Sub(start)
		if done > time.Duration(w+1)*window+grace {
			w = int(done / window)
		}
		if w < len(counts) {
			counts[w]++
		}
	}
	return slices.Min(counts)
}

// StoredPrefix returns the longest run 1..N of numbers a file of records holds, ignoring a cut
// last record (a crash may leave one past N), and how many whole records it holds.
func StoredPrefix(data []byte) (prefix, count uint64) {
	seen := make(map[uint64]bool, len(data)/RecordSize)
	for i := 0; i+RecordSize <= len(data); i += RecordSize {
		seen[binary.LittleEndian.Uint64(data[i:])] = true
		count++
	}
	for seen[prefix+1] {
		prefix++
	}
	return prefix, count
}

// ServeWriter is the measured writer's process: it stores each 8-byte number read from r through a
// Writer, ticking every millisecond so held records are written and syncs happen on time, until r
// ends. After each fsync that moved Synced it sends Synced to synced as 8 bytes; on Freeze it sends
// Freeze and then Synced, and stays idle.
func ServeWriter(r io.Reader, w *Writer, synced io.Writer) error {
	nums := make(chan uint64, 1024)
	readErr := make(chan error, 1)
	go func() {
		defer close(nums)
		var b [RecordSize]byte
		for {
			if _, err := io.ReadFull(r, b[:]); err != nil {
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
				return w.Tick()
			}
			before := w.Synced
			if err := w.Append(n); err != nil {
				return err
			}
			if n == Freeze { // the answer: the marker, then the final Synced
				if _, err := synced.Write(binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, Freeze), w.Synced)); err != nil {
					return fmt.Errorf("answer freeze: %w", err)
				}
				continue
			}
			if err := report(synced, before, w.Synced); err != nil {
				return err
			}
		case <-tick.C:
			before := w.Synced
			if err := w.Tick(); err != nil {
				return err
			}
			if err := report(synced, before, w.Synced); err != nil {
				return err
			}
		}
	}
}

func report(synced io.Writer, before, now uint64) error {
	if now == before {
		return nil
	}
	if _, err := synced.Write(binary.LittleEndian.AppendUint64(nil, now)); err != nil {
		return fmt.Errorf("report sync: %w", err)
	}
	return nil
}
