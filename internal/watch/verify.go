package watch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/entry"
)

const width = layout.EntryBundleWidth

var (
	// ErrFork: the witness is behind what the Pi verified, or holds another root at its size (T12).
	ErrFork = errors.New("watch: the witness's log is not the one the Pi verified")
	// ErrMismatch: the relay's bundles do not hash to the witness's root.
	ErrMismatch = errors.New("watch: the relay's bundles do not give the witness's root")
)

// Log is what the Pi verified of one origin's log: its size and root, the compact range over its complete
// bundles, the entries of an incomplete last bundle, and where the log's rules stand. The range and the
// partial entries together give the root, which check proves.
type Log struct {
	Size    uint64
	Root    [32]byte
	Hashes  [][]byte
	Partial [][]byte
	Rules   Rules
}

// Rules is the log's grammar after its last verified entry, as the ledger writes it (ADR 0027): seqs
// start at 1, so 0 is none yet.
type Rules struct {
	BatchLast   uint64 `json:"batch_last"`
	SealLast    uint64 `json:"seal_last"`
	SealedBatch bool   `json:"sealed_batch"` // a seal follows the last batch already
	LossMax     uint64 `json:"loss_max"`     // the highest lost record the next batch has to cover
	Final       bool   `json:"final"`
	Pending     bool   `json:"pending"` // the last health is UNKNOWN for a reason that clears by itself
}

// Findings is what one verified step's new entries say.
type Findings struct {
	Entries   uint64
	Broken    int    // entries that break a rule
	Problem   string // the first rule broken
	Lost      int    // losses of a stage other than truncated, and health with unstored records
	Truncated int
	Unknown   int // health UNKNOWN for a reason that alarms at once
	LogCap    int // the ledger's log at its cap (ADR 0036, point 5)
	Announced int
	Final     bool
}

// Fetch returns the first width entries of bundle idx.
type Fetch func(ctx context.Context, idx, width uint64) ([][]byte, error)

var rangeFactory = &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

// Advance verifies the log from l's size to the witness's head with the bundles fetch returns: the
// leaves appended to l's compact range must give the head's root, which proves every new entry included
// and the log consistent with l. Only then does it return the grown log and its findings; on any error
// l stays as it is. The relay's copy of entries the Pi already verified is never read.
func Advance(ctx context.Context, l Log, h Head, fetch Fetch) (Log, Findings, error) {
	switch {
	case h.Size < l.Size:
		return l, Findings{}, fmt.Errorf("%w: it holds %d entries, the Pi verified %d", ErrFork, h.Size, l.Size)
	case h.Size == 0 && !bytes.Equal(h.Root[:], rfc6962.DefaultHasher.EmptyRoot()):
		return l, Findings{}, fmt.Errorf("%w: not the empty root at 0 entries", ErrFork)
	case h.Size == l.Size && l.Size > 0 && h.Root != l.Root:
		return l, Findings{}, fmt.Errorf("%w: another root at %d entries", ErrFork, h.Size)
	case h.Size == l.Size:
		return l, Findings{}, nil
	}
	r, err := l.leaves()
	if err != nil {
		return l, Findings{}, err
	}
	next := Log{Rules: l.Rules, Hashes: slices.Clone(l.Hashes)}
	var f Findings
	partial := slices.Clone(l.Partial)
	for idx := l.Size / width; idx*width < h.Size; idx++ {
		w := min(h.Size-idx*width, width)
		got, err := fetch(ctx, idx, w)
		if err != nil {
			return l, Findings{}, err
		}
		if uint64(len(got)) != w {
			return l, Findings{}, fmt.Errorf("watch: bundle %d: %d entries, want %d", idx, len(got), w)
		}
		for _, raw := range got[len(partial):] {
			if err := r.Append(rfc6962.DefaultHasher.HashLeaf(raw), nil); err != nil {
				return l, Findings{}, fmt.Errorf("watch: range: %w", err)
			}
			next.Rules.check(raw, &f)
		}
		partial = append(partial, got[len(partial):]...)
		if w == width {
			next.Hashes, partial = slices.Clone(r.Hashes()), nil
		}
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		return l, Findings{}, fmt.Errorf("watch: range: %w", err)
	}
	if !bytes.Equal(root, h.Root[:]) {
		return l, Findings{}, fmt.Errorf("%w at %d entries", ErrMismatch, h.Size)
	}
	next.Size, next.Root, next.Partial = h.Size, h.Root, partial
	f.Entries = h.Size - l.Size
	return next, f, nil
}

// leaves is the compact range over all of l's leaves: its complete bundles' range and the partial entries.
func (l Log) leaves() (*compact.Range, error) {
	if uint64(len(l.Partial)) != l.Size%width {
		return nil, fmt.Errorf("watch: %d partial entries at size %d", len(l.Partial), l.Size)
	}
	r, err := rangeFactory.NewRange(0, l.Size-uint64(len(l.Partial)), slices.Clone(l.Hashes))
	if err != nil {
		return nil, fmt.Errorf("watch: stored range: %w", err)
	}
	for _, raw := range l.Partial {
		if err := r.Append(rfc6962.DefaultHasher.HashLeaf(raw), nil); err != nil {
			return nil, fmt.Errorf("watch: stored range: %w", err)
		}
	}
	return r, nil
}

// check proves a stored log consistent: its range and partial entries give its root.
func (l Log) check() error {
	r, err := l.leaves()
	if err != nil {
		return err
	}
	if l.Size == 0 {
		if l.Root != ([32]byte{}) {
			return errors.New("watch: stored root of an empty log")
		}
		return nil
	}
	root, err := r.GetRootHash(nil)
	if err != nil || !bytes.Equal(root, l.Root[:]) {
		return errors.Join(errors.New("watch: the stored range does not give the stored root"), err)
	}
	return nil
}

// check takes the next entry, in log order. A broken rule is counted, not stopped at: the entry is
// cosigned all the same, and the entries after it are still checked.
func (r *Rules) check(raw []byte, f *Findings) {
	broke := func(s string) {
		f.Broken++
		if f.Problem == "" {
			f.Problem = s
		}
	}
	e, err := entry.Decode(raw)
	if err != nil {
		broke("an entry that does not decode")
		return
	}
	if r.Final {
		broke("an entry after final")
	}
	switch b := e.Body.(type) {
	case entry.Batch:
		if r.BatchLast != 0 && b.First != r.BatchLast+1 {
			broke("a batch that does not follow the last one")
		}
		if b.Last < r.LossMax {
			broke("a loss the batch after it does not cover")
		}
		r.BatchLast, r.SealedBatch, r.LossMax = b.Last, false, 0
	case entry.Seal:
		switch {
		case r.BatchLast == 0 || b.Last != r.BatchLast || r.SealedBatch:
			broke("a seal not right after the batch ending at its last seq")
		case r.SealLast != 0 && b.First != r.SealLast+1:
			broke("seals that do not tile the seqs")
		}
		r.SealLast, r.SealedBatch = b.Last, true
	case entry.Loss:
		if b.Seq <= r.BatchLast {
			broke("a loss of a record already in a batch")
		}
		r.LossMax = max(r.LossMax, b.Seq)
		if b.Stage == entry.StageTruncated {
			f.Truncated++
		} else {
			f.Lost++
		}
	case entry.Health:
		r.health(b, f)
	case entry.Announce:
		f.Announced++
	case entry.Final:
		// at the cap the waiting batch is left out of the old log, its losses with it (ADR 0030, point 5)
		r.Final, f.Final, r.LossMax = true, true, 0
	}
}

// health: UNKNOWN alarms at once, except while starting or waiting for a canary, which the watchdog
// alarms only when no OK follows in time (ADR 0031, point 3).
func (r *Rules) health(h entry.Health, f *Findings) {
	if h.Unstored > 0 {
		f.Lost++
	}
	switch {
	case h.State == entry.StateOK:
		r.Pending = false
	case h.Reason == entry.ReasonStarting || h.Reason == entry.ReasonCanaryPending:
		r.Pending = true
	case h.Reason == entry.ReasonLogCap: // the ledger's, not the collector's: its own alert says what to do
		f.LogCap++
		r.Pending = false
	default:
		f.Unknown++
		r.Pending = false
	}
}
