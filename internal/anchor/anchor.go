// Package anchor is the ledger's log (ADR 0006, 0026, 0027): it appends the collector's stream as typed
// entries to an embedded Tessera POSIX log that signs its checkpoints, in the order ADR 0027 point 4
// fixes, and finds where the stream resumes in the log itself, never in a file beside it.
package anchor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
)

const (
	// CutEvery is the longest a batch waits after the last one: with a 100 ms tick and an append it
	// keeps batch entries within anchor_interval_s (1 s) while recording.
	CutEvery = 800 * time.Millisecond
	// tailBundles bounds how far back Open looks for the last batch (ADR 0027, point 4).
	tailBundles = 64
	// entryBytes bounds one entry on disk: its encoding, the bundle's length prefix and its share of
	// the hash tiles (32 bytes at level 0, a 255th of that per level above).
	entryBytes = entry.MaxBytes + 2 + 33
	lockName   = "ledger.lock"
)

// ErrStream marks a message the collector should not have sent; the log is unharmed.
var ErrStream = errors.New("anchor: out of stream order")

// Config opens a log.
type Config struct {
	Dir                string // the service's own directory (ADR 0007)
	Signer             note.Signer
	CapBytes           uint64 // host_log_cap_gib
	CheckpointInterval time.Duration
	Now                func() time.Time
}

// Resume is where the collector's stream continues: after Last, the last seq of the log's last batch,
// whose First and Root the collector checks against its own leaves (ADR 0027, point 3). Zero: no batch.
type Resume struct {
	Last, First uint64
	Root        [32]byte
}

type lossKey struct {
	seq   uint64
	stage entry.Stage
}

// Log appends the stream. Its methods are called from one goroutine.
type Log struct {
	add        tessera.AddFn
	shutdown   func(context.Context) error
	cancel     context.CancelFunc
	lock       *os.File
	now        func() time.Time
	maxSize    uint64
	size       uint64
	resume     Resume
	tailLoss   map[lossKey]entry.Loss // loss entries logged after the last batch
	tailSeal   *entry.Seal            // the seal logged after the last batch
	health     entry.Health           // the last health logged by this process
	batch      *entry.Root
	batchFirst uint64
	lastCut    time.Time
	broken     error
}

// Open locks dir for the process's lifetime, opens its log and reads back where the stream resumes.
// Close it before cancelling ctx's parent: Tessera finishes its work only on Close.
func Open(ctx context.Context, cfg Config) (*Log, error) {
	if !filepath.IsAbs(cfg.Dir) || cfg.Signer == nil || cfg.CapBytes < entryBytes || cfg.CheckpointInterval <= 0 || cfg.Now == nil {
		return nil, errors.New("anchor: incomplete config")
	}
	lock, err := lockDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	bg, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l := &Log{cancel: cancel, lock: lock, now: cfg.Now, maxSize: cfg.CapBytes / entryBytes,
		tailLoss: map[lossKey]entry.Loss{}, lastCut: cfg.Now()}
	fail := func(err error) (*Log, error) {
		cancel()
		return nil, errors.Join(err, lock.Close())
	}
	drv, err := posix.New(bg, posix.Config{Path: cfg.Dir})
	if err != nil {
		return fail(fmt.Errorf("anchor: open log: %w", err))
	}
	opts := tessera.NewAppendOptions().WithCheckpointSigner(cfg.Signer).
		WithCheckpointInterval(cfg.CheckpointInterval).WithBatching(1, tessera.DefaultBatchMaxAge)
	app, shutdown, reader, err := tessera.NewAppender(bg, drv, opts)
	if err != nil {
		return fail(fmt.Errorf("anchor: open log: %w", err))
	}
	l.add, l.shutdown = app.Add, shutdown
	if l.size, err = reader.IntegratedSize(ctx); err == nil {
		err = l.recover(ctx, reader)
	}
	if err != nil {
		return fail(errors.Join(fmt.Errorf("anchor: %w", err), shutdown(ctx)))
	}
	return l, nil
}

func lockDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600) //nolint:gosec // the service's own directory
	if err != nil {
		return nil, fmt.Errorf("anchor: lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(fmt.Errorf("anchor: another ledger holds %s: %w", dir, err), f.Close())
	}
	return f, nil
}

// recover reads the log back, newest first, to its last batch; the losses and the seal after it are
// what a resent stream must not log twice.
func (l *Log) recover(ctx context.Context, r tessera.LogReader) error {
	var after []entry.Entry
	for end, n := l.size, 0; end > 0; n++ {
		if n == tailBundles {
			return fmt.Errorf("no batch in the last %d bundles", tailBundles)
		}
		idx := (end - 1) / layout.EntryBundleWidth
		b, err := client.GetEntryBundle(ctx, r.ReadEntryBundle, idx, l.size)
		if err != nil {
			return fmt.Errorf("read the log's tail: %w", err)
		}
		if uint64(len(b.Entries)) != end-idx*layout.EntryBundleWidth {
			return fmt.Errorf("bundle %d holds %d entries", idx, len(b.Entries))
		}
		for i := len(b.Entries) - 1; i >= 0; i-- {
			e, err := entry.Decode(b.Entries[i])
			if err != nil {
				return fmt.Errorf("log entry %d: %w", idx*layout.EntryBundleWidth+uint64(i), err)
			}
			if batch, ok := e.Body.(entry.Batch); ok {
				l.resume = Resume{Last: batch.Last, First: batch.First, Root: batch.Root}
				return l.tail(after)
			}
			after = append(after, e)
		}
		end = idx * layout.EntryBundleWidth
	}
	return l.tail(after)
}

// tail takes the entries after the last batch: losses of later records, the seal that ended at it.
func (l *Log) tail(after []entry.Entry) error {
	for _, e := range after {
		switch body := e.Body.(type) {
		case entry.Loss:
			if body.Seq <= l.resume.Last {
				return fmt.Errorf("loss of record %d after the batch through %d", body.Seq, l.resume.Last)
			}
			l.tailLoss[lossKey{body.Seq, body.Stage}] = body
		case entry.Seal:
			if body.Last != l.resume.Last || l.tailSeal != nil {
				return fmt.Errorf("seal through %d after the batch through %d", body.Last, l.resume.Last)
			}
			l.tailSeal = &body
		}
	}
	return nil
}

// Resume is where the stream continues.
func (l *Log) Resume() Resume { return l.resume }

// Broken is why the log stopped appending, or nil. Once broken it stays so until the process restarts.
func (l *Log) Broken() error { return l.broken }

func (l *Log) next() uint64 {
	if l.batch != nil {
		return l.batchFirst + l.batch.Len()
	}
	return l.resume.Last + 1
}

// Record adds the next record: first the loss entry it carries, which precedes the batch covering it.
func (l *Log) Record(ctx context.Context, r link.Record) error {
	if l.broken != nil {
		return l.broken
	}
	if want := l.next(); r.Seq != want || r.Seq > entry.MaxSeq {
		return fmt.Errorf("%w: record %d, want %d", ErrStream, r.Seq, want)
	}
	if r.Loss != nil && r.Loss.Seq != r.Seq {
		return fmt.Errorf("%w: loss of record %d carried by %d", ErrStream, r.Loss.Seq, r.Seq)
	}
	if loss := r.Loss; loss != nil {
		switch logged, ok := l.tailLoss[lossKey{loss.Seq, loss.Stage}]; {
		case ok && logged != *loss: // the same record's loss again, with another count
			l.broken = fmt.Errorf("anchor: loss %+v resent as %+v", logged, *loss)
			return l.broken
		case !ok:
			if err := l.append(ctx, *loss); err != nil {
				return err
			}
			l.tailLoss[lossKey{loss.Seq, loss.Stage}] = *loss
		}
	}
	if l.batch == nil {
		l.batch, l.batchFirst = entry.NewRoot(), r.Seq
	}
	if err := l.batch.Add(r.Leaf); err != nil {
		l.broken = fmt.Errorf("anchor: %w", err)
		return l.broken
	}
	return nil
}

// Seal logs a sealed shard right after the batch ending at its last record. A seal anywhere else, or
// another one at the same place, breaks the log (ADR 0027, point 4); the same one again is a resend.
func (l *Log) Seal(ctx context.Context, s entry.Seal) error {
	if l.broken != nil {
		return l.broken
	}
	if pos := l.next() - 1; s.Last != pos {
		l.broken = fmt.Errorf("anchor: seal %d-%d at stream position %d", s.First, s.Last, pos)
		return l.broken
	}
	if l.batch != nil {
		if err := l.cut(ctx); err != nil {
			return err
		}
	}
	if l.tailSeal != nil {
		if *l.tailSeal == s {
			return nil
		}
		l.broken = fmt.Errorf("anchor: seal %d-%d where %d-%d is logged", s.First, s.Last, l.tailSeal.First, l.tailSeal.Last)
		return l.broken
	}
	if err := l.append(ctx, s); err != nil {
		return err
	}
	l.tailSeal = &s
	return nil
}

// Health logs the collector's health when it differs from the last one this process logged.
func (l *Log) Health(ctx context.Context, h entry.Health) error {
	if l.broken != nil {
		return l.broken
	}
	if h == l.health {
		return nil
	}
	if err := l.append(ctx, h); err != nil {
		return err
	}
	l.health = h
	return nil
}

// Tick logs the waiting batch once CutEvery has passed since the last one.
func (l *Log) Tick(ctx context.Context) error {
	if l.broken != nil || l.batch == nil || l.now().Sub(l.lastCut) < CutEvery {
		return l.broken
	}
	return l.cut(ctx)
}

// Flush logs the waiting batch now: when the collector disconnects, and before Close.
func (l *Log) Flush(ctx context.Context) error {
	if l.broken != nil || l.batch == nil {
		return l.broken
	}
	return l.cut(ctx)
}

func (l *Log) cut(ctx context.Context) error {
	root, err := l.batch.Sum()
	if err != nil {
		l.broken = fmt.Errorf("anchor: %w", err)
		return l.broken
	}
	b := entry.Batch{First: l.batchFirst, Last: l.batchFirst + l.batch.Len() - 1, Root: root}
	if err := l.append(ctx, b); err != nil {
		return err
	}
	l.resume, l.batch, l.tailSeal, l.lastCut = Resume{Last: b.Last, First: b.First, Root: root}, nil, nil, l.now()
	clear(l.tailLoss)
	return nil
}

// append logs one entry and waits until Tessera has integrated it, so entries land in call order and a
// failure is never followed by a later entry (R6).
func (l *Log) append(ctx context.Context, body entry.Body) error {
	if l.size >= l.maxSize {
		l.broken = fmt.Errorf("anchor: log at its cap of %d entries (host_log_cap_gib)", l.maxSize)
		return l.broken
	}
	b, err := entry.Entry{At: l.now().UnixNano(), Body: body}.Encode()
	if err != nil {
		l.broken = fmt.Errorf("anchor: %w", err)
		return l.broken
	}
	idx, err := l.add(context.WithoutCancel(ctx), tessera.NewEntry(b))()
	if err == nil && idx.Index != l.size {
		err = fmt.Errorf("entry landed at %d, want %d", idx.Index, l.size)
	}
	if err != nil {
		l.broken = fmt.Errorf("anchor: append: %w", err)
		return l.broken
	}
	l.size++
	return nil
}

// Close logs the waiting batch, lets Tessera publish a checkpoint that covers it, and unlocks.
func (l *Log) Close(ctx context.Context) error {
	err := l.Flush(ctx)
	err = errors.Join(err, l.shutdown(ctx))
	l.cancel()
	return errors.Join(err, l.lock.Close())
}
