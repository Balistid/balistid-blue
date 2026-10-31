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
	"sync"
	"syscall"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
)

const (
	// CutEvery is the longest a batch waits after the last one: with a 100 ms tick and an append it
	// keeps batch entries within anchor_interval_s (1 s) while recording.
	CutEvery = 800 * time.Millisecond
	// tailBundles bounds how far back Open looks for the last batch (ADR 0027, point 4).
	tailBundles = 64
	entryBytes  = entry.LogBytes
	lockName    = "ledger.lock"
)

// ErrStream marks a message the collector should not have sent; the log is unharmed.
var ErrStream = errors.New("anchor: out of stream order")

// ErrFinal marks an append after the log's final entry (ADR 0030, point 5): the log is whole and takes
// nothing more; the collector's store keeps the records for the next yearly log.
var ErrFinal = errors.New("anchor: the log ended with its final entry")

// ErrFull marks an append at the cap (host_log_cap_gib): the log took its UNKNOWN for the cap and takes only its
// final entry now, in the slots the cap keeps for them (ADR 0036, point 5); the collector's store keeps the records
// for the next log.
var ErrFull = errors.New("anchor: the log is at its cap and takes only its final entry")

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

// sealAt is a seal and the log's size once it was in: a checkpoint of that size or more covers it.
type sealAt struct {
	seal entry.Seal
	size uint64
}

type lossKey struct {
	seq   uint64
	stage entry.Stage
}

// Log appends the stream, and the announcements and final entry of the control socket. Its exported
// methods hold mu, so the stream's and the control socket's goroutines append in turn.
type Log struct {
	mu         sync.Mutex
	origin     string
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
	pending    *sealAt                // the last seal this process logged or saw resent, not yet known cosigned
	covered    *sealAt                // the newest seal a cosigned checkpoint covers, as far as this process knows
	health     entry.Health           // the last health logged by this process
	batch      *entry.Root
	batchFirst uint64
	lastCut    time.Time
	broken     error
	final      *entry.Final // the log's last entry, once logged
}

// Open locks dir for the process's lifetime, opens its log and reads back where the stream resumes.
// Close it before cancelling ctx's parent: Tessera finishes its work only on Close.
func Open(ctx context.Context, cfg Config) (*Log, error) {
	// The cap keeps its last two slots, for its UNKNOWN and the final entry, so at least one other must fit.
	if !filepath.IsAbs(cfg.Dir) || cfg.Signer == nil || cfg.CapBytes < 3*entryBytes || cfg.CheckpointInterval <= 0 || cfg.Now == nil {
		return nil, errors.New("anchor: incomplete config")
	}
	lock, err := lockDir(cfg.Dir)
	if err != nil {
		return nil, err
	}
	bg, cancel := context.WithCancel(context.WithoutCancel(ctx))
	l := &Log{origin: cfg.Signer.Name(), cancel: cancel, lock: lock, now: cfg.Now, maxSize: cfg.CapBytes / entryBytes,
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

// tail takes the entries after the last batch, newest first: losses of later records, the seal that
// ended at it, and the final entry, which only the newest may be.
func (l *Log) tail(after []entry.Entry) error {
	for i, e := range after {
		switch body := e.Body.(type) {
		case entry.Final:
			if i != 0 {
				return fmt.Errorf("%d entries after the final one", i)
			}
			l.final = &body
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
func (l *Log) Resume() Resume {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.resume
}

// Broken is why the log stopped appending, or nil. Once broken it stays so until the process restarts.
func (l *Log) Broken() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.broken
}

// Full reports whether the log is at its cap without its final entry: only that still fits.
func (l *Log) Full() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.final == nil && l.size >= l.maxSize-1
}

// Ended reports whether the log holds its final entry.
func (l *Log) Ended() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.final != nil
}

// stopped is why nothing more is appended: the log broke or ended.
func (l *Log) stopped() error {
	switch {
	case l.broken != nil:
		return l.broken
	case l.final != nil:
		return ErrFinal
	case l.size >= l.maxSize-1:
		return ErrFull
	}
	return nil
}

func (l *Log) next() uint64 {
	if l.batch != nil {
		return l.batchFirst + l.batch.Len()
	}
	return l.resume.Last + 1
}

// Record adds the next record: first the loss entry it carries, which precedes the batch covering it.
func (l *Log) Record(ctx context.Context, r link.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.stopped(); err != nil {
		return err
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
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.stopped(); err != nil {
		return err
	}
	if pos := l.next() - 1; s.Last != pos {
		l.broken = fmt.Errorf("anchor: seal %d-%d at stream position %d", s.First, s.Last, pos)
		return l.broken
	}
	if err := l.flush(ctx); err != nil {
		return err
	}
	if l.tailSeal != nil {
		if *l.tailSeal == s { // logged before: within the log as it is now
			l.pending = &sealAt{s, l.size}
			return nil
		}
		l.broken = fmt.Errorf("anchor: seal %d-%d where %d-%d is logged", s.First, s.Last, l.tailSeal.First, l.tailSeal.Last)
		return l.broken
	}
	if err := l.append(ctx, s); err != nil {
		return err
	}
	l.tailSeal, l.pending = &s, &sealAt{s, l.size}
	return nil
}

// Cosigned is the frame a checkpoint the witness cosigned gives the collector (ADR 0029, point 2): the
// newest seal it covers, with the note. A seal counts once the checkpoint's size reaches the log's size
// after it; only seals this process logged or saw resent count, so after a restart none does until the
// next one. ok is false while none does, and for a checkpoint older than the covered seal, which a
// replayed note would be. A cosigned size past the log means the log lost cosigned history (T12).
func (l *Log) Cosigned(cp cosign.Checkpoint) (m link.Cosigned, ok bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cp.Size > l.size {
		return link.Cosigned{}, false, fmt.Errorf("anchor: the witness cosigned %d entries, the log holds %d", cp.Size, l.size)
	}
	if l.pending != nil && cp.Size >= l.pending.size {
		l.covered, l.pending = l.pending, nil
	}
	if l.covered == nil || cp.Size < l.covered.size {
		return link.Cosigned{}, false, nil
	}
	return link.Cosigned{Seal: l.covered.seal, Note: cp.Note}, true, nil
}

// Health logs the collector's health when it differs from the last one this process logged.
func (l *Log) Health(ctx context.Context, h entry.Health) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.stopped(); err != nil {
		return err
	}
	if h == l.health {
		return nil
	}
	if h.Reason == entry.ReasonLogCap { // the ledger's own, at its cap: a collector claiming it lies
		return fmt.Errorf("%w: the collector's health claims the log's cap", ErrStream)
	}
	if err := l.append(ctx, h); err != nil {
		return err
	}
	l.health = h
	return nil
}

// Announce logs a clean shutdown or suspend after the waiting batch (ADR 0030, point 1) and returns the
// log's size with it: a checkpoint of that size or more covers the announcement and every record before it.
func (l *Log) Announce(ctx context.Context, kind entry.Announcement) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.stopped(); err != nil {
		return 0, err
	}
	if err := l.flush(ctx); err != nil {
		return 0, err
	}
	if err := l.append(ctx, entry.Announce{Kind: kind}); err != nil {
		return 0, err
	}
	return l.size, nil
}

// Final ends the log after the waiting batch with an entry naming the next yearly log, in the slot the
// cap keeps for it (ADR 0030, point 5), and returns the log's size with it. The same final again
// returns that size; another one, or one naming this log, is refused and leaves the log as it is.
func (l *Log) Final(ctx context.Context, next string) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.broken != nil:
		return 0, l.broken
	case l.final != nil && l.final.NextOrigin == next:
		return l.size, nil
	case l.final != nil:
		return 0, ErrFinal
	case next == l.origin:
		return 0, fmt.Errorf("anchor: a final entry naming this log, %q", next)
	}
	f := entry.Final{NextOrigin: next}
	if _, err := (entry.Entry{Body: f}).Encode(); err != nil {
		return 0, err //nolint:wrapcheck // entry errors carry their context
	}
	// At the cap the waiting batch no longer fits: it is left out, and its records, still in the
	// collector's store, are resent to the next log from the last batch logged here.
	if err := l.flush(ctx); err != nil && !errors.Is(err, ErrFull) {
		return 0, err
	}
	l.batch = nil
	if err := l.append(ctx, f); err != nil {
		return 0, err
	}
	l.final = &f
	return l.size, nil
}

// Tick logs the waiting batch once CutEvery has passed since the last one.
func (l *Log) Tick(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken != nil || l.batch == nil || l.now().Sub(l.lastCut) < CutEvery {
		return l.broken
	}
	return l.cut(ctx)
}

// Flush logs the waiting batch now: when the collector disconnects, and before Close.
func (l *Log) Flush(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flush(ctx)
}

func (l *Log) flush(ctx context.Context) error {
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

// capHealth is what the log logs in the first of the two slots its cap keeps: the Pi alarms on it at once.
var capHealth = entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLogCap}

// append logs one entry and waits until Tessera has integrated it, so entries land in call order and a
// failure is never followed by a later entry (R6). The cap keeps its last two slots (ADR 0036, point 5): an
// entry that reaches the first is refused and capHealth takes it instead, once; the last is the final entry's.
func (l *Log) append(ctx context.Context, body entry.Body) error {
	_, final := body.(entry.Final)
	switch {
	case final && l.size >= l.maxSize, !final && body != entry.Body(capHealth) && l.size > l.maxSize-2:
		return fmt.Errorf("%w: %d entries", ErrFull, l.maxSize)
	case !final && body != entry.Body(capHealth) && l.size == l.maxSize-2:
		if err := l.append(ctx, capHealth); err != nil {
			return err
		}
		return fmt.Errorf("%w: %d entries", ErrFull, l.maxSize)
	}
	b, err := entry.Entry{At: l.now().UnixNano(), Body: body}.Encode()
	if err != nil {
		l.broken = fmt.Errorf("anchor: %w", err)
		return l.broken
	}
	return l.appendEncoded(ctx, b)
}

func (l *Log) appendEncoded(ctx context.Context, b []byte) error {
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
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.flush(ctx)
	if errors.Is(err, ErrFull) { // the waiting batch goes to the next log
		err = nil
	}
	err = errors.Join(err, l.shutdown(ctx))
	l.cancel()
	return errors.Join(err, l.lock.Close())
}
