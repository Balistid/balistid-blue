package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// leavesPerTick bounds what one tick reads for the ledger: eight ticks of sustained_rate, so a
	// stream that fell behind catches up while a tick stays short (BenchmarkLeaves).
	leavesPerTick = 4096
	// leavesBytesPerTick bounds the record data one tick walks past to read leaves: about 30 ms warm
	// (BenchmarkLeaves), far inside the 10 s watchdog, when large records fill the backlog.
	leavesBytesPerTick = 64 << 20
	// checkBytes bounds the ledger's last batch the writer reads back: a batch covers what four ticks of
	// leavesBytesPerTick send in CutEvery, so a larger one is a ledger that lies.
	checkBytes = 256 << 20
	// ledgerQueue bounds the groups waiting for the connection; when full the writer sends them later.
	ledgerQueue   = 16
	redialEvery   = time.Second
	ledgerTimeout = 5 * time.Second
	// healthEvery spaces health entries whose state stayed and whose unstored count changed.
	healthEvery = time.Minute
)

// group is what the writer hands over at once: records up to a seal and the seal, so a full queue
// never splits a seal from the batch ending at it (ADR 0027, point 4). last is its last seq, or 0.
type group struct {
	epoch uint64
	msgs  []link.Message
	last  uint64
}

type helloOf struct {
	epoch uint64
	hello link.Hello
}

// Ledger is the collector's end of the stream to the ledger (ADR 0027). Its goroutine owns the
// connection; the writer hands it groups on its tick and never waits.
type Ledger struct {
	dial  func(ctx context.Context) (*net.UnixConn, error)
	log   *slog.Logger
	out   chan group
	hello chan helloOf
	epoch uint64 // numbers connections: a group queued for an earlier one is dropped; Run's alone
}

// NewLedger returns the stream's end that dial connects.
func NewLedger(dial func(ctx context.Context) (*net.UnixConn, error), log *slog.Logger) *Ledger {
	return &Ledger{dial: dial, log: log, out: make(chan group, ledgerQueue), hello: make(chan helloOf, 1)}
}

// DialLedger connects to the ledger's socket at path and refuses any peer but ledgerUID (ADR 0027).
func DialLedger(path string, ledgerUID int) func(ctx context.Context) (*net.UnixConn, error) {
	return func(ctx context.Context) (*net.UnixConn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, fmt.Errorf("collector: ledger: %w", err)
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return nil, errors.Join(errors.New("collector: ledger: not a unix connection"), c.Close())
		}
		p, err := unixsock.PeerCred(uc)
		if err == nil && p.UID != ledgerUID {
			err = fmt.Errorf("collector: ledger socket held by uid %d, want %d", p.UID, ledgerUID)
		}
		if err != nil {
			return nil, errors.Join(err, uc.Close())
		}
		return uc, nil
	}
}

// Run connects, hands the ledger's hello to the writer and sends what it queues, until ctx ends.
func (l *Ledger) Run(ctx context.Context) {
	up := true
	for ctx.Err() == nil {
		err := l.session(ctx)
		if up && ctx.Err() == nil {
			l.log.Warn("ledger link down, redialing every second", "err", err)
		}
		up = err == nil
		select {
		case <-ctx.Done():
		case <-time.After(redialEvery):
		}
	}
}

func (l *Ledger) session(ctx context.Context) error {
	c, err := l.dial(ctx)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	defer c.Close() //nolint:errcheck // the session ends here either way
	if err := c.SetReadDeadline(time.Now().Add(ledgerTimeout)); err != nil {
		return fmt.Errorf("collector: ledger: %w", err)
	}
	m, err := link.Read(c)
	hello, ok := m.(link.Hello)
	if err != nil || !ok {
		return errors.Join(fmt.Errorf("collector: ledger sent %T first", m), err)
	}
	l.epoch++
	epoch := l.epoch
	select { // a hello the writer has not taken yet is stale now
	case <-l.hello:
	default:
	}
	l.hello <- helloOf{epoch, hello}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("collector: ledger: %w", err)
	}
	closed := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Go(func() { // the ledger sends nothing after its hello: a read ends only with the connection
		_, err := c.Read(make([]byte, 1))
		closed <- err
	})
	defer wg.Wait()
	defer c.Close() //nolint:errcheck // ends the read before wg.Wait
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-closed:
			return fmt.Errorf("collector: ledger closed the stream: %w", err)
		case g := <-l.out:
			if g.epoch != epoch {
				continue
			}
			if err := c.SetWriteDeadline(time.Now().Add(ledgerTimeout)); err != nil {
				return fmt.Errorf("collector: ledger: %w", err)
			}
			for _, m := range g.msgs {
				if err := link.Write(c, m); err != nil {
					return fmt.Errorf("collector: ledger: %w", err)
				}
			}
		}
	}
}

// send queues g without waiting and reports whether it was taken.
func (l *Ledger) send(g group) bool {
	select {
	case l.out <- g:
		return true
	default:
		return false
	}
}

// groups cuts leaves into groups of one record frame of at most link.MaxRecords, a group ending with
// the seal of the shard whose last record ends its frame, and gives each record the loss it carries.
func groups(epoch uint64, leaves []shard.Leaf, seals []store.Seal) ([]group, error) {
	var out []group
	var recs link.Records
	for _, l := range leaves {
		loss, err := lossOf(l)
		if err != nil {
			return nil, err
		}
		recs = append(recs, link.Record{Seq: l.Seq, Leaf: l.Hash, Loss: loss})
		sealed := len(seals) > 0 && seals[0].Last == l.Seq
		if !sealed && len(recs) < link.MaxRecords {
			continue
		}
		g := group{epoch: epoch, msgs: []link.Message{recs}, last: l.Seq}
		if sealed {
			g.msgs, seals = append(g.msgs, sealEntry(seals[0])), seals[1:]
		}
		out, recs = append(out, g), nil
	}
	if len(recs) > 0 {
		out = append(out, group{epoch: epoch, msgs: []link.Message{recs}, last: recs[len(recs)-1].Seq})
	}
	if len(seals) > 0 {
		return nil, fmt.Errorf("collector: seal through %d past the leaves read", seals[0].Last)
	}
	return out, nil
}

func sealEntry(s store.Seal) entry.Seal {
	return entry.Seal{First: s.First, Last: s.Last, SHA256: s.SHA256}
}

var lossStages = map[Stage]entry.Stage{
	StageCap: entry.StageCap, StageQueue: entry.StageQueue, StageFraming: entry.StageFraming,
	StageStore: entry.StageStore, StageShutdown: entry.StageShutdown,
}

// lossOf is the loss a stored record carries: a truncated sensor record, the store's loss record, or
// the collector's lost record (ADR 0027, point 6). Own records are decoded strictly: they are ours.
func lossOf(l shard.Leaf) (*entry.Loss, error) {
	loss := &entry.Loss{Seq: l.Seq}
	switch l.Provider {
	case store.SensorProvider:
		if !l.Truncated {
			return nil, nil
		}
		loss.Stage, loss.Records = entry.StageTruncated, 1
	case store.LossProvider:
		var r struct {
			SchemaVersion int    `json:"schema_version"`
			Dropped       uint64 `json:"dropped"`
			FirstReceived int64  `json:"first_received"`
			LastReceived  int64  `json:"last_received"`
		}
		if err := strict(l.Data, &r); err != nil || r.SchemaVersion != 1 || r.Dropped == 0 {
			return nil, fmt.Errorf("collector: store loss record %d: %w", l.Seq, errors.Join(err, errors.New("unexpected fields")))
		}
		loss.Stage, loss.Records = entry.StageCap, r.Dropped
	case store.HealthProvider:
		var kind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(l.Data, &kind); err != nil {
			return nil, fmt.Errorf("collector: health record %d: %w", l.Seq, err)
		}
		if kind.Kind != "lost" {
			return nil, nil
		}
		var r struct {
			SchemaVersion int    `json:"schema_version"`
			At            int64  `json:"at"`
			NoteSeq       uint64 `json:"note_seq"`
			Kind          string `json:"kind"`
			Stage         Stage  `json:"stage"`
			Count         uint64 `json:"count"`
			Bytes         uint64 `json:"bytes"`
			FirstSeq      uint64 `json:"first_seq"`
			LastSeq       uint64 `json:"last_seq"`
			FirstAt       int64  `json:"first_at"`
			LastAt        int64  `json:"last_at"`
		}
		err := strict(l.Data, &r)
		stage, known := lossStages[r.Stage]
		if err != nil || !known || r.SchemaVersion != healthSchema || r.Count == 0 {
			return nil, fmt.Errorf("collector: lost record %d: %w", l.Seq, errors.Join(err, errors.New("unexpected fields")))
		}
		loss.Stage, loss.Records = stage, r.Count
	default:
		return nil, fmt.Errorf("collector: record %d of unknown provider", l.Seq)
	}
	return loss, nil
}

// strict decodes one JSON object into v, refusing unknown fields and trailing data.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if d.More() {
		return errors.New("decode: data after the object")
	}
	return nil
}

// healthEntry is the health entry for the writer's health string (setHealth), with the unstored count.
func healthEntry(h string, unstored uint64) (entry.Health, error) {
	e := entry.Health{State: entry.StateUnknown, Unstored: unstored}
	switch {
	case h == "OK":
		e.State = entry.StateOK
	case h == "UNKNOWN store: starting":
		e.Reason = entry.ReasonStarting
	case strings.HasPrefix(h, "UNKNOWN store: "):
		e.Reason = entry.ReasonStoreDown
	case h == "UNKNOWN laurel-disconnected":
		e.Reason = entry.ReasonLaurelDisconnected
	case h == "UNKNOWN canary-missed":
		e.Reason = entry.ReasonCanaryMissed
	case h == "UNKNOWN canary-pending":
		e.Reason = entry.ReasonCanaryPending
	case h == streamUnknown:
		e.Reason = entry.ReasonStream
	default:
		return entry.Health{}, fmt.Errorf("collector: no health entry for %q", h)
	}
	return e, nil
}

// streamUnknown is the writer's health while its stream to the ledger stopped or cannot read leaves.
const streamUnknown = "UNKNOWN ledger-stream"

// maxBatchCheck bounds the batch a hello may ask the writer to read back: the ledger cuts a batch every
// CutEvery, far below this, and a larger one would let it make the collector read the whole store.
const maxBatchCheck = 1 << 16

// stream feeds the ledger on the writer's tick (ADR 0027): health whatever the store does, committed
// records once the ledger's resume point checked out against the store. It never waits.
func (w *Writer) stream(ctx context.Context) {
	if w.Ledger == nil {
		return
	}
	select {
	case h := <-w.Ledger.hello:
		w.epoch, w.hello, w.healthSent = h.epoch, &h.hello, ""
	default:
	}
	if w.epoch == 0 {
		return
	}
	// The resume point is checked before any health goes, so a stream that stops never logs OK first.
	if w.st != nil && w.hello != nil && w.stopped == "" {
		w.check(ctx)
	}
	defer w.sendHealth() // also after the stream stopped: the ledger logs why (ADR 0027, point 3)
	if w.st == nil || w.hello != nil || w.stopped != "" || !w.sealAtSent() {
		return
	}
	leaves, seals, err := w.st.Leaves(ctx, w.sent, leavesPerTick, leavesBytesPerTick)
	if err != nil {
		if err.Error() != w.leavesErr {
			w.Log.Error("ledger stream: leaves not read", "err", err)
		}
		w.leavesErr = err.Error()
		return
	}
	w.leavesErr = ""
	gs, err := groups(w.epoch, leaves, seals)
	if err != nil {
		w.stop(err)
		return
	}
	for _, g := range gs {
		if !w.Ledger.send(g) {
			return
		}
		if w.sent = g.last; len(g.msgs) == 2 { // the frame and the seal ending it
			w.sealSent = g.last
		}
	}
}

// check holds the ledger's resume point against the store: the ledger may not be ahead of it, and its
// last batch's root must be the store's own leaves; otherwise the stream stops (ADR 0027, point 3).
func (w *Writer) check(ctx context.Context) {
	h := *w.hello
	switch {
	case h.Last > w.st.Committed():
		w.stop(fmt.Errorf("ledger resumes after %d, the store committed %d", h.Last, w.st.Committed()))
		return
	case h.Last-h.First >= maxBatchCheck:
		w.stop(fmt.Errorf("ledger's last batch %d-%d is larger than any it cuts", h.First, h.Last))
		return
	}
	if h.Last > 0 {
		span := h.Last - h.First + 1
		leaves, _, err := w.st.Leaves(ctx, h.First-1, int(span), checkBytes) //nolint:gosec // below maxBatchCheck
		if err != nil {                                                      // the resume point unread is a stream that cannot go on: UNKNOWN until it reads
			if err.Error() != w.leavesErr {
				w.Log.Error("ledger stream: resume point not read", "err", err)
			}
			w.leavesErr = err.Error()
			return
		}
		if uint64(len(leaves)) != span {
			w.stop(fmt.Errorf("ledger's last batch %d-%d holds more data than any it cuts", h.First, h.Last))
			return
		}
		r := entry.NewRoot()
		for _, l := range leaves {
			if err := r.Add(l.Hash); err != nil {
				w.stop(err)
				return
			}
		}
		if root, err := r.Sum(); err != nil || root != h.Root {
			w.stop(errors.Join(fmt.Errorf("ledger's batch %d-%d is not the store's", h.First, h.Last), err))
			return
		}
	}
	// The seal ending where the ledger resumes may be missing after a crash; sealAtSent resends it.
	w.hello, w.sent, w.sealSent, w.leavesErr = nil, h.Last, 0, ""
}

// sealAtSent hands the ledger the seal of a shard whose last record it already has: a shard sealed when the
// next record arrived (rotation in Append) ends at sent, which Leaves, reading after sent, never returns.
// It reports whether the stream may go on to the records after it.
func (w *Writer) sealAtSent() bool {
	if w.sent == 0 || w.sealSent == w.sent {
		return true
	}
	seals := w.st.Seals()
	i := slices.IndexFunc(seals, func(s store.Seal) bool { return s.Last == w.sent })
	if i < 0 {
		return true
	}
	if !w.Ledger.send(group{epoch: w.epoch, msgs: []link.Message{sealEntry(seals[i])}}) {
		return false
	}
	w.sealSent = w.sent
	return true
}

// sendHealth hands the ledger the writer's health on connect and on change; a changed unstored count
// alone goes at most every healthEvery.
func (w *Writer) sendHealth() {
	unstored, now, h := w.unstored(), w.Now(), w.health
	if h == "OK" && (w.stopped != "" || w.leavesErr != "") { // the tick's health predates this tick's stream
		h = streamUnknown
	}
	if h == w.healthSent && (unstored == w.unstoredSent || now.Sub(w.healthAt) < healthEvery) {
		return
	}
	e, err := healthEntry(h, unstored)
	if err != nil {
		w.stop(err)
		return
	}
	if w.Ledger.send(group{epoch: w.epoch, msgs: []link.Message{e}}) {
		w.healthSent, w.unstoredSent, w.healthAt = h, unstored, now
	}
}

// unstored counts the records the collector counted lost whose loss record the store has not committed.
func (w *Writer) unstored() uint64 {
	n := w.capped.Count
	for _, l := range w.pending {
		n += l.Count
	}
	for _, x := range append(slices.Clone(w.inflight), w.notes...) {
		if x.kind == "lost" {
			n += x.l.Count
		}
	}
	return n
}

// stop ends the stream for good: what the ledger holds and what the store holds disagree, or the
// collector cannot say what a record carries (R6). Health turns UNKNOWN; a restart retries.
func (w *Writer) stop(err error) {
	w.stopped = err.Error()
	w.Log.Error("ledger stream stopped", "err", err)
}
