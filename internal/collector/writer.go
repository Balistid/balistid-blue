package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const (
	// StageFraming counts records the store refused for themselves (store.ErrRefused).
	StageFraming Stage = "framing"
	// StageStore counts records lost to a failing store call, at most (ADR 0016, point 4).
	StageStore Stage = "store"
	// StageShutdown counts records still queued when the store could not take them at stop.
	StageShutdown Stage = "shutdown"

	// ReopenEvery is how long the writer waits before opening a failed store again.
	ReopenEvery = 30 * time.Second
	// statsEvery is how often stats and the refusal summary are stored (refusal_summary_s).
	statsEvery = time.Minute
	// lagBudget is the longest handover-to-commit time before it is a health event (crash_loss_ms).
	lagBudget    = time.Second
	healthSchema = 1
	// maxNotes bounds health records waiting for the store; older ones give way and are counted.
	maxNotes = 64
)

// Store is what the writer needs of the store; *store.Store satisfies it.
type Store interface {
	Append(ctx context.Context, r rawrecord.Record) (bool, []store.Seal, error)
	Flush(ctx context.Context) ([]store.Seal, error)
	NoteHealth(data []byte) error
	Health() string
	Close(ctx context.Context) ([]store.Seal, error)
}

// maxLinkEvents bounds connection events between two ticks; more are counted, not kept.
const maxLinkEvents = 16

// linkEvent is one connection or EOF as the reader saw it.
type linkEvent struct {
	connected bool
	pid       int
	cause     string
}

// Links tracks Laurel's connections as the reader sees them, for the writer's health records; every
// change is kept until the writer takes it, so two changes between ticks are both recorded.
type Links struct {
	mu        sync.Mutex
	events    []linkEvent
	dropped   int
	connected bool
	started   bool
	lastPID   int
}

// Connected records a new connection from pid: the collector's first, a restarted Laurel (another pid)
// or a reconnect (the same pid, which a SIGHUP re-exec also is) (ADR 0017, point 4).
func (l *Links) Connected(pid int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cause := "reconnect"
	switch {
	case !l.started:
		cause = "collector-start"
	case pid != l.lastPID:
		cause = "laurel-restart"
	}
	l.started, l.connected, l.lastPID = true, true, pid
	l.add(linkEvent{connected: true, pid: pid, cause: cause})
}

// Disconnected records EOF on the connection being read.
func (l *Links) Disconnected() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.connected = false
	l.add(linkEvent{pid: l.lastPID, cause: "eof"})
}

func (l *Links) add(e linkEvent) {
	if len(l.events) == maxLinkEvents {
		l.dropped++
		return
	}
	l.events = append(l.events, e)
}

// take returns the events since the last take, how many did not fit, and whether a connection is open.
func (l *Links) take() ([]linkEvent, int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev, dropped := l.events, l.dropped
	l.events, l.dropped = nil, 0
	return ev, dropped, l.connected
}

// Writer owns the store (ADR 0013): it is the only goroutine that calls it. It appends what the reader
// queued, flushes on every tick, writes health and loss records, and keeps running while the store is
// down: the reader drains and counts, and the store is opened again every ReopenEvery.
type Writer struct {
	Queue    *Queue
	Losses   *Losses
	Refusals *Refusals
	Reader   *Reader
	Links    *Links
	Canary   *Canary
	Open     func(ctx context.Context) (Store, error)
	Now      func() time.Time
	Notify   func(state string) error // sd_notify; the tick feeds the watchdog
	Log      *slog.Logger
	Started  map[string]string // version, boot id, rule version for the started record

	st          Store
	down        string // why the store is not open; "" while it is
	opened      chan openResult
	opening     bool
	cancelOpen  context.CancelFunc
	nextOpen    time.Time
	uncommitted uint64 // records appended since the last commit, lost at most if a call fails
	oldest      int64  // receive time of the oldest uncommitted record
	pending     map[Stage]Loss
	maxLag      time.Duration
	lastStats   time.Time
	lastJournal time.Time
	lastRound   time.Time
	connectedAt time.Time // when the connection being read began; zero while none is
	health      string
	notes       [][]byte
	lostNotes   uint64
}

type openResult struct {
	st  Store
	err error
}

// Run writes until stop is closed, which the owner does after the reader returned, then stores what is
// left and closes the store. tick drives every periodic step.
func (w *Writer) Run(ctx context.Context, tick <-chan time.Time, stop <-chan struct{}) error {
	w.pending, w.down, w.opened = map[Stage]Loss{}, "starting", make(chan openResult, 1)
	now := w.Now()
	w.lastStats, w.lastJournal, w.lastRound, w.health = now, now, now, "UNKNOWN starting"
	w.note(map[string]any{"kind": "started", "info": w.Started})
	w.startOpen(ctx)
	for {
		select {
		case <-tick:
			w.step(ctx)
		case <-w.Queue.Ready():
			w.appendQueued(ctx)
		case r := <-w.opened:
			w.openDone(r)
		case <-stop:
			return w.shutdown(ctx)
		}
	}
}

// startOpen opens the store in a goroutine the writer owns, so a long recovery does not stop its tick.
func (w *Writer) startOpen(ctx context.Context) {
	w.nextOpen, w.opening = time.Time{}, true
	ctx, w.cancelOpen = context.WithCancel(ctx)
	go func() {
		st, err := w.Open(ctx)
		if err == nil && st.Health() != "" {
			_, cerr := st.Close(context.WithoutCancel(ctx))
			err = errors.Join(fmt.Errorf("collector: store opened UNKNOWN: %s", st.Health()), cerr)
			st = nil
		}
		w.opened <- openResult{st, err}
	}()
}

func (w *Writer) openDone(r openResult) {
	w.opening = false
	w.cancelOpen()
	if r.err != nil {
		w.Log.Error("store open failed", "err", r.err)
		w.down, w.nextOpen = "store-open", w.Now().Add(ReopenEvery)
		return
	}
	w.st, w.down = r.st, ""
	w.Log.Info("store open")
}

// step is one tick: append, flush, probe, health, stats, watchdog.
func (w *Writer) step(ctx context.Context) {
	now := w.Now()
	w.appendQueued(ctx)
	w.flush(ctx, now)
	w.connections(now, true)
	w.canary(now)
	w.losses()
	if now.Sub(w.lastStats) >= statsEvery {
		w.stats(now)
	}
	w.setHealth()
	w.writeNotes()
	if w.st == nil && now.Sub(w.lastJournal) >= time.Minute {
		w.lastJournal = now
		w.Log.Warn("store down, draining and counting", "reason", w.down, "lost", w.pending)
	}
	if w.st == nil && !w.opening && !now.Before(w.nextOpen) {
		w.startOpen(ctx)
	}
	if err := w.Notify("WATCHDOG=1"); err != nil {
		w.Log.Error("watchdog notify failed", "err", err)
	}
}

// appendQueued stores every queued record, or counts it lost while the store is down. Until the first
// Open returns, records wait in the queue, which drops and counts what does not fit (ADR 0016, point 5).
func (w *Writer) appendQueued(ctx context.Context) {
	if w.st == nil && w.down == "starting" {
		return
	}
	for _, r := range w.Queue.Drain() {
		if w.st == nil {
			w.Losses.Add(StageStore, r)
			continue
		}
		stored, sealed, err := w.st.Append(ctx, r)
		switch {
		case errors.Is(err, store.ErrRefused):
			w.Log.Error("record refused", "err", err)
			w.Losses.Add(StageFraming, r)
		case err != nil:
			w.Losses.Add(StageStore, r)
			w.fail(ctx, "store-append", err)
		case stored:
			if len(sealed) > 0 { // the seal committed every record before this one
				w.uncommitted = 0
			}
			if w.uncommitted == 0 {
				w.oldest = r.Received
			}
			w.uncommitted++
			w.Canary.Observe(r)
		}
	}
}

func (w *Writer) flush(ctx context.Context, now time.Time) {
	if w.st == nil {
		return
	}
	if _, err := w.st.Flush(ctx); err != nil {
		w.fail(ctx, "store-flush", err)
		return
	}
	if w.uncommitted > 0 {
		if lag := now.Sub(time.Unix(0, w.oldest)); lag > w.maxLag {
			w.maxLag = lag
			if lag > lagBudget {
				w.note(map[string]any{"kind": "lag", "lag_ms": lag.Milliseconds()})
			}
		}
	}
	w.uncommitted = 0
}

// fail counts what the store had not committed as lost at most, closes it and schedules a reopen.
func (w *Writer) fail(ctx context.Context, reason string, err error) {
	w.Log.Error("store failed", "reason", reason, "err", err)
	if w.uncommitted > 0 {
		w.addPending(StageStore, Loss{Count: w.uncommitted, FirstAt: w.oldest, LastAt: w.Now().UnixNano()})
	}
	w.uncommitted = 0
	if _, cerr := w.st.Close(context.WithoutCancel(ctx)); cerr != nil {
		w.Log.Error("store close failed", "err", cerr)
	}
	w.st, w.down, w.nextOpen = nil, reason, w.Now().Add(ReopenEvery)
}

// connections notes every connection change and, with probe, sends a probe over a new connection at once.
func (w *Writer) connections(now time.Time, probe bool) {
	events, dropped, connected := w.Links.take()
	for _, e := range events {
		w.note(map[string]any{"kind": "connection", "laurel_pid": e.pid, "cause": e.cause})
	}
	if dropped > 0 {
		w.note(map[string]any{"kind": "connection", "dropped_events": dropped})
	}
	switch {
	case !connected:
		w.connectedAt = time.Time{}
	case len(events) > 0: // a new connection: only a probe sent after it proves it
		w.connectedAt = now
		if probe {
			w.Canary.Probe(now, false)
			w.lastRound = now // the next round waits a full interval, or it would replace this probe
		}
	}
}

func (w *Writer) canary(now time.Time) {
	if err := w.Canary.Failure(); err != nil {
		w.Log.Error("canary probe failed", "err", err)
	}
	if now.Sub(w.lastRound) >= CanaryEvery {
		w.lastRound = now
		w.Canary.Probe(now, true)
	}
}

// losses moves the counted losses into pending and, while the store is up, into one record per stage.
func (w *Writer) losses() {
	for stage, l := range w.Losses.Take() {
		w.addPending(stage, l)
	}
	if w.st == nil {
		return
	}
	for stage, l := range w.pending {
		w.note(map[string]any{"kind": "lost", "stage": stage, "count": l.Count, "bytes": l.Bytes,
			"first_seq": l.FirstSeq, "last_seq": l.LastSeq, "first_at": l.FirstAt, "last_at": l.LastAt})
		delete(w.pending, stage)
	}
}

func (w *Writer) addPending(stage Stage, l Loss) {
	p, ok := w.pending[stage]
	if !ok {
		w.pending[stage] = l
		return
	}
	p.Count += l.Count
	p.Bytes += l.Bytes
	p.LastSeq, p.LastAt = l.LastSeq, l.LastAt
	w.pending[stage] = p
}

func (w *Writer) stats(now time.Time) {
	w.lastStats = now
	c := w.Reader.Counts()
	w.note(map[string]any{"kind": "stats", "records": c.Records, "bytes": c.Bytes, "truncated": c.Truncated,
		"malformed": c.Malformed, "queue_high_water": w.Queue.HighWater(), "max_lag_ms": w.maxLag.Milliseconds()})
	w.maxLag = 0
	if r := w.Refusals.Take(); r.Count > 0 {
		w.note(map[string]any{"kind": "refused", "count": r.Count, "first_at": r.First, "last_at": r.Last,
			"last_uid": r.LastUID, "last_error": r.LastError})
	}
}

// setHealth is UNKNOWN until the store is open, Laurel connected, the probe over this connection stored
// and fewer than two probes missed; a change is a record (ADR 0017).
func (w *Writer) setHealth() {
	failing := w.Canary.Due(w.Now())
	h := "OK"
	switch {
	case w.st == nil:
		h = "UNKNOWN store: " + w.down
	case w.connectedAt.IsZero():
		h = "UNKNOWN laurel-disconnected"
	case failing:
		h = "UNKNOWN canary-missed"
	case !w.Canary.SeenSince(w.connectedAt):
		h = "UNKNOWN canary-pending"
	}
	if h != w.health {
		w.health = h
		w.note(map[string]any{"kind": "health", "state": h})
	}
}

// Health returns the state the latest tick computed.
func (w *Writer) Health() string { return w.health }

func (w *Writer) note(fields map[string]any) {
	fields["schema_version"] = healthSchema
	fields["at"] = w.Now().UnixNano()
	b, err := json.Marshal(fields)
	if err != nil {
		w.Log.Error("health record not encoded", "err", err)
		return
	}
	if len(w.notes) == maxNotes {
		w.notes, w.lostNotes = w.notes[1:], w.lostNotes+1
		w.Log.Warn("health record dropped while the store cannot take it", "dropped", w.lostNotes)
	}
	w.notes = append(w.notes, b)
}

// writeNotes hands health records to the store; the store keeps at most 64, so the rest wait.
func (w *Writer) writeNotes() {
	if w.st == nil {
		return
	}
	for len(w.notes) > 0 {
		if err := w.st.NoteHealth(w.notes[0]); err != nil {
			w.Log.Warn("health record waits", "err", err)
			return
		}
		w.notes = w.notes[1:]
	}
}

// shutdown stores what the reader left and closes the store; a store that cannot take it counts it.
func (w *Writer) shutdown(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	if w.opening {
		w.cancelOpen() // the open goroutine is the writer's: stop it and wait for it
		w.openDone(<-w.opened)
	}
	w.appendQueued(ctx)
	if w.st == nil {
		for _, r := range w.Queue.Drain() {
			w.Losses.Add(StageShutdown, r)
		}
		w.Log.Warn("stopped with the store down", "lost", w.Losses.Take(), "pending", w.pending)
		return nil
	}
	w.connections(w.Now(), false)
	w.losses()
	w.note(map[string]any{"kind": "stopping"})
	w.writeNotes()
	if _, err := w.st.Close(ctx); err != nil {
		return fmt.Errorf("collector: close store: %w", err)
	}
	return nil
}
