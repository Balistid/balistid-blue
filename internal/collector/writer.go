package collector

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
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
	// StageCap counts records the store dropped at its cap whose own loss record it had not committed
	// when it failed; once committed, the store's record counts them.
	StageCap Stage = "cap"

	// ReopenEvery is how long the writer waits before opening a failed store again.
	ReopenEvery = 30 * time.Second
	// statsEvery is how often stats and the refusal summary are stored (refusal_summary_s).
	statsEvery = time.Minute
	// lagBudget is the longest handover-to-commit time before it is a health event (crash_loss_ms).
	lagBudget    = time.Second
	healthSchema = 1
	// maxNotes bounds health records waiting for the store: those handed over but not committed (the
	// store queues at most 64) and as many again; older ones give way and are counted.
	maxNotes = 128
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
	dropped   uint64
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
func (l *Links) take() ([]linkEvent, uint64, bool) {
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
	batch       Loss      // records appended since the last commit, lost at most if a store call fails
	openedAt    time.Time // when the store last opened; only a probe sent after it proves the new store
	pending     map[Stage]Loss
	maxLag      time.Duration
	lastStats   time.Time
	lastJournal time.Time
	lastRound   time.Time
	connectedAt time.Time // when the connection being read began; zero while none is
	health      string
	notes       []note // health records waiting to be handed to the store
	inflight    []note // handed to the store, not yet committed: sent again if the store fails
	capped      Loss   // dropped at the cap by the store, its loss record not yet committed
	noteSeq     uint64 // numbers every health record, so one sent twice after a failure is seen as one
	// lost counts records the collector counted lost since start (ADR 0016), including cap drops whose
	// store loss record a failed Close lost; cap drops the store committed are only in its own loss records.
	lost        uint64
	lostNotes   uint64             // health records given way in the queue since start
	loggedNotes uint64             // lostNotes as the journal last saw it
	gave        map[string]gaveWay // connection and refused records given way, not yet in a gave_way record
}

// note is an encoded health record and what the writer needs of it later, so it never decodes one. In a
// full queue "lost" and "gave_way" records give way last and "connection" and "refused" records before
// them (a reconnect is a loss the collector cannot count, T25; a refusal names the peer, T2), into one
// gave_way record per kind.
type note struct {
	b     []byte
	kind  string
	of    string // the kind a gave_way record sums
	stage Stage  // a lost record's stage and loss, for the journal
	lost  Loss
	part  gaveWay // what a connection or refused record adds to its kind's gave_way record
}

// gaveWay sums connection or refused records that gave way in the queue: count is connection events or
// refusals, and the latest of them names its pid and cause, or the uid.
type gaveWay struct {
	count           uint64
	firstAt, lastAt int64
	pid             int
	cause           string
	uid             int
}

// rank is the order in which notes give way in a full queue: lowest first.
func (n note) rank() int {
	switch n.kind {
	case "lost", "gave_way":
		return 2
	case "connection", "refused":
		return 1
	}
	return 0
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
	w.note(note{kind: "started"}, map[string]any{"info": w.Started})
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
	w.st, w.down, w.openedAt = r.st, "", w.Now()
	w.Log.Info("store open")
	w.Canary.Probe(w.openedAt, false)
	w.lastRound = w.openedAt
}

// step is one tick: append, flush, probe, health, stats, watchdog.
func (w *Writer) step(ctx context.Context) {
	now := w.Now()
	w.appendQueued(ctx)
	w.flush(ctx)
	w.connections(now, true)
	w.canary(now)
	w.losses(false)
	if now.Sub(w.lastStats) >= statsEvery {
		w.stats(now)
	}
	w.setHealth()
	w.writeNotes()
	w.gaveWayNotes(false)
	if w.st == nil && now.Sub(w.lastJournal) >= time.Minute {
		w.lastJournal = now
		w.Log.Warn("store down, draining and counting", append([]any{"reason", w.down, "lost", w.pending}, w.waiting()...)...)
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
			if len(sealed) > 0 { // the seal before the failure committed what came before
				w.committed()
			}
			w.Losses.Add(StageStore, r)
			w.fail(ctx, "store-append", err)
		case !stored:
			w.capped.add(r)
		default:
			if len(sealed) > 0 { // the seal committed everything handed over before this record
				w.committed()
			}
			w.batch.add(r)
			w.Canary.Observe(r, w.Now())
		}
	}
}

func (w *Writer) flush(ctx context.Context) {
	if w.st == nil {
		return
	}
	sealed, err := w.st.Flush(ctx)
	if len(sealed) > 0 || err == nil {
		w.committed() // a seal on the way committed what was handed over, even if Flush then failed
	}
	if err != nil {
		w.fail(ctx, "store-flush", err)
	}
}

// committed is called once the store committed everything handed to it: the records, the health
// records and its own cap loss record.
func (w *Writer) committed() {
	w.recordsCommitted()
	w.capped, w.inflight = Loss{}, nil
}

// recordsCommitted is called once the store committed the records appended; it measures the lag from
// handover to this commit.
func (w *Writer) recordsCommitted() {
	if w.batch.Count > 0 {
		if lag := w.Now().Sub(time.Unix(0, w.batch.FirstAt)); lag > w.maxLag {
			w.maxLag = lag
			if lag > lagBudget {
				w.note(note{kind: "lag"}, map[string]any{"lag_ms": lag.Milliseconds()})
			}
		}
	}
	w.batch = Loss{}
}

// fail counts what the store had not committed as lost at most, closes it and schedules a reopen.
func (w *Writer) fail(ctx context.Context, reason string, err error) {
	w.Log.Error("store failed", "reason", reason, "err", err)
	// Close commits what the store held, or fails saying it is lost (store.Close): only then is it
	// counted and handed to the next store, so nothing committed is counted twice.
	sealed, cerr := w.st.Close(context.WithoutCancel(ctx))
	if cerr == nil {
		w.committed()
	} else {
		w.Log.Error("store close failed", "err", cerr)
		// A seal with the error still holds every record appended; the health records and the cap loss
		// record come from the flush that failed, so they are sent again or counted (note_seq tells).
		if len(sealed) > 0 {
			w.recordsCommitted()
		}
		if w.batch.Count > 0 {
			w.addPending(StageStore, w.batch)
		}
		if w.capped.Count > 0 {
			w.addPending(StageCap, w.capped)
		}
		w.requeue(w.inflight)
		w.batch, w.capped, w.inflight = Loss{}, Loss{}, nil
	}
	w.st, w.down, w.nextOpen = nil, reason, w.Now().Add(ReopenEvery)
}

// connections notes every connection change and, with probe, sends a probe over a new connection at once.
func (w *Writer) connections(now time.Time, probe bool) {
	events, dropped, connected := w.Links.take()
	at := now.UnixNano()
	for _, e := range events {
		w.note(note{kind: "connection", part: gaveWay{count: 1, firstAt: at, lastAt: at, pid: e.pid, cause: e.cause}},
			map[string]any{"laurel_pid": e.pid, "cause": e.cause})
	}
	if dropped > 0 {
		w.note(note{kind: "connection", part: gaveWay{count: dropped, firstAt: at, lastAt: at}},
			map[string]any{"dropped_events": dropped})
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
// While an earlier loss record waits for its commit, pending keeps adding up instead, so loss records
// in the queue stay a few and none ever has to give way (requeue). At stop every stage gets its record,
// since Close commits them all.
func (w *Writer) losses(stop bool) {
	for stage, l := range w.Losses.Take() {
		w.addPending(stage, l)
	}
	if w.st == nil || !stop && w.lossWaiting() {
		return
	}
	for stage, l := range w.pending {
		w.note(note{kind: "lost", stage: stage, lost: l}, map[string]any{"stage": stage, "count": l.Count,
			"bytes": l.Bytes, "first_seq": l.FirstSeq, "last_seq": l.LastSeq, "first_at": l.FirstAt, "last_at": l.LastAt})
		delete(w.pending, stage)
	}
}

// lossWaiting reports whether a loss record is waiting for the store. One handed over is committed or
// back among the notes by now: the tick's flush comes first.
func (w *Writer) lossWaiting() bool {
	return slices.ContainsFunc(w.notes, func(n note) bool { return n.kind == "lost" })
}

// gaveWayNotes turns what gave way of each kind into one gave_way record while the store is up and the
// queue has room, so the record itself makes nothing give way. Like losses, it waits while one of its kind
// waits, so they stay a few; at stop every kind gets its record.
func (w *Writer) gaveWayNotes(stop bool) {
	for _, of := range []string{"connection", "refused"} {
		a := w.gave[of]
		waiting := slices.ContainsFunc(w.notes, func(n note) bool { return n.kind == "gave_way" && n.of == of })
		if w.st == nil || a.count == 0 || len(w.notes) >= maxNotes || !stop && waiting {
			continue
		}
		delete(w.gave, of)
		fields := map[string]any{"of": of, "count": a.count, "first_at": a.firstAt, "last_at": a.lastAt}
		if of == "refused" {
			fields["last_uid"] = a.uid
		} else {
			fields["last_laurel_pid"], fields["last_cause"] = a.pid, a.cause
		}
		w.note(note{kind: "gave_way", of: of}, fields)
	}
}

// fold adds a connection or refused record that gave way to its kind's gave_way record.
func (w *Writer) fold(n note) {
	if w.gave == nil {
		w.gave = map[string]gaveWay{}
	}
	a, p := w.gave[n.kind], n.part
	if a.count == 0 || p.firstAt < a.firstAt {
		a.firstAt = p.firstAt
	}
	a.count += p.count
	if p.lastAt >= a.lastAt { // a record a failed Close handed back can give way after newer ones
		a.lastAt, a.uid = p.lastAt, p.uid
		if p.cause != "" {
			a.pid, a.cause = p.pid, p.cause
		}
	}
	w.gave[n.kind] = a
}

// waiting is what the journal says of the health records waiting for the store: counts, and the losses
// among them summed per stage, since a failed Close may have handed loss records back and while the store
// is down the journal is where they leave the collector (ADR 0017, point 7). It never carries a body.
func (w *Writer) waiting() []any {
	lost, conn := map[Stage]Loss{}, 0
	for _, n := range w.notes {
		switch n.kind {
		case "lost":
			l := lost[n.stage]
			l.merge(n.lost)
			lost[n.stage] = l
		case "connection", "refused":
			conn++
		}
	}
	gave := map[string]uint64{}
	for of, a := range w.gave {
		gave[of] = a.count
	}
	return []any{"lost_records_waiting", lost, "connection_records_waiting", conn,
		"health_records_waiting", len(w.notes), "health_records_dropped", w.lostNotes, "gave_way", gave}
}

func (w *Writer) addPending(stage Stage, l Loss) {
	w.lost += l.Count
	p := w.pending[stage]
	p.merge(l)
	w.pending[stage] = p
}

// merge adds l, a later loss of the same stage.
func (c *Loss) merge(l Loss) {
	if c.Count == 0 {
		*c = l
		return
	}
	c.Count += l.Count
	c.Bytes += l.Bytes
	c.LastSeq, c.LastAt = l.LastSeq, l.LastAt
}

func (w *Writer) stats(now time.Time) {
	w.lastStats = now
	c := w.Reader.Counts()
	w.note(note{kind: "stats"}, map[string]any{"records": c.Records, "bytes": c.Bytes, "truncated": c.Truncated,
		"malformed": c.Malformed, "lost": w.lost, "lost_health": w.lostNotes, "queue_high_water": w.Queue.HighWater(),
		"max_lag_ms": w.maxLag.Milliseconds()})
	w.maxLag = 0
	if r := w.Refusals.Take(); r.Count > 0 {
		w.note(note{kind: "refused", part: gaveWay{count: r.Count, firstAt: r.First, lastAt: r.Last, uid: r.LastUID}},
			map[string]any{"count": r.Count, "first_at": r.First, "last_at": r.Last, "last_uid": r.LastUID,
				"last_error": r.LastError})
	}
	if w.lostNotes > w.loggedNotes { // once a minute at most, however many gave way
		w.loggedNotes = w.lostNotes
		w.Log.Warn("health records dropped while the store cannot take them", w.waiting()...)
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
	case !w.Canary.SeenSince(later(w.connectedAt, w.openedAt)):
		h = "UNKNOWN canary-pending"
	}
	if h != w.health {
		w.health = h
		w.note(note{kind: "health"}, map[string]any{"state": h})
	}
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Health returns the state the latest tick computed.
func (w *Writer) Health() string { return w.health }

// note encodes n's record from fields, with n.kind and the fields every record has, and queues it.
func (w *Writer) note(n note, fields map[string]any) {
	w.noteSeq++
	if fields == nil {
		fields = map[string]any{}
	}
	fields["kind"] = n.kind
	fields["schema_version"] = healthSchema
	fields["at"] = w.Now().UnixNano()
	fields["note_seq"] = w.noteSeq
	b, err := json.Marshal(fields)
	if err != nil {
		w.Log.Error("health record not encoded", "kind", n.kind, "err", err)
		return
	}
	if len(b) > store.MaxHealthBytes { // the store would refuse it and every note queued behind it
		w.lostNotes++
		w.Log.Warn("health record too large for the store", "kind", n.kind, "bytes", len(b))
		if n.rank() == 1 {
			w.fold(n)
		}
		return
	}
	n.b = b
	w.requeue(nil, n)
}

// requeue puts health records back ahead of those waiting, oldest first, and then appends more; past
// maxNotes the oldest of the lowest rank give way and are counted, a connection or refused record into
// its kind's gave_way record. A rank 2 record gives way only to its rank, which never fills the queue.
func (w *Writer) requeue(first []note, more ...note) {
	w.notes = append(append(append([]note(nil), first...), w.notes...), more...)
	over := len(w.notes) - maxNotes
	if over <= 0 {
		return
	}
	w.lostNotes += uint64(over)
	for rank := 0; over > 0; rank++ {
		keep := w.notes[:0]
		for _, n := range w.notes {
			if over > 0 && n.rank() == rank {
				over--
				if rank == 1 {
					w.fold(n)
				}
				continue
			}
			keep = append(keep, n)
		}
		w.notes = keep
	}
}

// writeNotes hands health records to the store; the store keeps at most 64, so the rest wait.
func (w *Writer) writeNotes() {
	if w.st == nil {
		return
	}
	for len(w.notes) > 0 {
		if err := w.st.NoteHealth(w.notes[0].b); err != nil {
			w.Log.Warn("health record waits", "err", err)
			return
		}
		w.inflight = append(w.inflight, w.notes[0])
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
	w.connections(w.Now(), false) // a reconnect since the last tick is noted, the store up or down
	if w.st == nil {
		for _, r := range w.Queue.Drain() {
			w.Losses.Add(StageShutdown, r)
		}
		w.Log.Warn("stopped with the store down", append([]any{"lost", w.Losses.Take(), "pending", w.pending}, w.waiting()...)...)
		return nil
	}
	w.losses(true)
	w.note(note{kind: "stopping"}, nil)
	// The store takes a bounded number of health records per Flush: loss records go first, then connection
	// and refusal records, and every Flush makes room for more. Each record keeps its note_seq.
	slices.SortStableFunc(w.notes, func(a, b note) int { return cmp.Compare(b.rank(), a.rank()) })
	w.flush(ctx) // the store's own queue may be full of notes handed over earlier: commit them first
	for w.st != nil {
		w.gaveWayNotes(true)
		left := len(w.notes)
		w.writeNotes()
		if len(w.notes) == left { // all handed over, or the store takes no more
			break
		}
		w.flush(ctx)
	}
	if w.st == nil { // a flush failed and fail() closed the store, counting what it had not committed
		w.Log.Error("store failed at stop: these may be lost", append([]any{"pending", w.pending}, w.waiting()...)...)
		return fmt.Errorf("collector: store failed at stop: %s", w.down)
	}
	if len(w.notes) > 0 {
		w.Log.Warn("health records not stored at stop", w.waiting()...)
	}
	if sealed, err := w.st.Close(ctx); err != nil {
		if len(sealed) > 0 { // as in fail: the seal holds every record appended
			w.recordsCommitted()
		}
		w.Log.Error("store close failed at stop: these may be lost", "records", w.batch, "cap_dropped", w.capped,
			"health_records", len(w.inflight), "err", err)
		return fmt.Errorf("collector: close store: %w", err)
	}
	return nil
}
