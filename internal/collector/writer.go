package collector

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
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
	lagBudget = time.Second
	// appendBudget bounds one run of appends, so a due tick, which flushes and feeds the watchdog,
	// waits for at most one run however large a burst (ADR 0017, point 6).
	appendBudget = store.FlushEvery / 2
	healthSchema = 1
	// maxNotes bounds health records waiting for the store: those handed over but not committed (the
	// store queues at most 64) and as many again; older ones give way and are counted, except loss and
	// summary records, of which at most one per stage or kind waits.
	maxNotes = 128
)

// Store is what the writer needs of the store; *store.Store satisfies it.
type Store interface {
	Append(ctx context.Context, r rawrecord.Record) (bool, []store.Seal, error)
	Flush(ctx context.Context) ([]store.Seal, error)
	NoteHealth(data []byte) error
	Health() string
	Close(ctx context.Context) ([]store.Seal, error)
	Committed() uint64
	Leaves(ctx context.Context, after uint64, max int, budget int64) ([]shard.Leaf, []store.Seal, error)
	Seals() []store.Seal
	MarkCosigned(first, last uint64, sum [32]byte, at time.Time) error
	Expire(latest time.Time, minAge time.Duration) (*store.Seal, error)
}

// maxLinkPIDs bounds the distinct pids kept per cause until a summary record takes the counts; the
// events of further pids are counted in pidsDropped.
const maxLinkPIDs = 16

// linkCounts counts connection events per cause and per pid (ADR 0017, point 4) until a summary
// record takes them, so a flood or a long store outage is counted whole in bounded memory.
type linkCounts struct {
	count           uint64
	firstAt, lastAt int64 // the ticks that first and last saw an event
	causes          map[string]uint64
	pids            map[string]map[int]uint64
	pidsDropped     uint64
	lastPID         int
	lastCause       string
}

func (c *linkCounts) add(cause string, pid int) {
	if c.causes == nil {
		c.causes, c.pids = map[string]uint64{}, map[string]map[int]uint64{}
	}
	c.count++
	c.causes[cause]++
	c.lastPID, c.lastCause = pid, cause
	m := c.pids[cause]
	if m == nil {
		m = map[int]uint64{}
		c.pids[cause] = m
	}
	if _, ok := m[pid]; ok || len(m) < maxLinkPIDs {
		m[pid]++
		return
	}
	c.pidsDropped++
}

// Links tracks Laurel's connections as the reader sees them, for the writer's health records: it counts
// every change until a summary record takes the counts, and says each tick whether one happened.
type Links struct {
	mu        sync.Mutex
	counts    linkCounts
	changed   bool // since the last check
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
	l.started, l.connected, l.lastPID, l.changed = true, true, pid, true
	l.counts.add(cause, pid)
}

// Disconnected records the end of the connection being read: EOF, or the read error that ended it.
func (l *Links) Disconnected(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cause := "eof"
	if err != nil {
		cause = "read-error"
	}
	l.connected, l.changed = false, true
	l.counts.add(cause, l.lastPID)
}

// check reports whether a connection changed since the last check, which at marks, and whether one is open.
func (l *Links) check(at time.Time) (bool, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	changed := l.changed
	if changed && l.counts.count > 0 { // a take since then left nothing to mark
		l.mark(at)
	}
	l.changed = false
	return changed, l.connected
}

func (l *Links) mark(at time.Time) {
	if l.counts.firstAt == 0 {
		l.counts.firstAt = at.UnixNano()
	}
	l.counts.lastAt = at.UnixNano()
}

// waiting returns how many events the counts hold.
func (l *Links) waiting() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts.count
}

// take returns the counts for a summary record at and starts them afresh.
func (l *Links) take(at time.Time) linkCounts {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.changed { // events after the last check, which still gets to probe for them
		l.mark(at)
	}
	c := l.counts
	l.counts = linkCounts{}
	return c
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
	Notify   func(state string) error // sd_notify; the tick and each run at stop feed the watchdog
	Log      *slog.Logger
	Started  map[string]string // version, boot id, rule version for the started record
	// LogCommits journals each new Committed of the store: the range reads it as the barrier and
	// the last durable seq (ADR 0022). Off on the host.
	LogCommits bool
	// Ledger takes the stream of committed records and health (ADR 0027); nil without a ledger.
	Ledger *Ledger
	// Cosign verifies the ledger's cosigned frames; nil retires nothing (ADR 0029).
	Cosign *cosign.Keys
	// Retention is raw_retention_days: how far both clocks must be past a shard's seal.
	Retention time.Duration

	st          Store
	down        string // why the store is not open; "" while it is
	opened      chan openResult
	opening     bool
	todo        []rawrecord.Record // taken from the queue, not yet appended; non-empty only once the first Open returned
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
	probeWanted bool      // the probe of a new store or connection was dropped; the next tick sends it
	health      string
	notes       []note // health records waiting to be handed to the store
	inflight    []note // handed to the store, not yet committed: sent again if the store fails
	capped      Loss   // dropped at the cap by the store, its loss record not yet committed
	noteSeq     uint64 // numbers every health record, so one sent twice after a failure is seen as one
	// lost counts records the collector counted lost since start (ADR 0016), including cap drops whose
	// store loss record a failed Close lost; cap drops the store committed are only in its own loss records.
	lost          uint64
	lostNotes     uint64 // health records given way in the queue or too large for the store, since start
	journaledLost uint64 // lostNotes when the journal last said so
	noteErr       error  // why the store last refused a health record, for the journal
	refuse        tally  // refusals not yet in a summary record
	loggedCommit  uint64 // the Committed last journaled
	ledgerState
}

// ledgerState is the writer's side of the stream to the ledger (ADR 0027).
type ledgerState struct {
	epoch        uint64      // the ledger connection the stream belongs to; 0 before the first
	hello        *link.Hello // the ledger's resume point, until checked against the store
	sent         uint64      // the last seq handed to the ledger
	sealSent     uint64      // the last seq of the last seal handed to the ledger
	stopped      string      // why the stream stopped for good (R6), or ""
	healthSent   string
	unstoredSent uint64
	healthAt     time.Time
	leavesErr    string      // the last error reading leaves, journaled once
	checkRoot    *entry.Root // the root of the ledger's last batch while it is read back, over ticks
	checkAt      uint64      // the last seq added to checkRoot
	cosignAt     time.Time   // the witness's time of the last cosigned frame taken
	cosignErr    string      // why the last cosigned frame was not taken, journaled once
}

// note is an encoded health record. Loss and summary records never give way in the queue; n is what
// they count (losses or events) and l the loss of a loss record, which the journal reports instead.
type note struct {
	b     []byte
	kind  string
	stage Stage
	l     Loss
	n     uint64
}

func (n note) keep() bool { return n.kind == "lost" || n.kind == "connection" || n.kind == "refused" }

// tally sums refusals into one summary record per tick, so a flood or a long store outage costs one
// record and none has to give way.
type tally struct {
	count           uint64
	causes          map[string]uint64
	firstAt, lastAt int64
	last            map[string]any // the newest uid and error
}

func (t *tally) add(n uint64, causes map[string]uint64, first, last int64, fields map[string]any) {
	if t.count == 0 {
		t.firstAt, t.causes = first, map[string]uint64{}
	}
	for cause, c := range causes {
		t.causes[cause] += c
	}
	t.count, t.lastAt, t.last = t.count+n, last, fields
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
	// First stop, which comes after the reader returned (shutdown stores the rest in runs), then a due
	// tick, then the rest of a burst one run at a time, so neither waits behind appends. A store that
	// opened goes in before the next record a run takes (appendQueued), so a burst does not hold it off.
	for {
		select {
		case <-stop:
			return w.shutdown(ctx)
		default:
		}
		select {
		case <-tick:
			w.step(ctx)
			continue
		default:
		}
		if len(w.todo) > 0 {
			w.appendQueued(ctx)
			continue
		}
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
	w.probe(w.openedAt)
}

// probe sends the probe a new store or connection needs. Canary.Probe drops it while another probe's
// syscall still runs; it then goes out on a later tick (probeWanted), not only with the next round.
func (w *Writer) probe(at time.Time) {
	w.probeWanted = !w.Canary.Probe(at, false)
	if !w.probeWanted {
		w.lastRound = at // the next round waits a full interval, or it would replace this probe
	}
}

// step is one tick: append, flush, probe, health, stats, watchdog.
func (w *Writer) step(ctx context.Context) {
	now := w.Now()
	w.appendQueued(ctx)
	w.flush(ctx)
	w.connections(w.Now()) // after the appends, which can open the store and send its probe
	w.canary(now)
	w.losses(false)
	if now.Sub(w.lastStats) >= statsEvery {
		w.stats(now)
	}
	w.summaries(false)
	w.setHealth()
	w.writeNotes()
	w.stream(ctx)
	// While the store is down, the journal is where losses leave the collector (ADR 0017, point 7).
	if (w.st == nil || len(w.notes) > 0 || w.lostNotes != w.journaledLost) && now.Sub(w.lastJournal) >= time.Minute {
		counts, losses := w.backlog(slices.Concat(w.inflight, w.notes))
		w.Log.Warn("health records wait for the store, counting", "store_down", w.down, "lost", w.pending,
			"lost_waiting", losses, "waiting", counts, "health_given_way", w.lostNotes, "refused_by_store", w.noteErr)
		w.lastJournal, w.journaledLost, w.noteErr = now, w.lostNotes, nil
	}
	if w.st == nil && !w.opening && !now.Before(w.nextOpen) {
		w.startOpen(ctx)
	}
	w.feedWatchdog()
}

// appendQueued stores queued records, or counts them lost while the store is down, for one run of
// appendBudget; at least one record per call, so a backlog always shrinks. It reports whether it took any.
// Until the first Open returns, records wait in the queue, which drops and counts what does not fit
// (ADR 0016, point 5). A store that opened goes in before the next record is taken, so a flood that
// keeps the writer from its select does not count records lost beside a usable store.
func (w *Writer) appendQueued(ctx context.Context) bool {
	start := w.Now()
	for took := false; ; took = true {
		if w.opening {
			select {
			case r := <-w.opened:
				w.openDone(r)
			default:
			}
		}
		if len(w.todo) == 0 {
			if w.st == nil && w.down == "starting" {
				return took
			}
			if w.todo = w.Queue.Drain(); len(w.todo) == 0 {
				return took
			}
		}
		r := w.todo[0]
		w.todo[0] = rawrecord.Record{} // an appended record is freed now, not with the whole burst
		w.todo = w.todo[1:]
		w.appendOne(ctx, r)
		if w.Now().Sub(start) >= appendBudget {
			return true
		}
	}
}

// feedWatchdog tells systemd the writer is making progress (ADR 0017, point 6).
func (w *Writer) feedWatchdog() {
	if err := w.Notify("WATCHDOG=1"); err != nil {
		w.Log.Error("watchdog notify failed", "err", err)
	}
}

// appendOne stores r, or counts it lost while the store is down.
func (w *Writer) appendOne(ctx context.Context, r rawrecord.Record) {
	if w.st == nil {
		w.Losses.Add(StageStore, r)
		return
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

func (w *Writer) flush(ctx context.Context) {
	if w.st == nil {
		return
	}
	sealed, err := w.st.Flush(ctx)
	if len(sealed) > 0 || err == nil {
		w.committed() // a seal on the way committed what was handed over, even if Flush then failed
	}
	if err != nil {
		w.fail(ctx, "store-flush", err) // journals what its Close committed
		return
	}
	w.logCommitted()
}

// committed is called once the store committed everything handed to it: the records, the health
// records and its own cap loss record. It measures the lag from handover to this commit.
func (w *Writer) committed() {
	if w.batch.Count > 0 {
		if lag := w.Now().Sub(time.Unix(0, w.batch.FirstAt)); lag > w.maxLag {
			w.maxLag = lag
			if lag > lagBudget {
				w.note(map[string]any{"kind": "lag", "lag_ms": lag.Milliseconds()})
			}
		}
	}
	w.batch, w.capped, w.inflight = Loss{}, Loss{}, nil
}

// logCommitted journals the store's Committed when LogCommits is on and it changed. It runs after
// each Flush and after the Close of a failed store, only once the call returned, so the line never
// runs ahead of the disk. The Close at stop is not journaled: the range reads that seal itself.
func (w *Writer) logCommitted() {
	if !w.LogCommits {
		return
	}
	if n := w.st.Committed(); n != w.loggedCommit {
		w.loggedCommit = n
		w.Log.Info("committed through", "seq", n)
	}
}

// fail counts what the store had not committed as lost at most, closes it and schedules a reopen.
func (w *Writer) fail(ctx context.Context, reason string, err error) {
	w.Log.Error("store failed", "reason", reason, "err", err)
	// Close commits what the store held, or fails saying it is lost (store.Close): only then is it
	// counted and handed to the next store, so nothing committed is counted twice.
	sealed, cerr := w.st.Close(context.WithoutCancel(ctx))
	w.logCommitted()
	if cerr == nil {
		w.committed()
	} else {
		// A seal that comes with the error holds every record; drops at the cap after the last record and
		// the health records may be missing from it, so they count as lost at most and are sent again.
		w.Log.Error("store close failed", "err", cerr)
		if len(sealed) == 0 && w.batch.Count > 0 {
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

// connections follows the connection state, checked at at, and sends a probe over a new connection at
// once, or the probe a store or connection still waits for.
func (w *Writer) connections(at time.Time) {
	changed, connected := w.Links.check(at)
	switch {
	case !connected:
		w.connectedAt = time.Time{}
	case changed: // a new connection, dated from its check: only a probe sent after it proves it
		w.connectedAt, w.probeWanted = at, true
	}
	if w.probeWanted {
		w.probe(at)
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
		if n, ok := w.encode(map[string]any{"kind": "lost", "stage": stage, "count": l.Count, "bytes": l.Bytes,
			"first_seq": l.FirstSeq, "last_seq": l.LastSeq, "first_at": l.FirstAt, "last_at": l.LastAt}); ok {
			n.l = l
			w.requeue(nil, n)
		}
		delete(w.pending, stage)
	}
}

// lossWaiting reports whether a loss record is waiting for the store. One handed over is committed or
// back among the notes by now: the tick's flush comes first.
func (w *Writer) lossWaiting() bool {
	return slices.ContainsFunc(w.notes, func(n note) bool { return n.kind == "lost" })
}

// summaries turns the connection counts and the refusal tally into one summary record each while the
// store is up and no earlier one of its kind waits for its commit. One that waits is sent again
// unchanged, never merged, so its note_seq stays the one it may already be stored under; the counts
// keep adding up meanwhile. At stop each gets its record.
func (w *Writer) summaries(stop bool) {
	// One handed over is committed or back among the notes by now: the tick's flush comes first.
	free := func(kind string) bool {
		return w.st != nil && (stop || !slices.ContainsFunc(w.notes, func(n note) bool { return n.kind == kind }))
	}
	if w.Links.waiting() > 0 && free("connection") {
		c := w.Links.take(w.Now())
		w.note(map[string]any{"kind": "connection", "count": c.count, "first_at": c.firstAt, "last_at": c.lastAt,
			"causes": c.causes, "pids": c.pids, "pids_dropped": c.pidsDropped, "laurel_pid": c.lastPID, "cause": c.lastCause})
	}
	if t := w.refuse; t.count > 0 && free("refused") {
		f := map[string]any{"kind": "refused", "socket": socketName, "count": t.count, "causes": t.causes,
			"first_at": t.firstAt, "last_at": t.lastAt, "rule_version": w.Started["rule_version"]}
		maps.Copy(f, t.last)
		w.note(f)
		w.refuse = tally{}
	}
}

// backlog is what has not reached the store, for the journal, which never gets a record itself: per
// kind the events not yet in a summary plus those in summaries among notes, one per other record, and
// per stage the loss of every loss record among notes (ADR 0017, point 7).
func (w *Writer) backlog(notes []note) (map[string]uint64, map[Stage][]Loss) {
	counts, losses := map[string]uint64{}, map[Stage][]Loss{}
	if n := w.Links.waiting(); n > 0 {
		counts["connection"] = n
	}
	if w.refuse.count > 0 {
		counts["refused"] = w.refuse.count
	}
	for _, n := range notes {
		if n.kind == "lost" {
			losses[n.stage] = append(losses[n.stage], n.l)
			continue
		}
		counts[n.kind] += n.n
	}
	return counts, losses
}

func (w *Writer) addPending(stage Stage, l Loss) {
	w.lost += l.Count
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
		"malformed": c.Malformed, "lost": w.lost, "lost_health": w.lostNotes, "queue_high_water": w.Queue.HighWater(),
		"max_lag_ms": w.maxLag.Milliseconds()})
	w.maxLag = 0
	w.refusals()
}

// refusals moves the acceptor's count into the writer's tally, for the next summary record.
func (w *Writer) refusals() {
	if r := w.Refusals.Take(); r.Count > 0 {
		if r.LastError == "" && w.refuse.last != nil { // the acceptor's error is per Take, the tally's since its record
			r.LastError, _ = w.refuse.last["last_error"].(string)
		}
		w.refuse.add(r.Count, r.Causes, r.First, r.Last, map[string]any{"last_uid": r.LastUID, "last_error": r.LastError})
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
	case w.streamFault(): // last: every other reason stays recorded as it changes (ADR 0017, point 5)
		h = streamUnknown
	}
	if h != w.health {
		w.health = h
		w.note(map[string]any{"kind": "health", "state": h})
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

func (w *Writer) note(fields map[string]any) {
	if n, ok := w.encode(fields); ok {
		w.requeue(nil, n)
	}
}

// encode numbers and encodes a health record; one the store would refuse is counted instead.
func (w *Writer) encode(fields map[string]any) (note, bool) {
	w.noteSeq++
	fields["schema_version"] = healthSchema
	fields["at"] = w.Now().UnixNano()
	fields["note_seq"] = w.noteSeq
	b, err := json.Marshal(fields)
	kind, _ := fields["kind"].(string)
	if err != nil {
		w.Log.Error("health record not encoded", "kind", kind, "err", err)
		return note{}, false
	}
	if len(b) > store.MaxHealthBytes { // the store refuses it: waiting would block every record after it
		w.lostNotes++
		w.Log.Error("health record too large for the store", "kind", kind, "bytes", len(b))
		return note{}, false
	}
	n := note{b: b, kind: kind, n: 1}
	n.stage, _ = fields["stage"].(Stage)
	if c, ok := fields["count"].(uint64); ok {
		n.n = c
	}
	return n, true
}

// requeue puts health records back ahead of those waiting, oldest first, and then appends more; past
// maxNotes the oldest give way, counted. Loss and summary records give way only to each other, and
// losses and summaries keep them from filling the queue.
func (w *Writer) requeue(first []note, more ...note) {
	w.notes = append(append(append([]note(nil), first...), w.notes...), more...)
	over := len(w.notes) - maxNotes
	if over <= 0 {
		return
	}
	w.lostNotes += uint64(over)
	keep := w.notes[:0]
	for _, n := range w.notes {
		if over > 0 && !n.keep() {
			over--
			continue
		}
		keep = append(keep, n)
	}
	w.notes = keep[over:]
}

// writeNotes hands health records to the store; the store keeps at most 64, so the rest wait, which the
// journal says once a minute (step).
func (w *Writer) writeNotes() {
	if w.st == nil {
		return
	}
	for len(w.notes) > 0 {
		if err := w.st.NoteHealth(w.notes[0].b); err != nil {
			w.noteErr = err
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
	up := w.st != nil
	// The rest of a burst, then what the reader left, in runs with a commit and the watchdog between
	// them as while running: after the acceptor failed, systemd still holds the watchdog armed.
	for w.appendQueued(ctx) {
		w.flush(ctx)
		w.feedWatchdog()
	}
	w.refusals()
	w.flush(ctx) // the store's own health queue drains, so the last hand-over fits in it
	if w.st == nil {
		for _, r := range w.Queue.Drain() {
			w.Losses.Add(StageShutdown, r)
		}
		counts, losses := w.backlog(w.notes)
		w.Log.Warn("stopped with the store down", "lost", w.Losses.Take(), "pending", w.pending,
			"lost_not_stored", losses, "not_stored", counts)
		if up {
			return errors.New("collector: the store failed at stop")
		}
		return nil
	}
	w.losses(true)
	w.summaries(true)
	w.note(map[string]any{"kind": "stopping"})
	// The store takes a bounded number of health records and this is the last hand-over: loss records go
	// first, then summaries, so a backlog gives way in the journal rather than a loss. Each keeps its note_seq.
	rank := func(n note) int {
		switch {
		case n.kind == "lost":
			return 0
		case n.keep():
			return 1
		}
		return 2
	}
	slices.SortStableFunc(w.notes, func(a, b note) int { return cmp.Compare(rank(a), rank(b)) })
	w.writeNotes()
	if len(w.notes) > 0 {
		counts, losses := w.backlog(w.notes)
		w.Log.Warn("health records not stored at stop", "lost_not_stored", losses, "not_stored", counts)
	}
	// The flush above committed every record and cap drop: only the health records handed over since may be lost.
	if _, err := w.st.Close(ctx); err != nil {
		counts, losses := w.backlog(w.inflight)
		w.Log.Error("store close failed at stop: these may be lost", "lost_records", losses, "health_records", counts, "err", err)
		return fmt.Errorf("collector: close store: %w", err)
	}
	return nil
}
