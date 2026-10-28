package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

// fakeStore stands in for the store; its failures are switched by the test.
// Like the store, it keeps health records and its count of records dropped at the cap until a Flush
// commits them, and a failed Flush or Close loses what it held.
type fakeStore struct {
	mu                       sync.Mutex
	appended, committed      []rawrecord.Record
	queued, notes            []map[string]any
	dropped, droppedStored   int
	failAppend, failFlush    bool
	refuse, full, rejectNote bool
	failClose, sealNext      bool          // sealNext: the next Append seals, committing what came before
	commitThenFail           bool          // the next Flush commits, then fails; Close then has nothing left to lose
	sealThenFail             bool          // the next Append seals, committing what came before, then fails
	block                    chan struct{} // Append waits on it when set
	entered                  chan struct{} // Append signals it, if it has room, before it waits on block
	onAppend                 func()        // runs inside Append after block, as a slow insert would
	onFlush                  func()        // runs inside Flush, as a slow commit would
	noteCap                  int           // NoteHealth refuses past this many queued, as the store's 64; 0 is none
	flushErr                 bool          // Flush fails and keeps what it holds, for Close
	closeSealErr             bool          // the next Close commits what it holds, then fails with the seal
	closed                   int
}

func (s *fakeStore) Append(_ context.Context, r rawrecord.Record) (bool, []store.Seal, error) {
	s.mu.Lock()
	block, entered, onAppend := s.block, s.entered, s.onAppend
	s.mu.Unlock()
	select {
	case entered <- struct{}{}:
	default:
	}
	if block != nil {
		<-block
	}
	if onAppend != nil {
		onAppend()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.sealThenFail:
		s.sealThenFail = false
		s.commit()
		return false, []store.Seal{{Name: "00000000000000000001.db"}}, errors.New("disk gone after the seal")
	case s.failAppend:
		return false, nil, errors.New("disk gone")
	case s.refuse:
		return false, nil, fmt.Errorf("%w: test", store.ErrRefused)
	case s.full:
		s.dropped++
		return false, nil, nil
	}
	var sealed []store.Seal
	if s.sealNext {
		s.sealNext = false
		s.commit()
		sealed = []store.Seal{{Name: "00000000000000000001.db"}}
	}
	s.appended = append(s.appended, r)
	return true, sealed, nil
}

func (s *fakeStore) Flush(context.Context) ([]store.Seal, error) {
	s.mu.Lock()
	onFlush := s.onFlush
	s.mu.Unlock()
	if onFlush != nil {
		onFlush()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFlush {
		s.lose()
		return nil, errors.New("fsync failed")
	}
	if s.flushErr {
		return nil, errors.New("flush failed")
	}
	s.commit()
	if s.commitThenFail {
		s.commitThenFail = false
		return nil, errors.New("failed after the commit")
	}
	return nil, nil
}

// lose drops what a failed store held uncommitted.
func (s *fakeStore) lose() {
	s.appended, s.queued, s.dropped = nil, nil, 0
}

func (s *fakeStore) commit() {
	s.committed, s.appended = append(s.committed, s.appended...), nil
	s.notes, s.queued = append(s.notes, s.queued...), nil
	s.droppedStored, s.dropped = s.droppedStored+s.dropped, 0
}

func (s *fakeStore) NoteHealth(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rejectNote || s.noteCap > 0 && len(s.queued) >= s.noteCap || len(b) > store.MaxHealthBytes {
		return errors.New("64 health records queued or too large")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s.queued = append(s.queued, m)
	return nil
}

func (s *fakeStore) Health() string { return "" }

// The ledger stream is tested against a real store (ledger_test.go); the fake has nothing to read.
func (s *fakeStore) Leaves(context.Context, uint64, int, int64) ([]shard.Leaf, []store.Seal, error) {
	return nil, nil, nil
}

func (s *fakeStore) Seals() []store.Seal { return nil }

func (s *fakeStore) Committed() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.committed))
}

func (s *fakeStore) Close(context.Context) ([]store.Seal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	if s.failClose || s.failFlush {
		s.lose()
		return nil, errors.New("close failed")
	}
	s.commit()
	if s.closeSealErr {
		s.closeSealErr = false
		return []store.Seal{{Name: "00000000000000000002.db"}}, errors.New("sealed, but the flush before failed")
	}
	return nil, nil
}

func (s *fakeStore) set(f func(*fakeStore)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// kinds returns the health records of kind, in order.
func (s *fakeStore) kinds(kind string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, n := range s.notes {
		if n["kind"] == kind {
			out = append(out, n)
		}
	}
	return out
}

// snapshot is the writer's state as its own goroutine saw it when it fed the watchdog.
type snapshot struct {
	health  string
	opening bool
	up      bool
	pending map[Stage]Loss
	waiting int
}

// rig runs a writer on a fake clock; each step sends one tick and waits until the writer fed the
// watchdog, which ends every step and hands over a snapshot.
type rig struct {
	t       *testing.T
	w       *Writer
	st      *fakeStore
	opens   chan error // each Open takes one: nil opens st
	mu      sync.Mutex
	now     time.Time
	tick    chan time.Time
	fed     chan snapshot
	last    snapshot
	stop    chan struct{}
	done    chan error
	touched chan uint64
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, st: &fakeStore{}, opens: make(chan error, 8), now: time.Unix(0, noon),
		tick: make(chan time.Time), fed: make(chan snapshot, 1), stop: make(chan struct{}),
		done: make(chan error, 1), touched: make(chan uint64, 16)}
	loss := &Losses{}
	q := NewQueue(1<<20, loss)
	c, err := NewCanary(t.TempDir(), 1000, 4242)
	if err != nil {
		t.Fatal(err)
	}
	c.touch = func(_ string, n uint64) error { r.touched <- n; return nil }
	r.w = &Writer{
		Queue: q, Losses: loss, Refusals: &Refusals{}, Reader: NewReader(q, r.clock), Links: &Links{},
		Canary: c, Now: r.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Started: map[string]string{"version": "test", "rule_version": "test-rules"},
		Open: func(ctx context.Context) (Store, error) {
			select {
			case err := <-r.opens:
				if err != nil {
					return nil, err
				}
				return r.st, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		Notify: func(string) error {
			w := r.w
			snap := snapshot{health: w.health, opening: w.opening, up: w.st != nil, pending: map[Stage]Loss{}, waiting: len(w.notes)}
			for k, v := range w.pending {
				snap.pending[k] = v
			}
			select {
			case r.fed <- snap:
			default:
			}
			return nil
		},
	}
	return r
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = r.now.Add(d)
}

func (r *rig) start(openErr error) {
	r.opens <- openErr
	go func() { r.done <- r.w.Run(r.t.Context(), r.tick, r.stop) }()
	r.t.Cleanup(func() {
		select {
		case <-r.done:
		default:
			close(r.stop)
			<-r.done
		}
	})
}

// step advances the clock by d and runs one tick to its end.
func (r *rig) step(d time.Duration) {
	r.t.Helper()
	r.advance(d)
	select {
	case <-r.fed: // a snapshot nobody waited for
	default:
	}
	select {
	case r.tick <- r.clock():
	case <-time.After(5 * time.Second):
		r.t.Fatal("the writer did not take a tick")
	}
	select {
	case r.last = <-r.fed:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the writer did not finish its tick")
	}
}

// settle runs ticks until the writer has the store open, so the open goroutine's result is in.
func (r *rig) settle() {
	r.t.Helper()
	for range 200 {
		r.step(0)
		if !r.last.opening {
			r.step(0) // writes what waited for the store
			if r.last.up {
				select { // the probe a newly opened store sends, unless its syscall is stuck
				case <-r.touched:
					r.probeReturned()
				case <-time.After(200 * time.Millisecond):
				}
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	r.t.Fatal("the store never opened")
}

func (r *rig) push(lines ...string) {
	for _, l := range lines {
		rec, ok := (&line{buf: []byte(l), n: uint64(len(l))}).record(r.clock().UnixNano())
		if !ok {
			rec.ProviderSeq = 0
		}
		r.w.Queue.Push(rec)
	}
}

// canaryLine is the record Laurel would deliver for probe n of uid and pid.
func canaryLine(serial int, n uint64, uid, pid int) string {
	return fmt.Sprintf(`{"ID":"1.2:%d","SYSCALL":{"syscall":"openat","success":"yes","uid":%d,"pid":%d,"key":"%s"},`+
		`"PATH":[{"name":"/var/lib/balistid/canary/c-%d"}]}`, serial, uid, pid, CanaryKey, n)
}

func health(r *rig) string { return r.last.health }

// probed returns the number of the next probe the canary sent.
func probed(r *rig) uint64 {
	r.t.Helper()
	select {
	case n := <-r.touched:
		r.probeReturned()
		return n
	case <-time.After(5 * time.Second):
		r.t.Fatal("no probe sent")
		return 0
	}
}

// probeReturned waits until the probe goroutine that just reported its touch has returned. The touch
// seam reports before the goroutine gives back the canary's in-flight token, and until it does a new
// probe sends no syscall, so a test that goes on at once may miss its next probe.
func (r *rig) probeReturned() {
	r.t.Helper()
	until(r.t, func() bool { return len(r.w.Canary.inFlight) == 0 })
}

func TestStartedRecordAndStoreOpen(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	if got := r.st.kinds("started"); len(got) != 1 || got[0]["info"].(map[string]any)["version"] != "test" {
		t.Fatalf("started records %v", got)
	}
}

func TestFailingStoreCallCountsItsRecord(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.failAppend = true })
	r.push(event(5, ""))
	r.step(0)
	if !strings.HasPrefix(health(r), "UNKNOWN store") || r.st.closed != 1 {
		t.Fatalf("health %q, closed %d", health(r), r.st.closed)
	}
	if l := r.last.pending[StageStore]; l.Count != 1 || l.FirstSeq != 5 {
		t.Fatalf("pending loss %+v", r.last.pending)
	}
}

func TestFlushFailureCountsUncommittedBatch(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.push(event(1, ""))
	r.step(0) // committed
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.push(event(2, ""), event(3, ""))
	r.step(0)
	if l := r.last.pending[StageStore]; l.Count != 2 {
		t.Fatalf("lost %+v, want the two uncommitted records only", r.last.pending)
	}
	r.st.set(func(s *fakeStore) { s.failFlush = false; s.notes = nil })
	r.opens <- nil
	r.step(ReopenEvery)
	r.settle()
	r.step(0)
	lost := r.st.kinds("lost")
	if len(lost) != 1 || lost[0]["stage"] != "store" || lost[0]["count"] != 2.0 {
		t.Fatalf("lost records after reopen %v", lost)
	}
}

func TestRecordsWaitForTheFirstOpen(t *testing.T) {
	r := newRig(t)
	r.push(event(1, ""), event(2, ""))
	r.start(nil)
	r.settle()
	r.step(0)
	if n := len(r.st.committed); n != 2 || len(r.st.kinds("lost")) != 0 {
		t.Fatalf("committed %d of 2 records queued before the store opened", n)
	}
}

func TestStoreDownReaderKeepsDrainingAndReopens(t *testing.T) {
	r := newRig(t)
	r.start(errors.New("no disk"))
	r.settle()
	if !strings.HasPrefix(health(r), "UNKNOWN store") {
		t.Fatalf("health %q", health(r))
	}
	r.push(event(7, ""), event(8, ""))
	r.step(0)
	if q := r.w.Queue.Drain(); len(q) != 0 {
		t.Fatal("records stayed queued while the store was down")
	}
	r.step(ReopenEvery - time.Second)
	select {
	case r.opens <- nil:
	default:
		t.Fatal("open slot taken early")
	}
	r.step(time.Second)
	r.settle()
	r.step(0)
	lost := r.st.kinds("lost")
	if len(lost) != 1 || lost[0]["count"] != 2.0 || lost[0]["first_seq"] != 7.0 || lost[0]["last_seq"] != 8.0 {
		t.Fatalf("lost after reopen %v", lost)
	}
}

func TestRefusedRecordKeepsTheStore(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.refuse = true })
	r.push(event(9, ""))
	r.step(0)
	r.step(0) // commits the loss record handed over in the step before
	if r.st.closed != 0 || !r.last.up {
		t.Fatal("a refused record closed the store")
	}
	if lost := r.st.kinds("lost"); len(lost) != 1 || lost[0]["stage"] != "framing" {
		t.Fatalf("lost %v", lost)
	}
}

func TestHealthRecordWaitsWhileStoreRejectsIt(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	r.settle()
	if n := len(r.st.kinds("started")); n != 0 || r.last.waiting == 0 {
		t.Fatalf("started stored %d, waiting %d", n, r.last.waiting)
	}
	r.st.set(func(s *fakeStore) { s.rejectNote = false })
	r.step(0)
	r.step(0)
	if n := len(r.st.kinds("started")); n != 1 {
		t.Fatalf("started stored %d after the store took records again", n)
	}
}

func TestLagOverBudgetIsHealthEvent(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.push(event(1, ""))
	time.Sleep(50 * time.Millisecond) // the writer appends on Ready; the tick 1.5 s later commits it
	r.step(1500 * time.Millisecond)
	r.step(0)
	if lag := r.st.kinds("lag"); len(lag) != 1 || lag[0]["lag_ms"] != 1500.0 {
		t.Fatalf("lag records %v", lag)
	}
}

func TestStartRestartReexecToldApart(t *testing.T) {
	l := &Links{}
	for _, pid := range []int{10, 10, 11} {
		l.Connected(pid)
		l.Disconnected(nil)
	}
	l.Disconnected(errors.New("connection reset"))
	_, connected := l.check(time.Now())
	c := l.take(time.Now())
	if fmt.Sprint(c.causes) != "map[collector-start:1 eof:3 laurel-restart:1 read-error:1 reconnect:1]" || connected {
		t.Fatalf("causes %v, connected %v", c.causes, connected)
	}
	if fmt.Sprint(c.pids["eof"]) != "map[10:2 11:1]" || c.lastPID != 11 || c.lastCause != "read-error" {
		t.Fatalf("pids %v, last %d %s", c.pids, c.lastPID, c.lastCause)
	}
}

// More connection changes between two ticks than pids kept are all counted, by cause.
func TestLinksCountEveryChangeBetweenTwoTicks(t *testing.T) {
	l := &Links{}
	const pairs = 3 * maxLinkPIDs
	for pid := range pairs {
		l.Connected(100 + pid)
		l.Disconnected(nil)
	}
	c := l.take(time.Now())
	var listed uint64
	for _, m := range c.pids {
		for _, n := range m {
			listed += n
		}
	}
	if c.causes["laurel-restart"] != pairs-1 || c.causes["eof"] != pairs || listed+c.pidsDropped != 2*pairs ||
		len(c.pids["eof"]) != maxLinkPIDs || c.lastPID != 100+pairs-1 {
		t.Fatalf("causes %v, %d listed, %d dropped, %d eof pids, last %d", c.causes, listed, c.pidsDropped, len(c.pids["eof"]), c.lastPID)
	}
}

func connect(r *rig, pid int) {
	r.w.Links.Connected(pid)
}

func TestEOFUnknownUntilProbeOnTheNextConnection(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	n := probed(r) // the probe sent at connection
	r.push(canaryLine(1, n, 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q after the probe was stored", health(r))
	}
	r.w.Links.Disconnected(nil)
	r.step(0)
	if health(r) != "UNKNOWN laurel-disconnected" {
		t.Fatalf("health %q after EOF", health(r))
	}
	r.push(canaryLine(2, n, 1000, 4242)) // an old probe proves nothing
	connect(r, 77)
	r.step(time.Second)
	if health(r) != "UNKNOWN canary-pending" {
		t.Fatalf("health %q before the new probe", health(r))
	}
	m := probed(r)
	r.push(canaryLine(3, m, 1000, 4242))
	r.step(0)
	if health(r) != "OK" || m == n {
		t.Fatalf("health %q, probes %d then %d", health(r), n, m)
	}
	if conns := r.st.kinds("connection"); len(conns) != 3 || conns[2]["cause"] != "reconnect" {
		t.Fatalf("connection records %v", conns)
	}
}

func TestForgedCanaryNotSeen(t *testing.T) {
	for name, forge := range map[string]func(n uint64) string{
		"other uid":         func(n uint64) string { return canaryLine(1, n, 0, 4242) },
		"other pid":         func(n uint64) string { return canaryLine(1, n, 1000, 1) },
		"older probe":       func(n uint64) string { return canaryLine(1, n-1, 1000, 4242) },
		"failed syscall":    func(n uint64) string { return strings.Replace(canaryLine(1, n, 1000, 4242), `"yes"`, `"no"`, 1) },
		"other key":         func(n uint64) string { return strings.Replace(canaryLine(1, n, 1000, 4242), CanaryKey, "x", 1) },
		"not Laurel's line": func(n uint64) string { return "junk " + CanaryKey },
	} {
		r := newRig(t)
		r.start(nil)
		r.settle()
		connect(r, 77)
		r.step(0)
		n := probed(r)
		r.push(forge(n))
		r.step(0)
		if health(r) == "OK" {
			t.Fatalf("%s: a forged canary made the sensor OK", name)
		}
	}
}

func TestCanaryDroppedAtCapIsMiss(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.st.set(func(s *fakeStore) { s.full = true })
	r.step(0)
	n := probed(r)
	r.push(canaryLine(1, n, 1000, 4242))
	r.step(0)
	if health(r) == "OK" {
		t.Fatal("a probe the store dropped counted as seen")
	}
}

func TestTwoMissesUnknownAndStuckSyscallIsMiss(t *testing.T) {
	r := newRig(t)
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	r.w.Canary.touch = func(string, uint64) error { <-stuck; return nil }
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.step(CanaryEvery) // the first probe's deadline; the next round cannot start
	r.step(CanaryEvery)
	if health(r) != "UNKNOWN canary-missed" {
		t.Fatalf("health %q with a stuck canary syscall", health(r))
	}
}

func TestWatchdogFedWhileStoreDownAndNotWhileWriterStuck(t *testing.T) {
	r := newRig(t)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(time.Second) // fed although the store is down
	r.opens <- nil
	r.step(ReopenEvery)
	r.settle()
	block := make(chan struct{})
	r.st.set(func(s *fakeStore) { s.block = block })
	r.push(event(1, ""))
	r.advance(time.Second)
	go func() { r.tick <- r.clock() }()
	select {
	case <-r.fed:
		t.Fatal("the watchdog was fed while the writer was stuck in the store")
	case <-time.After(200 * time.Millisecond):
	}
	close(block)
	<-r.fed
}

// burst holds the writer in its first Append while n records queue behind it; each Append then takes
// cost of the writer's clock, then runs onAppend. Closing the returned channel lets the writer go on.
func burst(r *rig, n int, cost time.Duration, onAppend func()) chan struct{} {
	r.t.Helper()
	block, entered := make(chan struct{}), make(chan struct{}, 1)
	r.st.set(func(s *fakeStore) {
		s.block, s.entered = block, entered
		s.onAppend = func() {
			r.advance(cost)
			if onAppend != nil {
				onAppend()
			}
		}
	})
	r.push(event(1, ""))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the writer did not append")
	}
	for i := 2; i <= n; i++ {
		r.push(event(i, ""))
	}
	return block
}

// committedSeqs returns the provider seqs the store committed, in order.
func committedSeqs(r *rig) []uint64 {
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	var seqs []uint64
	for _, rec := range r.st.committed {
		seqs = append(seqs, rec.ProviderSeq)
	}
	return seqs
}

func wantSeqs(t *testing.T, got []uint64, from, to uint64) {
	t.Helper()
	var want []uint64
	for s := from; s <= to; s++ {
		want = append(want, s)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("committed %v, want %d..%d in order", got, from, to)
	}
}

// stored returns how many records the store took, committed or not.
func stored(r *rig) int {
	r.st.mu.Lock()
	defer r.st.mu.Unlock()
	return len(r.st.appended) + len(r.st.committed)
}

// A burst the store takes far longer than WatchdogSec to append goes in runs of appendBudget. With a
// tick due every FlushEvery of the writer's clock, as a ticker sends them, the watchdog is fed at most
// a tick and two runs apart, and the burst is stored whole (ADR 0017, point 6).
func TestWatchdogFedDuringALongDrain(t *testing.T) {
	const n, cost = 300, 10 * time.Millisecond                                          // 3 s of appends
	const maxGap = store.FlushEvery + 2*(store.FlushEvery/2+cost) + 80*time.Millisecond // a tick, two runs
	r := newRig(t)
	r.tick = make(chan time.Time, 1) // a tick waits while the writer appends, as a ticker's does
	var mu sync.Mutex
	var fed []time.Time
	notify := r.w.Notify
	r.w.Notify = func(state string) error {
		mu.Lock()
		fed = append(fed, r.w.Now())
		mu.Unlock()
		return notify(state)
	}
	r.start(nil)
	r.settle()
	t0 := r.clock()
	next := t0.Add(store.FlushEvery)
	close(burst(r, n, cost, func() { // on the writer's goroutine, inside Append
		if now := r.clock(); !now.Before(next) {
			next = now.Add(store.FlushEvery)
			select {
			case r.tick <- now:
			default: // a ticker drops the tick nobody took
			}
		}
	}))
	until(t, func() bool { return stored(r) == n })
	r.step(0)
	r.step(0) // the tick a run may have left waiting, then the one that commits the rest
	wantSeqs(t, committedSeqs(r), 1, n)
	if len(r.st.kinds("lost")) != 0 || len(r.last.pending) != 0 {
		t.Fatalf("lost %v, pending %v", r.st.kinds("lost"), r.last.pending)
	}
	mu.Lock()
	defer mu.Unlock()
	last := t0
	for _, at := range fed {
		if at.Before(t0) {
			continue
		}
		if gap := at.Sub(last); gap > maxGap {
			t.Fatalf("the watchdog went %v unfed during the burst, more than %v", gap, maxGap)
		}
		last = at
	}
}

// A Flush as slow as the tick leaves a tick always due, so the writer only steps; each step still
// appends a run, so the burst is stored rather than the watchdog fed over a backlog that never shrinks,
// and stop still gets through.
func TestSlowFlushStillAppendsAndStops(t *testing.T) {
	const n = 30
	r := newRig(t)
	r.tick = make(chan time.Time, 1)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) {
		s.onFlush = func() {
			r.advance(store.FlushEvery)
			select {
			case r.tick <- r.clock():
			default:
			}
		}
	})
	block := burst(r, n, 10*time.Millisecond, nil)
	r.tick <- r.clock()
	close(block)
	until(t, func() bool { return len(committedSeqs(r)) == n })
	wantSeqs(t, committedSeqs(r), 1, n)
	close(r.stop)
	select {
	case err := <-r.done:
		r.done <- err
	case <-time.After(5 * time.Second):
		r.st.set(func(s *fakeStore) { s.onFlush = nil }) // lets the rig's cleanup through
		r.done <- <-r.done
		t.Fatal("stop waited behind ticks that were always due")
	}
}

func TestStopDuringABurstStoresItAll(t *testing.T) {
	const n = 30
	r := newRig(t)
	r.start(nil)
	r.settle()
	block := burst(r, n, time.Second, nil)
	close(r.stop)
	close(block)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	wantSeqs(t, committedSeqs(r), 1, n)
	if r.st.closed != 1 || len(r.st.kinds("lost")) != 0 {
		t.Fatalf("closed %d, lost %v", r.st.closed, r.st.kinds("lost"))
	}
}

// Stop taken while a burst waits in the writer stores the burst, then what the reader queued after it,
// in runs that commit and feed the watchdog, which systemd keeps armed when the acceptor failed.
func TestStopWithABacklogStoresItThenTheQueueInRuns(t *testing.T) {
	const n, cost = 300, 10 * time.Millisecond // 6 s of appends at stop
	const maxGap = store.FlushEvery            // a run, its commit and its feed
	r := newRig(t)
	var holding atomic.Bool
	var fed, flushed []time.Time // written by the writer's goroutine, read once Run returned
	hold, held := make(chan struct{}), make(chan struct{}, 1)
	notify := r.w.Notify
	r.w.Notify = func(state string) error {
		if holding.Load() {
			held <- struct{}{}
			<-hold
		}
		fed = append(fed, r.w.Now())
		return notify(state)
	}
	r.start(nil)
	r.settle()
	holding.Store(true)
	go func() { r.tick <- r.clock() }()
	<-held // the writer is inside a tick, so the next run takes all n at once
	for i := 1; i <= n; i++ {
		r.push(event(i, ""))
	}
	var once sync.Once
	var stopAt time.Time
	r.st.set(func(s *fakeStore) {
		s.onAppend = func() {
			r.advance(cost)
			once.Do(func() { // the run goes on to its budget; the rest of the burst waits
				for i := n + 1; i <= 2*n; i++ {
					r.push(event(i, ""))
				}
				stopAt = r.clock()
				close(r.stop)
			})
		}
		s.onFlush = func() { flushed = append(flushed, r.clock()) }
	})
	holding.Store(false)
	close(hold)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	wantSeqs(t, committedSeqs(r), 1, 2*n)
	if len(r.st.kinds("lost")) != 0 {
		t.Fatalf("lost %v", r.st.kinds("lost"))
	}
	for name, at := range map[string][]time.Time{"fed the watchdog": fed, "committed": flushed} {
		last := stopAt
		for _, a := range at {
			if a.Before(stopAt) {
				continue
			}
			if gap := a.Sub(last); gap > maxGap {
				t.Fatalf("shutdown went %v without having %s, more than %v", gap, name, maxGap)
			}
			last = a
		}
		if last.Sub(stopAt) < time.Duration(n)*cost {
			t.Fatalf("shutdown last %s %v after stop, before its appends ended", name, last.Sub(stopAt))
		}
	}
}

// A store that fails on a commit between shutdown's runs makes the stop a failure; the records it held
// and those after it are not reported stored.
func TestStoreFailingBetweenShutdownRunsFailsTheStop(t *testing.T) {
	const n, cost = 60, 10 * time.Millisecond
	r := newRig(t)
	r.start(nil)
	r.settle()
	var once sync.Once
	stopped := false // both hooks run on the writer's goroutine
	r.st.set(func(s *fakeStore) {
		s.onAppend = func() {
			r.advance(cost)
			once.Do(func() { close(r.stop); stopped = true })
		}
		s.onFlush = func() {
			if stopped {
				r.st.set(func(s *fakeStore) { s.failFlush = true })
			}
		}
	})
	for i := 1; i <= n; i++ {
		r.push(event(i, ""))
	}
	err := <-r.done
	r.done <- nil
	if err == nil || len(committedSeqs(r)) != 0 {
		t.Fatalf("stop returned %v with %d records committed after the store failed", err, len(committedSeqs(r)))
	}
}

// A store that fails inside a burst keeps what it committed; the record that failed and every one
// after it, still waiting in the writer, count as lost.
func TestStoreFailingInABurstCountsTheRest(t *testing.T) {
	const n, k = 30, 5
	r := newRig(t)
	r.start(nil)
	r.settle()
	calls := 0
	block := burst(r, n, time.Second, func() {
		if calls++; calls == k {
			r.st.set(func(s *fakeStore) { s.failAppend = true })
		}
	})
	close(block)
	for range 2 * n {
		if r.step(0); !r.last.up && r.last.pending[StageStore].Count == n-k+1 {
			break
		}
	}
	wantSeqs(t, committedSeqs(r), 1, k-1)
	if l := r.last.pending[StageStore]; l.Count != n-k+1 || l.FirstSeq != k || l.LastSeq != n {
		t.Fatalf("pending %+v, want %d..%d lost to the store", r.last.pending, k, n)
	}
}

// A store that opened while records wait goes in before the next tick takes them, so they are stored,
// not counted lost; a tick is due when the writer comes back, so it is the tick that takes them.
func TestReopenedStoreTakesTheRecordsWaiting(t *testing.T) {
	r := newRig(t)
	var holding atomic.Bool
	var ticks atomic.Int32
	hold, held := make(chan struct{}), make(chan struct{}, 1)
	heldTick(r, &holding, &ticks, held, hold)
	r.tick = make(chan time.Time, 1)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery) // a reopen, waiting for r.opens
	holding.Store(true)
	r.tick <- r.clock()
	<-held // the writer is inside a tick
	r.opens <- nil
	until(t, func() bool { return len(r.w.opened) == 1 })
	r.push(event(1, ""), event(2, ""))
	holding.Store(false)
	r.tick <- r.clock() // due before the writer's select can take the open
	close(hold)
	r.step(0)
	r.step(0)
	wantSeqs(t, committedSeqs(r), 1, 2)
	if lost := r.st.kinds("lost"); len(lost) != 0 {
		t.Fatalf("lost %v: records counted lost while the store had opened", lost)
	}
}

// A store that opens inside a tick in which Laurel connected is proved by that connection's probe:
// the tick reads its clock after the appends that opened the store, so the probe is not dated before it.
func TestStoreOpenedInsideATickIsProvedByTheNextProbe(t *testing.T) {
	r := newRig(t)
	r.w.Now = func() time.Time { r.advance(time.Microsecond); return r.clock() } // moves on every read
	var holding atomic.Bool
	hold, held := make(chan struct{}), make(chan struct{}, 1)
	notify := r.w.Notify
	r.w.Notify = func(state string) error {
		if holding.Load() {
			held <- struct{}{}
			<-hold
		}
		return notify(state)
	}
	r.tick = make(chan time.Time, 1)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery) // a reopen, waiting for r.opens, and a scheduled probe
	r.probeReturned()
	for len(r.touched) > 0 { // so the probes taken below are this tick's
		<-r.touched
	}
	holding.Store(true)
	r.tick <- r.clock()
	<-held // the writer is inside a tick
	r.opens <- nil
	until(t, func() bool { return len(r.w.opened) == 1 })
	var once sync.Once
	openProbe := make(chan struct{})
	r.st.set(func(s *fakeStore) {
		s.onAppend = func() { // the open's own probe returns before the tick goes on
			once.Do(func() {
				<-r.touched
				for len(r.w.Canary.inFlight) > 0 {
					time.Sleep(time.Millisecond)
				}
				close(openProbe)
			})
		}
	})
	r.push(event(1, ""))
	connect(r, 77)
	holding.Store(false)
	r.tick <- r.clock() // the next tick opens the store inside its appends
	close(hold)
	select {
	case <-openProbe:
	case <-time.After(5 * time.Second):
		t.Fatal("the tick took the record without opening the store first")
	}
	n := probed(r) // the connection's probe, sent in the same tick
	r.push(canaryLine(2, n, 1000, 4242))
	r.step(0)
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q although the probe sent after the open was stored", health(r))
	}
}

// blockingTouch makes the canary's probe syscalls wait on release while blocking is set, as an audited
// syscall sleeps while the kernel backlog is full.
func blockingTouch(r *rig, blocking *atomic.Bool, release <-chan struct{}) {
	r.w.Canary.touch = func(_ string, n uint64) error {
		r.touched <- n
		if blocking.Load() {
			<-release
		}
		return nil
	}
}

// touchedNow returns the number of a probe whose syscall started, without waiting for it to return.
func touchedNow(r *rig) uint64 {
	r.t.Helper()
	select {
	case n := <-r.touched:
		return n
	case <-time.After(5 * time.Second):
		r.t.Fatal("no probe sent")
		return 0
	}
}

// heldTick makes the writer wait inside a tick's watchdog feed while holding is set; ticks counts the
// ticks it finished.
func heldTick(r *rig, holding *atomic.Bool, ticks *atomic.Int32, held chan<- struct{}, hold <-chan struct{}) {
	notify := r.w.Notify
	r.w.Notify = func(state string) error {
		if holding.Load() {
			held <- struct{}{}
			<-hold
		}
		defer ticks.Add(1)
		return notify(state)
	}
}

// A store that opens inside a tick while Laurel connected: the open's probe still runs when the
// connection's would go out, so that one goes out on the next tick, not 30 s later with the round.
func TestConnectionProbeDroppedBesideTheOpensGoesOutOnTheNextTick(t *testing.T) {
	r := newRig(t)
	r.w.Now = func() time.Time { r.advance(time.Microsecond); return r.clock() } // moves on every read
	var holding, blocking atomic.Bool
	var ticks atomic.Int32
	hold, held, release := make(chan struct{}), make(chan struct{}, 1), make(chan struct{})
	blockingTouch(r, &blocking, release)
	heldTick(r, &holding, &ticks, held, hold)
	r.tick = make(chan time.Time, 1)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery) // a reopen, waiting for r.opens, and a scheduled probe
	r.probeReturned()
	for len(r.touched) > 0 {
		<-r.touched
	}
	holding.Store(true)
	r.tick <- r.clock()
	<-held // the writer is inside a tick
	r.opens <- nil
	until(t, func() bool { return len(r.w.opened) == 1 })
	r.push(event(1, ""))
	connect(r, 77)
	blocking.Store(true)
	holding.Store(false)
	done := ticks.Load() + 2 // the held tick, then the one that opens the store
	r.tick <- r.clock()
	close(hold)
	open := touchedNow(r) // the open's probe, still running through the tick
	until(t, func() bool { return ticks.Load() >= done })
	blocking.Store(false)
	close(release)
	r.probeReturned()
	r.push(canaryLine(2, open, 1000, 4242))
	r.step(0) // stores the open's probe and sends the connection's
	n := probed(r)
	r.push(canaryLine(3, n, 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q although the connection's probe was stored", health(r))
	}
}

// A connection that begins during a tick's appends, after the store opened inside them, is not proved
// by the open's probe, which went out before it began.
func TestConnectionDuringTheAppendsIsNotProvedByTheOpensProbe(t *testing.T) {
	r := newRig(t)
	r.w.Now = func() time.Time { r.advance(time.Microsecond); return r.clock() }
	var holding, blocking atomic.Bool
	var ticks atomic.Int32
	hold, held, release := make(chan struct{}), make(chan struct{}, 1), make(chan struct{})
	blockingTouch(r, &blocking, release)
	heldTick(r, &holding, &ticks, held, hold)
	r.tick = make(chan time.Time, 1)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery)
	r.probeReturned()
	for len(r.touched) > 0 {
		<-r.touched
	}
	holding.Store(true)
	r.tick <- r.clock()
	<-held
	r.opens <- nil
	until(t, func() bool { return len(r.w.opened) == 1 })
	var once sync.Once
	r.st.set(func(s *fakeStore) {
		s.onAppend = func() { once.Do(func() { connect(r, 77) }) } // after the open's probe went out
	})
	r.push(event(1, ""))
	blocking.Store(true)
	holding.Store(false)
	done := ticks.Load() + 2
	r.tick <- r.clock()
	close(hold)
	open := touchedNow(r)
	until(t, func() bool { return ticks.Load() >= done })
	blocking.Store(false)
	close(release)
	r.probeReturned()
	r.push(canaryLine(2, open, 1000, 4242))
	r.step(0)
	if health(r) == "OK" {
		t.Fatal("health OK proved by a probe sent before the connection began")
	}
}

// A connection that comes while the probe of a store opened between ticks still runs gets its probe on
// the next tick, not with the round 30 s later.
func TestDroppedConnectionProbeGoesOutOnTheNextTick(t *testing.T) {
	r := newRig(t)
	var blocking atomic.Bool
	release := make(chan struct{})
	blockingTouch(r, &blocking, release)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery) // a reopen, waiting for r.opens, and a scheduled probe
	r.probeReturned()
	for len(r.touched) > 0 {
		<-r.touched
	}
	blocking.Store(true)
	r.opens <- nil
	open := touchedNow(r) // the open's probe, sent from Run's select, still running
	connect(r, 77)
	r.step(store.FlushEvery) // the connection's probe is dropped
	blocking.Store(false)
	close(release)
	r.probeReturned()
	r.push(canaryLine(1, open, 1000, 4242))
	r.step(store.FlushEvery) // and goes out now
	n := probed(r)
	r.push(canaryLine(2, n, 1000, 4242))
	r.step(store.FlushEvery)
	if health(r) != "OK" {
		t.Fatalf("health %q although the connection's probe was stored", health(r))
	}
}

// A store that reopens while the round's probe still runs gets its own probe on the next tick, not with
// the next round.
func TestReopenWhileARoundsProbeRunsProbesOnTheNextTick(t *testing.T) {
	r := newRig(t)
	var blocking atomic.Bool
	release := make(chan struct{})
	blockingTouch(r, &blocking, release)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.push(canaryLine(1, probed(r), 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q", health(r))
	}
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.push(event(2, ""))
	r.step(time.Second)
	r.st.set(func(s *fakeStore) { s.failFlush = false })
	blocking.Store(true)
	r.step(ReopenEvery) // the round's probe goes out and stays in its syscall; the reopen starts
	touchedNow(r)
	r.opens <- nil
	for range 50 { // the open's probe is dropped
		if r.step(0); r.last.up {
			break
		}
		time.Sleep(time.Millisecond)
	}
	blocking.Store(false)
	close(release)
	r.probeReturned()
	r.step(store.FlushEvery) // the store's probe goes out now
	r.push(canaryLine(3, probed(r), 1000, 4242))
	r.step(store.FlushEvery)
	if health(r) != "OK" {
		t.Fatalf("health %q although the reopened store's probe was stored", health(r))
	}
}

// Laurel disconnecting during a tick's appends makes that tick's health UNKNOWN.
func TestDisconnectDuringATicksAppendsIsUnknown(t *testing.T) {
	r := newRig(t)
	var holding atomic.Bool
	var ticks atomic.Int32
	hold, held := make(chan struct{}), make(chan struct{}, 1)
	heldTick(r, &holding, &ticks, held, hold)
	var mu sync.Mutex
	var healths []string // each tick's health, as its watchdog feed sees it
	feed := r.w.Notify
	r.w.Notify = func(state string) error {
		mu.Lock()
		healths = append(healths, r.w.health)
		mu.Unlock()
		return feed(state)
	}
	r.tick = make(chan time.Time, 1)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.push(canaryLine(1, probed(r), 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("setup: health %q", health(r))
	}
	var once sync.Once
	r.st.set(func(s *fakeStore) { s.onAppend = func() { once.Do(func() { r.w.Links.Disconnected(nil) }) } })
	holding.Store(true)
	r.tick <- r.clock()
	<-held // inside a tick
	r.push(event(2, ""))
	holding.Store(false)
	done := ticks.Load() + 2 // the held tick, then the one whose append sees Laurel go
	r.tick <- r.clock()
	close(hold)
	until(t, func() bool { return ticks.Load() >= done })
	mu.Lock()
	defer mu.Unlock()
	if h := healths[len(healths)-1]; h == "OK" {
		t.Fatalf("health OK in the tick whose appends saw Laurel disconnect")
	}
}

// A store that opens in the middle of a run takes the rest of the run's records: only those taken
// before it opened count lost.
func TestStoreOpenedInsideARunTakesTheRestOfIt(t *testing.T) {
	const n = 10
	r := newRig(t)
	var holding, armed atomic.Bool
	var ticks, reads atomic.Int32
	hold, held := make(chan struct{}), make(chan struct{}, 1)
	heldTick(r, &holding, &ticks, held, hold)
	r.w.Now = func() time.Time {
		if armed.Load() && reads.Add(1) == 2 { // the run's budget check after its first record
			r.opens <- nil
			for i := 0; i < 500 && len(r.w.opened) == 0; i++ { // the writer's goroutine: no t.Fatal here
				time.Sleep(10 * time.Millisecond)
			}
		}
		return r.clock()
	}
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery) // a reopen, waiting for r.opens
	holding.Store(true)
	go func() { r.tick <- r.clock() }()
	<-held // the writer is inside a tick; the queue fills, so one run takes it all
	for i := 1; i <= n; i++ {
		r.push(event(i, ""))
	}
	armed.Store(true)
	holding.Store(false)
	close(hold)
	until(t, func() bool { return reads.Load() > 2 })
	r.step(0)
	r.step(0)
	wantSeqs(t, committedSeqs(r), 2, n)
	if lost := r.st.kinds("lost"); len(lost) != 1 || lost[0]["stage"] != "store" || lost[0]["count"] != 1.0 ||
		lost[0]["first_seq"] != 1.0 {
		t.Fatalf("lost %v, want only the first record lost to the store", lost)
	}
}

func TestShutdownStopsAPendingOpen(t *testing.T) {
	r := newRig(t)
	r.start(errors.New("no disk"))
	r.settle()
	r.step(ReopenEvery) // a reopen that never returns on its own
	close(r.stop)
	select {
	case <-r.done:
		r.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited for an open that does not end")
	}
}

func TestShutdownStoresQueuedLinesThenCloses(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.push(event(1, ""), event(2, ""))
	close(r.stop)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	if len(r.st.appended)+len(r.st.committed) != 2 || r.st.closed != 1 || len(r.st.kinds("stopping")) != 1 {
		t.Fatalf("appended %d, closed %d", len(r.st.appended)+len(r.st.committed), r.st.closed)
	}
}

func TestLeftoverCanaryFilesRemovedAtStart(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"c-3", "c-4"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewCanary(dir, 1, 1); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "c-*")); len(left) != 0 {
		t.Fatalf("left %v", left)
	}
}

func TestTouchCreatesNextAndRemovesPrevious(t *testing.T) {
	dir := t.TempDir()
	if err := errors.Join(touch(dir, 1), touch(dir, 2), touch(dir, 4)); err != nil { // 3 never touched
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "c-*")); len(left) != 1 || filepath.Base(left[0]) != "c-4" {
		t.Fatalf("left %v", left)
	}
}

// A connection's probe must not be replaced by the round that falls due right after it.
func TestConnectionProbeNotReplacedByTheRound(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.step(CanaryEvery)
	n := probed(r) // the round's probe, before any connection
	r.step(CanaryEvery - time.Second)
	connect(r, 77)
	r.step(0)
	m := probed(r)
	r.step(time.Second) // a full interval since the round, not since the connection
	r.push(canaryLine(1, m, 1000, 4242))
	r.step(0)
	if health(r) != "OK" || m == n {
		t.Fatalf("health %q, probes %d then %d", health(r), n, m)
	}
}

func TestHealthRecordsWaitingForTheStoreAreBounded(t *testing.T) {
	r := newRig(t)
	r.start(errors.New("no disk"))
	r.settle()
	for range maxNotes + 10 {
		r.step(statsEvery)
	}
	if r.last.waiting > maxNotes {
		t.Fatalf("%d health records waiting", r.last.waiting)
	}
}

// While the store takes no health record, the queue gives way, but never a loss record: a loss that
// comes while one waits adds up in pending, and every loss is stored once the store takes them again.
func TestLossRecordsNeverGiveWayInTheQueue(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.step(0) // the loss record waits for the store
	for i := range maxNotes + 10 {
		if i == maxNotes/2 {
			r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 22, noon, []byte("dropped")))
		}
		r.step(statsEvery)
	}
	if r.last.waiting > maxNotes {
		t.Fatalf("%d health records waiting", r.last.waiting)
	}
	r.st.set(func(s *fakeStore) { s.rejectNote = false })
	for range 3 {
		r.step(0)
	}
	var seqs []float64
	for _, l := range r.st.kinds("lost") {
		seqs = append(seqs, l["first_seq"].(float64))
	}
	if fmt.Sprint(seqs) != "[21 22]" {
		t.Fatalf("committed loss records start at %v, want [21 22]", seqs)
	}
	r.step(statsEvery)
	stats := r.st.kinds("stats")
	if last := stats[len(stats)-1]; last["lost"] != 2.0 || last["lost_health"].(float64) < 10 {
		t.Fatalf("last stats record %v", last)
	}
}

// A flood of losses while the store takes no health record adds up in pending: once the store takes
// records again, the loss records it gets account for every loss.
func TestLossFloodIsSummedNotDropped(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	seq := uint64(100)
	for range 2 * maxNotes {
		for _, stage := range []Stage{StageQueue, StageFraming, StageStore} {
			seq++
			r.w.Losses.Add(stage, rawrecord.New(0, "laurel", seq, noon, []byte("dropped")))
		}
		r.step(statsEvery)
	}
	r.st.set(func(s *fakeStore) { s.rejectNote = false })
	for range 4 {
		r.step(0)
	}
	var sum float64
	for _, l := range r.st.kinds("lost") {
		sum += l["count"].(float64)
	}
	if want := float64(seq - 100); sum != want {
		t.Fatalf("loss records count %v of %v losses", sum, want)
	}
}

// At stop, a loss summed in pending while an earlier loss record waited gets its own record.
func TestStopStoresLossesSummedBehindAWaitingRecord(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.step(0) // its record waits for the store
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 22, noon, []byte("dropped")))
	r.step(0) // pending, behind the waiting record
	r.st.set(func(s *fakeStore) { s.rejectNote = false })
	close(r.stop)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	var seqs []float64
	for _, l := range r.st.kinds("lost") {
		seqs = append(seqs, l["first_seq"].(float64))
	}
	if fmt.Sprint(seqs) != "[21 22]" {
		t.Fatalf("loss records stored at stop start at %v, want [21 22]", seqs)
	}
}

// The queue stays bounded: other records give way first, loss records only to newer loss records.
func TestRequeueBoundGivesWayToLossRecordsLast(t *testing.T) {
	w := &Writer{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.requeue(nil, note{b: []byte("loss 0"), kind: "lost"}, note{b: []byte("other")})
	for i := range maxNotes - 1 {
		w.requeue(nil, note{b: fmt.Appendf(nil, "loss %d", i+1), kind: "lost"})
	}
	if len(w.notes) != maxNotes || w.lostNotes != 1 || string(w.notes[0].b) != "loss 0" {
		t.Fatalf("%d waiting, %d given way, oldest %q", len(w.notes), w.lostNotes, w.notes[0].b)
	}
	w.requeue(nil, note{b: []byte("loss 128"), kind: "lost"})
	if len(w.notes) != maxNotes || w.lostNotes != 2 || string(w.notes[0].b) != "loss 1" {
		t.Fatalf("only loss records: %d waiting, %d given way, oldest %q", len(w.notes), w.lostNotes, w.notes[0].b)
	}
}

// journal is a log sink the writer's goroutine and the test share.
type journal struct {
	mu sync.Mutex
	b  strings.Builder
}

func (j *journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.b.Write(p)
}

func (j *journal) String() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.b.String()
}

// A loss record that a failed Close handed back reaches the journal each minute while the store is down,
// and again at a stop with the store still down (ADR 0017, point 7).
func TestLossRecordsWaitingWhileDownReachTheJournal(t *testing.T) {
	r := newRig(t)
	j := &journal{}
	r.w.Log = slog.New(slog.NewTextHandler(j, nil))
	r.start(nil)
	r.settle()
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.step(0) // the loss record is handed to the store
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.step(0) // Flush and Close fail: the record comes back, the store is down
	r.step(time.Minute)
	minute := strings.Count(j.String(), "lost_waiting=\"map[queue:[{Count:1 Bytes:7 FirstSeq:21 LastSeq:21")
	if minute == 0 {
		t.Fatalf("no loss record in the journal while the store is down:\n%s", j)
	}
	close(r.stop)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	if n := strings.Count(j.String(), "lost_not_stored=\"map[queue:[{Count:1 Bytes:7 FirstSeq:21 LastSeq:21"); n == 0 {
		t.Fatalf("the loss record was not journaled at stop:\n%s", j)
	}
}

// At stop the store takes only so many health records: a loss record goes before a backlog.
func TestStopStoresLossRecordsFirst(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	for range 80 {
		r.step(statsEvery)
	}
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.step(0)
	r.st.set(func(s *fakeStore) { s.rejectNote, s.noteCap = false, 64 })
	close(r.stop)
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil
	if lost := r.st.kinds("lost"); len(lost) != 1 || lost[0]["first_seq"] != 21.0 {
		t.Fatalf("loss records stored at stop: %v", lost)
	}
}

// The stats record counts every record lost since start (ADR 0017, point 5).
func TestStatsRecordCountsLosses(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.w.Losses.Add(StageFraming, rawrecord.New(0, "laurel", 22, noon, []byte("dropped")))
	r.step(statsEvery)
	r.step(0)
	stats := r.st.kinds("stats")
	if len(stats) != 1 || stats[0]["lost"] != 2.0 || stats[0]["lost_health"] != 0.0 {
		t.Fatalf("stats records %v", stats)
	}
}

// enrichedCanaryLine is shaped as Laurel writes it with enrich and translate on (deploy/laurel): the
// "PID" and "PPID" objects and "UID" name next to the numbers they enrich.
func enrichedCanaryLine(serial int, n uint64, uid, pid int, key string) string {
	return fmt.Sprintf(`{"ID":"1.2:%d","SYSCALL":{"syscall":"openat","success":"yes","uid":%d,"UID":"balistid-collector",`+
		`"pid":%d,"PID":{"EVENT_ID":"1.1:1","comm":"balistid-collec","exe":"/usr/bin/balistid-collector"},`+
		`"ppid":1,"PPID":{"EVENT_ID":"1.0:1","comm":"systemd"},"key":%s},"SPAWNED_BY":{"ID":"1.0:1"},`+
		`"PATH":[{"name":"/var/lib/balistid/canary/c-%d","NAME":"c"}]}`, serial, uid, pid, jsonString(key), n)
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// latestProbe returns the number of the last probe sent so far.
func latestProbe(r *rig) uint64 {
	r.t.Helper()
	n := probed(r)
	for {
		select {
		case m := <-r.touched:
			r.probeReturned()
			n = m
		case <-time.After(100 * time.Millisecond):
			return n
		}
	}
}

func TestCanaryProbeReadsLaurelsEnrichedRecord(t *testing.T) {
	for name, line := range map[string]string{
		"enriched":     enrichedCanaryLine(1, 3, 1000, 4242, CanaryKey),
		"several keys": enrichedCanaryLine(1, 3, 1000, 4242, "other\x01"+CanaryKey),
	} {
		if got := canaryProbe([]byte(line), 1000, 4242); got != "c-3" {
			t.Fatalf("%s: canaryProbe = %q", name, got)
		}
	}
	if got := canaryProbe([]byte(enrichedCanaryLine(1, 3, 1000, 4242, "balistid-canary-not")), 1000, 4242); got != "" {
		t.Fatalf("a key that only starts like the canary's matched: %q", got)
	}
}

func TestProbeCountsOnlyOnceCommitted(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.push(enrichedCanaryLine(1, probed(r), 1000, 4242, CanaryKey))
	time.Sleep(50 * time.Millisecond) // appended on Ready, before the tick that commits it
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.step(0)
	if health(r) == "OK" {
		t.Fatal("a probe whose commit failed made the sensor OK")
	}
}

func TestReopenedStoreNeedsANewProbe(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.push(canaryLine(1, probed(r), 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q", health(r))
	}
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.push(event(2, ""))
	r.step(time.Second)
	r.st.set(func(s *fakeStore) { s.failFlush = false })
	r.step(ReopenEvery) // the round's probe goes out; the reopen waits for its slot
	probed(r)           // and returns, or the reopened store's probe would wait for the next round
	r.advance(time.Second)
	r.opens <- nil
	for range 50 {
		if r.step(0); r.last.up {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if health(r) == "OK" {
		t.Fatal("OK after reopen on a probe sent before it")
	}
	r.push(canaryLine(3, latestProbe(r), 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q after the reopened store's probe", health(r))
	}
}

func TestStoreLossCarriesSerialsAndBytes(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.push(event(11, ""), event(12, ""))
	r.step(0)
	l := r.last.pending[StageStore]
	if l.Count != 2 || l.FirstSeq != 11 || l.LastSeq != 12 || l.Bytes != uint64(2*len(event(11, ""))) {
		t.Fatalf("store loss %+v", l)
	}
}

func TestLateRecordOfAMissedProbeDoesNotCount(t *testing.T) {
	r := newRig(t)
	release := make(chan struct{})
	r.w.Canary.touch = func(_ string, n uint64) error { <-release; r.touched <- n; return nil }
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.step(CanaryEvery) // the connection's probe misses its deadline
	close(release)
	n := probed(r)
	r.push(canaryLine(1, n, 1000, 4242)) // late: must neither prove nor forgive the miss
	r.step(time.Second)
	if health(r) == "OK" {
		t.Fatal("a probe stored after its deadline made the sensor OK")
	}
	r.step(CanaryEvery) // the round's probe goes out
	latestProbe(r)
	r.step(CanaryEvery) // and misses: the second miss in a row
	if health(r) != "UNKNOWN canary-missed" {
		t.Fatalf("health %q: the late record hid a miss", health(r))
	}
}

// Probes that come back while their records stop arriving (auditd stopped, the connection still open)
// must turn a proven sensor UNKNOWN within two rounds.
func TestStoppedCanaryRecordsTurnUnknown(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.push(canaryLine(1, probed(r), 1000, 4242))
	r.step(0)
	if health(r) != "OK" {
		t.Fatalf("health %q", health(r))
	}
	r.step(CanaryEvery)
	latestProbe(r)
	r.step(CanaryEvery)
	latestProbe(r)
	r.step(CanaryEvery)
	if health(r) != "UNKNOWN canary-missed" {
		t.Fatalf("health %q after two rounds without canary records", health(r))
	}
}

// reopenAfterFailure lets the failed store's writer open a working one.
func reopenAfterFailure(r *rig) {
	r.t.Helper()
	r.st.set(func(s *fakeStore) { s.failFlush, s.failClose, s.flushErr, s.closeSealErr = false, false, false, false })
	r.opens <- nil
	r.step(ReopenEvery)
	for range 50 {
		if r.step(0); r.last.up {
			r.step(0) // hands over what waited
			r.step(0) // and commits it
			return
		}
		time.Sleep(time.Millisecond)
	}
	r.t.Fatal("the store did not reopen")
}

// A loss record the store took but did not commit before it failed is handed to the next store.
func TestLossRecordSurvivesAFailedCommit(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.step(0) // the loss record goes to the store, uncommitted
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.step(0)
	reopenAfterFailure(r)
	lost := r.st.kinds("lost")
	if len(lost) != 1 || lost[0]["stage"] != "queue" || lost[0]["first_seq"] != 21.0 {
		t.Fatalf("committed loss records %v", lost)
	}
}

// Records the store dropped at its cap are counted by the writer until the store commits its own
// loss record, so a failed commit does not forget them.
func TestCapDropsSurviveAFailedCommit(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.full = true })
	r.push(event(31, ""))
	until(t, func() bool { r.st.mu.Lock(); defer r.st.mu.Unlock(); return r.st.dropped == 1 })
	r.st.set(func(s *fakeStore) { s.full, s.failFlush = false, true })
	r.step(0)
	reopenAfterFailure(r)
	lost := r.st.kinds("lost")
	if len(lost) != 1 || lost[0]["stage"] != "cap" || lost[0]["count"] != 1.0 || lost[0]["first_seq"] != 31.0 {
		t.Fatalf("committed loss records %v", lost)
	}
}

func TestCapDropsCommittedByTheStoreAreNotCountedTwice(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.full = true })
	r.push(event(41, ""))
	r.step(0)
	r.st.set(func(s *fakeStore) { s.full = false })
	r.step(0) // the store commits its own loss record
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	r.push(event(42, ""))
	time.Sleep(50 * time.Millisecond)
	r.step(0) // a later failure must not count the committed drop again
	reopenAfterFailure(r)
	for _, l := range r.st.kinds("lost") {
		if l["stage"] == "cap" {
			t.Fatalf("a drop the store already counted was counted again: %v", l)
		}
	}
	if r.st.droppedStored != 1 {
		t.Fatalf("the store's own loss record counted %d", r.st.droppedStored)
	}
}

// A canary record that arrives after its probe's deadline, before the next tick, proves nothing.
func TestCanaryArrivingAfterItsDeadlineIsNotProof(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	n := probed(r)
	r.advance(CanaryEvery + time.Millisecond)
	r.push(canaryLine(1, n, 1000, 4242))
	time.Sleep(50 * time.Millisecond) // appended on Ready, between ticks
	r.step(0)
	if health(r) == "OK" {
		t.Fatal("a probe stored after its deadline made the sensor OK")
	}
}

func TestLagIsMeasuredWhenTheCommitEnds(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.onFlush = func() { r.advance(2 * time.Second) } })
	r.push(event(1, ""))
	time.Sleep(50 * time.Millisecond)
	r.step(0)
	r.st.set(func(s *fakeStore) { s.onFlush = nil })
	r.step(0)
	if lag := r.st.kinds("lag"); len(lag) != 1 || lag[0]["lag_ms"].(float64) < 2000 {
		t.Fatalf("lag records %v", lag)
	}
}

// Only -log-commits journals the store's Committed, once per change and after the commit (ADR 0022).
func TestNoCommitLogWithoutFlag(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprint(on), func(t *testing.T) {
			r := newRig(t)
			j := &journal{}
			r.w.Log = slog.New(slog.NewTextHandler(j, nil))
			r.w.LogCommits = on
			r.start(nil)
			r.settle()
			r.push(event(1, ""), event(2, ""))
			r.step(0)
			r.step(0) // nothing new was committed
			r.push(event(3, ""))
			r.step(0)
			lines := strings.Count(j.String(), `msg="committed through"`)
			if !on && lines != 0 {
				t.Fatalf("commit lines without the flag:\n%s", j)
			}
			if on && (lines != 2 || !strings.Contains(j.String(), `msg="committed through" seq=2`) ||
				!strings.Contains(j.String(), `msg="committed through" seq=3`)) {
				t.Fatalf("want one line at seq 2 and one at 3:\n%s", j)
			}
		})
	}
}

// A failed Flush journals nothing new, and the Close that follows it, which commits, does.
func TestCommitLogAfterTheCloseOfAFailedStore(t *testing.T) {
	r := newRig(t)
	j := &journal{}
	r.w.Log = slog.New(slog.NewTextHandler(j, nil))
	r.w.LogCommits = true
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.flushErr = true })
	r.push(event(1, ""))
	r.step(0)
	if got := strings.Count(j.String(), `msg="committed through"`); got != 1 || !strings.Contains(j.String(), `msg="committed through" seq=1`) {
		t.Fatalf("want one line at seq 1 from the Close:\n%s", j)
	}
}

func TestCloseFailureAtStopIsReported(t *testing.T) {
	r := newRig(t)
	var log strings.Builder
	var mu sync.Mutex
	r.w.Log = slog.New(slog.NewTextHandler(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return log.Write(b)
	}), nil))
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.failClose = true })
	r.push(event(51, ""))
	time.Sleep(50 * time.Millisecond)
	close(r.stop)
	err := <-r.done
	r.done <- nil
	mu.Lock()
	defer mu.Unlock()
	if err == nil || !strings.Contains(log.String(), "store close failed at stop") || !strings.Contains(log.String(), "stopping:1") {
		t.Fatalf("Run = %v, log:\n%s", err, log.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// What a seal committed is not sent again when the store fails afterwards: every health record is
// committed exactly once.
func TestASealCommitsWhatWasHandedOver(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 61, noon, []byte("dropped")))
	r.step(0) // the loss record goes to the store, uncommitted
	r.st.set(func(s *fakeStore) { s.sealNext, s.failFlush = true, true })
	r.push(event(62, "")) // its Append seals, committing the loss record; the Flush after it fails
	time.Sleep(50 * time.Millisecond)
	r.step(0)
	reopenAfterFailure(r)
	seen := map[float64]int{}
	for _, n := range r.st.kinds("lost") {
		seen[n["note_seq"].(float64)]++
	}
	for seq, n := range seen {
		if n != 1 {
			t.Fatalf("health record %v committed %d times", seq, n)
		}
	}
	if len(seen) == 0 {
		t.Fatal("the loss record was never committed")
	}
}

// until waits for cond, which the writer's goroutine makes true, instead of a fixed sleep.
func until(t *testing.T, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the writer never got there")
}

// countCap returns how many cap drops are on record: the store's own and the collector's "cap" losses.
func countCap(st *fakeStore) int {
	n := st.droppedStored
	for _, l := range st.kinds("lost") {
		if l["stage"] == "cap" {
			n += int(l["count"].(float64))
		}
	}
	return n
}

// A Flush that commits and then fails, or an Append that seals and then fails, committed what the
// store held: one drop at the cap stays one drop, and no health record is committed twice.
func TestACommitBeforeAFailureIsNotCountedAgain(t *testing.T) {
	for name, fail := range map[string]func(*fakeStore){
		"flush":              func(s *fakeStore) { s.commitThenFail = true },
		"append":             func(s *fakeStore) { s.sealThenFail = true },
		"append, then close": func(s *fakeStore) { s.sealThenFail, s.failClose = true, true },
	} {
		r := newRig(t)
		r.start(nil)
		r.settle()
		r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 70, noon, []byte("dropped")))
		r.st.set(func(s *fakeStore) { s.full = true })
		r.push(event(71, ""))
		r.step(0) // the drop at the cap and the loss record go to the store, uncommitted
		r.st.set(func(s *fakeStore) { s.full = false; fail(s) })
		r.push(event(72, ""))
		time.Sleep(50 * time.Millisecond)
		r.step(0)
		reopenAfterFailure(r)
		if n := countCap(r.st); n != 1 {
			t.Fatalf("%s: one drop at the cap is on record %d times", name, n)
		}
		seen := map[float64]int{}
		for _, n := range r.st.kinds("lost") {
			seen[n["note_seq"].(float64)]++
		}
		for seq, n := range seen {
			if n != 1 {
				t.Fatalf("%s: health record %v committed %d times", name, seq, n)
			}
		}
	}
}

// An event between a tick's check and its summary's take is stamped by the take and still probed by
// the next check, which does not stamp the counts the take emptied.
func TestEventBetweenCheckAndTakeKeepsItsTimesAndProbe(t *testing.T) {
	l := &Links{}
	at := func(s int) time.Time { return time.Unix(0, noon).Add(time.Duration(s) * time.Second) }
	l.check(at(0))
	l.Connected(1) // after the check, before the take
	if c := l.take(at(1)); c.count != 1 || c.firstAt != at(1).UnixNano() || c.lastAt != at(1).UnixNano() {
		t.Fatalf("taken %d events, first_at %d, last_at %d", c.count, c.firstAt, c.lastAt)
	}
	if changed, connected := l.check(at(2)); !changed || !connected {
		t.Fatalf("the next check saw changed %v, connected %v: the new connection gets no probe", changed, connected)
	}
	l.Disconnected(nil)
	l.check(at(3))
	if c := l.take(at(4)); c.count != 1 || c.firstAt != at(3).UnixNano() || c.lastAt != at(3).UnixNano() {
		t.Fatalf("taken %d events, first_at %v, last_at %v, want both at %v", c.count, c.firstAt, c.lastAt, at(3).UnixNano())
	}
}

// A stopped stream to the ledger names the health only where it would be OK: a missed canary is still
// recorded as such (ADR 0017, point 5).
func TestAStoppedStreamKeepsRecordingTheCanary(t *testing.T) {
	r := newRig(t)
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	r.w.Canary.touch = func(string, uint64) error { <-stuck; return nil }
	r.w.stopped = "the ledger's batch is not the store's"
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0)
	r.step(CanaryEvery)
	r.step(CanaryEvery)
	if health(r) != "UNKNOWN canary-missed" {
		t.Fatalf("health %q with a stopped stream and a stuck canary syscall", health(r))
	}
}
