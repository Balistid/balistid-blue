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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
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
	onFlush                  func()        // runs inside Flush, as a slow commit would
	closed                   int
}

func (s *fakeStore) Append(_ context.Context, r rawrecord.Record) (bool, []store.Seal, error) {
	s.mu.Lock()
	block := s.block
	s.mu.Unlock()
	if block != nil {
		<-block
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
	if s.rejectNote {
		return errors.New("64 health records queued")
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s.queued = append(s.queued, m)
	return nil
}

func (s *fakeStore) Health() string { return "" }

func (s *fakeStore) Close(context.Context) ([]store.Seal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	if s.failClose || s.failFlush {
		s.lose()
		return nil, errors.New("close failed")
	}
	s.commit()
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
		Started: map[string]string{"version": "test"},
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
		return n
	case <-time.After(5 * time.Second):
		r.t.Fatal("no probe sent")
		return 0
	}
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
		l.Disconnected()
	}
	events, dropped, connected := l.take()
	var causes []string
	for _, e := range events {
		causes = append(causes, e.cause)
	}
	if strings.Join(causes, " ") != "collector-start eof reconnect eof laurel-restart eof" || dropped != 0 || connected {
		t.Fatalf("causes %v, dropped %d, connected %v", causes, dropped, connected)
	}
	for range maxLinkEvents + 3 {
		l.Connected(12)
	}
	if events, dropped, _ := l.take(); len(events) != maxLinkEvents || dropped != 3 {
		t.Fatalf("kept %d events, dropped %d", len(events), dropped)
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
	r.w.Links.Disconnected()
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
	r.st.set(func(s *fakeStore) { s.failFlush, s.failClose = false, false })
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
	time.Sleep(50 * time.Millisecond)
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
	if err == nil || !strings.Contains(log.String(), "store close failed at stop") || !strings.Contains(log.String(), "Count:1") {
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
