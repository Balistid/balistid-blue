package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// stopRig closes the writer's stop channel and returns what Run returned.
func stopRig(r *rig) error {
	close(r.stop)
	err := <-r.done
	r.done <- nil
	return err
}

// once sums the count of the health records of kind, each note_seq once: a record sent again after a
// failure keeps its note_seq, so the store may hold it twice.
func once(st *fakeStore, kind string) (sum float64, seqs int) {
	seen := map[float64]bool{}
	for _, n := range st.kinds(kind) {
		if seq := n["note_seq"].(float64); !seen[seq] {
			seen[seq] = true
			c, ok := n["count"].(float64)
			if !ok { // one record per event
				c = 1
			}
			sum += c
		}
	}
	return sum, len(seen)
}

// waitUp runs ticks until the store the writer reopens is up.
func waitUp(r *rig) {
	r.t.Helper()
	for range 200 {
		if r.step(0); r.last.up {
			return
		}
		time.Sleep(time.Millisecond)
	}
	r.t.Fatal("the store did not reopen")
}

// A reconnect flood during a store outage is one connection record once the store is back (T25).
func TestReconnectFloodWhileDownIsOneSummary(t *testing.T) {
	r := newRig(t)
	r.start(errors.New("no disk"))
	r.settle()
	for i := range 600 {
		r.w.Links.Connected(100 + i)
		r.w.Links.Disconnected(nil)
		if i%20 == 0 { // 40 events a tick: more than Links keeps between two ticks
			r.step(time.Second)
		}
	}
	reopenAfterFailure(r)
	conns := r.st.kinds("connection")
	if len(conns) != 1 || conns[0]["count"] != 1200.0 || conns[0]["laurel_pid"] != 699.0 || conns[0]["cause"] != "eof" {
		t.Fatalf("%d connection records, first %v", len(conns), conns[:min(len(conns), 1)])
	}
	var causes, listed float64
	for _, n := range conns[0]["causes"].(map[string]any) {
		causes += n.(float64)
	}
	for _, m := range conns[0]["pids"].(map[string]any) {
		for _, n := range m.(map[string]any) {
			listed += n.(float64)
		}
	}
	if causes != 1200 || listed+conns[0]["pids_dropped"].(float64) != 1200 {
		t.Fatalf("causes count %v, pids count %v and %v dropped, of 1200 events", causes, listed, conns[0]["pids_dropped"])
	}
}

// Every pid of the connections between two ticks is in the summary (ADR 0017, point 4).
func TestConnectionSummaryNamesEveryPid(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	for _, pid := range []int{10, 20, 30} {
		connect(r, pid)
		r.w.Links.Disconnected(nil)
	}
	r.step(0)
	r.step(0)
	conns := r.st.kinds("connection")
	if len(conns) != 1 || fmt.Sprint(conns[0]["pids"]) != "map[collector-start:map[10:1] eof:map[10:1 20:1 30:1] laurel-restart:map[20:1 30:1]]" {
		t.Fatalf("connection records %v", conns)
	}
}

// At stop, events counted while an earlier summary waited get their own summary, and summaries go to
// the store before other records. A refusal without an error keeps the error of one before it.
func TestStopStoresEverySummaryBeforeOtherRecords(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	connect(r, 77)
	r.w.Refusals.add(r.clock(), 1233, nil)
	r.step(statsEvery) // both summaries wait for the store
	r.w.Links.Disconnected(nil)
	r.w.Refusals.add(r.clock(), 1234, errors.New("peer gone"))
	for range 80 {
		r.step(statsEvery) // counted behind the waiting summaries, which 80 records follow
	}
	r.w.Refusals.add(r.clock(), 1235, nil) // taken at stop
	r.st.set(func(s *fakeStore) { s.rejectNote, s.noteCap = false, 64 })
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	conns, seqs := once(r.st, "connection")
	refused := r.st.kinds("refused")
	if conns != 2 || seqs != 2 || len(refused) != 2 || refused[1]["count"] != 2.0 || refused[1]["last_error"] != "peer gone" {
		t.Fatalf("connection records count %v in %d, refused %v", conns, seqs, refused)
	}
}

// A store that opens, takes the records and fails before or while committing them, 200 times over,
// loses no connection event or loss and counts none twice.
func TestFlappingStoreLosesAndDoublesNothing(t *testing.T) {
	r := newRig(t)
	r.w.Canary.touch = func(string, uint64) error { return nil }
	r.st.noteCap = 64
	r.start(nil)
	r.settle()
	const cycles = 200
	for c := range cycles {
		r.w.Links.Connected(500 + c)
		r.w.Links.Disconnected(nil)
		r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", uint64(1000+c), noon, []byte("dropped")))
		if c%100 == 99 {
			r.step(0) // committed this time, and the new events handed over
		}
		r.st.set(func(s *fakeStore) { // what the store took when it opened is not committed yet
			if c%100 == 50 {
				s.flushErr, s.closeSealErr = true, true // Close commits them, but says it failed
			} else {
				s.failFlush = true
			}
		})
		r.step(0)
		r.st.set(func(s *fakeStore) { s.failFlush, s.flushErr, s.closeSealErr = false, false, false })
		r.opens <- nil
		r.step(ReopenEvery)
		waitUp(r)
	}
	reopenAfterFailure(r)
	for range 3 {
		r.step(0)
	}
	if sum, seqs := once(r.st, "connection"); sum != 2*cycles || seqs == len(r.st.kinds("connection")) {
		t.Fatalf("connection records count %v of %d events; %d stored, none twice", sum, 2*cycles, seqs)
	}
	sum, _ := once(r.st, "lost")
	first, last := 1e9, 0.0
	for _, l := range r.st.kinds("lost") {
		first, last = min(first, l["first_seq"].(float64)), max(last, l["last_seq"].(float64))
	}
	if sum != cycles || first != 1000 || last != 1000+cycles-1 {
		t.Fatalf("loss records count %v of %d, seq %v to %v", sum, cycles, first, last)
	}
}

// Under a flood of connections and refusals, with the store down or taking no health record while
// the records waiting for it give way, the journal gets one line a minute, with counts and no record.
func TestJournalBoundedUnderFlood(t *testing.T) {
	for name, down := range map[string]bool{"store down": true, "store taking no health record": false} {
		r := newRig(t)
		j := &journal{}
		r.w.Log = slog.New(slog.NewTextHandler(j, nil))
		r.w.Canary.touch = func(string, uint64) error { return nil }
		if down {
			r.start(errors.New("no disk"))
		} else {
			r.st.rejectNote = true
			r.start(nil)
		}
		r.settle()
		const minutes = 5
		events := 0
		for tick := range minutes * 60 {
			for i := range 20 {
				r.w.Links.Connected(100 + i)
				r.w.Refusals.add(r.clock(), 1234, errors.New("peer gone"))
			}
			events += 20
			if tick%2 == 1 { // a health record every tick, which gives way in the end
				r.w.Links.Disconnected(nil)
				events++
			}
			r.step(time.Second)
		}
		out := j.String()
		if n := strings.Count(out, "\n"); n > minutes+2 {
			t.Fatalf("%s: %d journal lines in %d minutes:\n%s", name, n, minutes, out)
		}
		for _, body := range []string{"note_seq", "laurel_pid", "last_uid", "peer gone"} {
			if strings.Contains(out, body) {
				t.Fatalf("%s: a health record reached the journal (%s):\n%s", name, body, out)
			}
		}
		if want := fmt.Sprintf("connection:%d", events); !strings.Contains(out, want) || !strings.Contains(out, "refused:") {
			t.Fatalf("%s: no %s or refusal count in the journal:\n%s", name, want, out)
		}
	}
}

// A refusal after the last stats tick is stored at stop, or journaled with the store down.
func TestRefusalAfterTheLastStatsTickIsKeptAtStop(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.w.Refusals.add(r.clock(), 1234, nil)
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	if got := r.st.kinds("refused"); len(got) != 1 || got[0]["count"] != 1.0 || got[0]["last_uid"] != 1234.0 {
		t.Fatalf("refused records %v", got)
	}
	r = newRig(t)
	j := &journal{}
	r.w.Log = slog.New(slog.NewTextHandler(j, nil))
	r.start(errors.New("no disk"))
	r.settle()
	r.w.Refusals.add(r.clock(), 1234, nil)
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.String(), "refused:1") {
		t.Fatalf("the refusal did not reach the journal:\n%s", j)
	}
}

// A health record larger than the store takes is counted and journaled by kind and size, and the
// records after it are stored.
func TestOversizedHealthRecordCountedNotBlocking(t *testing.T) {
	r := newRig(t)
	j := &journal{}
	r.w.Log = slog.New(slog.NewTextHandler(j, nil))
	r.w.Started = map[string]string{"version": strings.Repeat("v", store.MaxHealthBytes)}
	r.start(nil)
	r.settle()
	r.step(statsEvery)
	r.step(0)
	stats := r.st.kinds("stats")
	if len(r.st.kinds("started")) != 0 || len(stats) != 1 || stats[0]["lost_health"] != 1.0 {
		t.Fatalf("started %v, stats %v", r.st.kinds("started"), stats)
	}
	if out := j.String(); !strings.Contains(out, "kind=started bytes=") || strings.Contains(out, "vvvv") {
		t.Fatalf("journal:\n%s", out)
	}
}

// A Close that seals and then reports an error committed the records; the summary it may not hold is
// sent again under its own note_seq.
func TestCloseSealWithErrorCommitsRecordsAndResendsSummary(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	connect(r, 77)
	r.step(0) // the connection summary is handed over
	r.st.set(func(s *fakeStore) { s.flushErr, s.closeSealErr = true, true })
	r.push(event(81, ""))
	until(t, func() bool { r.st.mu.Lock(); defer r.st.mu.Unlock(); return len(r.st.appended) == 1 })
	r.step(0) // Flush fails; Close seals both, then fails
	if l := r.last.pending[StageStore]; l.Count != 0 || len(r.st.committed) != 1 {
		t.Fatalf("sealed record counted lost %+v, committed %d", l, len(r.st.committed))
	}
	reopenAfterFailure(r)
	conns := r.st.kinds("connection")
	if len(conns) != 2 || conns[0]["note_seq"] != conns[1]["note_seq"] || conns[1]["count"] != 1.0 {
		t.Fatalf("connection records %v, want the one summary twice", conns)
	}
}

// At stop the store may still queue the 64 health records of the last tick: they are flushed first, so
// the loss record still fits.
func TestStopWithTheStoresQueueFullStoresTheLossRecord(t *testing.T) {
	r := newRig(t)
	r.start(nil)
	r.settle()
	r.st.set(func(s *fakeStore) { s.rejectNote, s.noteCap = true, 64 })
	for range 80 {
		r.step(statsEvery)
	}
	r.st.set(func(s *fakeStore) { s.rejectNote = false })
	r.step(0) // hands over 64, uncommitted
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	if lost := r.st.kinds("lost"); len(lost) != 1 || lost[0]["first_seq"] != 21.0 {
		t.Fatalf("loss records stored at stop: %v", lost)
	}
}

// A Flush that fails at stop is reported, even when the Close after it succeeds.
func TestStopFlushFailureIsReported(t *testing.T) {
	r := newRig(t)
	j := &journal{}
	r.w.Log = slog.New(slog.NewTextHandler(j, nil))
	r.start(nil)
	r.settle()
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.st.set(func(s *fakeStore) { s.flushErr = true })
	if err := stopRig(r); err == nil || !strings.Contains(j.String(), "stopped with the store down") || !strings.Contains(j.String(), "Count:1") {
		t.Fatalf("Run = %v, journal:\n%s", err, j)
	}
}

// At stop with the store up, the journal names every loss record the store did not take or Close may
// have lost, with its range.
func TestStopJournalsTheLossRecordsNotStored(t *testing.T) {
	r := newRig(t)
	j := &journal{}
	r.w.Log = slog.New(slog.NewTextHandler(j, nil))
	r.start(nil)
	r.settle()
	r.w.Losses.Add(StageQueue, rawrecord.New(0, "laurel", 21, noon, []byte("dropped")))
	r.w.Losses.Add(StageFraming, rawrecord.New(0, "laurel", 22, noon, []byte("dropped")))
	r.st.set(func(s *fakeStore) { s.noteCap, s.failClose = 1, true }) // one loss record handed over, then lost
	if err := stopRig(r); err == nil {
		t.Fatal("a failed Close at stop was not reported")
	}
	for _, field := range []string{"lost_not_stored", "lost_records"} {
		if !regexp.MustCompile(field + `="map\[(queue|framing):\[\{Count:1 Bytes:7 FirstSeq:2[12] LastSeq:2[12] `).MatchString(j.String()) {
			t.Fatalf("no loss record in %s:\n%s", field, j)
		}
	}
}
