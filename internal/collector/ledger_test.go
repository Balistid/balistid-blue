package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

func leafOf(seq uint64) shard.Leaf {
	return shard.Leaf{Seq: seq, Hash: sha256.Sum256([]byte(fmt.Sprint(seq))), Provider: store.SensorProvider}
}

func TestGroupsKeepEachSealWithTheFrameEndingAtIt(t *testing.T) {
	var leaves []shard.Leaf
	for s := uint64(1); s <= 2500; s++ {
		leaves = append(leaves, leafOf(s))
	}
	seals := []store.Seal{{First: 1, Last: 1000, SHA256: sha256.Sum256([]byte("a"))}, {First: 1001, Last: 2048, SHA256: sha256.Sum256([]byte("b"))}}
	gs, err := groups(3, leaves, seals)
	if err != nil {
		t.Fatal(err)
	}
	next, sealed := uint64(1), 0
	for _, g := range gs {
		recs, ok := g.msgs[0].(link.Records)
		if !ok || len(recs) == 0 || len(recs) > link.MaxRecords || recs[0].Seq != next || g.last != recs[len(recs)-1].Seq || g.epoch != 3 {
			t.Fatalf("group %+v after %d", g, next-1)
		}
		next = g.last + 1
		if len(g.msgs) == 2 {
			if s, ok := g.msgs[1].(entry.Seal); !ok || s.Last != g.last {
				t.Fatalf("seal %+v in a group ending at %d", g.msgs[1], g.last)
			}
			sealed++
		}
	}
	if next != 2501 || sealed != 2 {
		t.Fatalf("groups end at %d with %d seals", next-1, sealed)
	}
	if _, err := groups(1, leaves[:10], seals); err == nil {
		t.Fatal("a seal past the leaves read was dropped silently")
	}
}

// lostRecord is the lost record the writer itself encodes for stage (losses).
func lostRecord(t *testing.T, stage Stage, count uint64) []byte {
	t.Helper()
	w := &Writer{st: &fakeStore{}, Now: time.Now, Log: slog.New(slog.DiscardHandler), pending: map[Stage]Loss{
		stage: {Count: count, Bytes: 10, FirstSeq: 1, LastSeq: count, FirstAt: 1, LastAt: 2}}, Losses: &Losses{}}
	w.losses(true)
	if len(w.notes) != 1 {
		t.Fatalf("%d notes", len(w.notes))
	}
	return w.notes[0].b
}

func TestLossOfEachProducer(t *testing.T) {
	storeLoss := []byte(`{"schema_version":1,"dropped":4,"first_received":1,"last_received":2}`)
	cases := []struct {
		name string
		leaf shard.Leaf
		want *entry.Loss
	}{
		{"sensor record", leafOf(9), nil},
		{"truncated sensor record", shard.Leaf{Seq: 9, Provider: store.SensorProvider, Truncated: true}, &entry.Loss{Seq: 9, Stage: entry.StageTruncated, Records: 1}},
		{"store loss record", shard.Leaf{Seq: 9, Provider: store.LossProvider, Data: storeLoss}, &entry.Loss{Seq: 9, Stage: entry.StageCap, Records: 4}},
		{"stats record", shard.Leaf{Seq: 9, Provider: store.HealthProvider, Data: []byte(`{"kind":"stats","records":5}`)}, nil},
	}
	for stage, want := range lossStages {
		cases = append(cases, struct {
			name string
			leaf shard.Leaf
			want *entry.Loss
		}{"lost " + string(stage), shard.Leaf{Seq: 9, Provider: store.HealthProvider, Data: lostRecord(t, stage, 3)}, &entry.Loss{Seq: 9, Stage: want, Records: 3}})
	}
	for _, c := range cases {
		got, err := lossOf(c.leaf)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}
}

func TestLossOfRefusesRecordsItCannotRead(t *testing.T) {
	lost := lostRecord(t, StageQueue, 3)
	for name, l := range map[string]shard.Leaf{
		"unknown provider":          {Seq: 1, Provider: "other"},
		"store loss, unknown field": {Seq: 1, Provider: store.LossProvider, Data: []byte(`{"schema_version":1,"dropped":4,"first_received":1,"last_received":2,"x":1}`)},
		"store loss, schema 2":      {Seq: 1, Provider: store.LossProvider, Data: []byte(`{"schema_version":2,"dropped":4,"first_received":1,"last_received":2}`)},
		"store loss, none dropped":  {Seq: 1, Provider: store.LossProvider, Data: []byte(`{"schema_version":1,"dropped":0,"first_received":1,"last_received":2}`)},
		"store loss, trailing":      {Seq: 1, Provider: store.LossProvider, Data: []byte(`{"schema_version":1,"dropped":4,"first_received":1,"last_received":2}{}`)},
		"lost, unknown stage":       {Seq: 1, Provider: store.HealthProvider, Data: bytes.Replace(lost, []byte(`"queue"`), []byte(`"kernel"`), 1)},
		"lost, unknown field":       {Seq: 1, Provider: store.HealthProvider, Data: bytes.Replace(lost, []byte(`"kind"`), []byte(`"extra":1,"kind"`), 1)},
		"lost, count zero":          {Seq: 1, Provider: store.HealthProvider, Data: bytes.Replace(lost, []byte(`"count":3`), []byte(`"count":0`), 1)},
		"health record not JSON":    {Seq: 1, Provider: store.HealthProvider, Data: []byte(`not json`)},
	} {
		if got, err := lossOf(l); err == nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestHealthEntryForEveryState(t *testing.T) {
	for h, want := range map[string]entry.Health{
		"OK":                          {State: entry.StateOK, Unstored: 2},
		"UNKNOWN store: starting":     {State: entry.StateUnknown, Reason: entry.ReasonStarting, Unstored: 2},
		"UNKNOWN store: store-open":   {State: entry.StateUnknown, Reason: entry.ReasonStoreDown, Unstored: 2},
		"UNKNOWN laurel-disconnected": {State: entry.StateUnknown, Reason: entry.ReasonLaurelDisconnected, Unstored: 2},
		"UNKNOWN canary-missed":       {State: entry.StateUnknown, Reason: entry.ReasonCanaryMissed, Unstored: 2},
		"UNKNOWN canary-pending":      {State: entry.StateUnknown, Reason: entry.ReasonCanaryPending, Unstored: 2},
	} {
		if got, err := healthEntry(h, 2); err != nil || got != want {
			t.Errorf("%q: %+v, %v", h, got, err)
		}
	}
	if got, err := healthEntry(streamUnknown, 3); err != nil || got != (entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStream, Unstored: 3}) {
		t.Errorf("stream stopped: %+v, %v", got, err)
	}
	if got, err := healthEntry("UNKNOWN something-new", 0); err == nil {
		t.Errorf("a state the ledger cannot take: %+v", got)
	}
}

// openStore is a real store holding records 1..n of 20 KiB, which rotate through 128 KiB shards.
func openStore(t *testing.T, n int) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), t.TempDir(), store.Limits{Cap: shard.WALMaxBytes + 4<<20, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 4*store.LossChunk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.Close(t.Context()) })
	for i := range n {
		data := bytes.Repeat([]byte{byte(i)}, 20<<10)
		if stored, _, err := st.Append(t.Context(), rawrecord.New(0, store.SensorProvider, uint64(i)+1, 1, data)); err != nil || !stored {
			t.Fatalf("append: %v %v", stored, err)
		}
	}
	if _, err := st.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return st
}

func streamWriter(st Store) (*Writer, *Ledger) {
	l := NewLedger(nil, slog.New(slog.DiscardHandler))
	return &Writer{Ledger: l, st: st, Now: time.Now, Log: slog.New(slog.DiscardHandler), health: "OK", pending: map[Stage]Loss{}}, l
}

// taken drains what the writer queued and returns the records' seqs and the seals and health in order.
func taken(l *Ledger) (seqs []uint64, others []link.Message) {
	for {
		select {
		case g := <-l.out:
			for _, m := range g.msgs {
				if recs, ok := m.(link.Records); ok {
					for _, r := range recs {
						seqs = append(seqs, r.Seq)
					}
				} else {
					others = append(others, m)
				}
			}
		default:
			return seqs, others
		}
	}
}

func rootOf(t *testing.T, st *store.Store, first, last uint64) [32]byte {
	t.Helper()
	leaves, _, err := st.Leaves(t.Context(), first-1, int(last-first+1), 1<<40) //nolint:gosec // a few test records
	if err != nil {
		t.Fatal(err)
	}
	r := entry.NewRoot()
	for _, l := range leaves {
		if err := r.Add(l.Hash); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := r.Sum()
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func TestStreamSendsNothingBeforeTheLedgerSaysWhere(t *testing.T) {
	w, l := streamWriter(openStore(t, 3))
	w.stream(t.Context())
	if seqs, others := taken(l); seqs != nil || others != nil {
		t.Fatalf("sent %v %v without a hello", seqs, others)
	}
}

func TestStreamFromAnEmptyLedger(t *testing.T) {
	st := openStore(t, 12)
	w, l := streamWriter(st)
	l.hello <- helloOf{1, link.Hello{}}
	w.stream(t.Context())
	seqs, others := taken(l)
	if uint64(len(seqs)) != st.Committed() || seqs[0] != 1 || w.sent != st.Committed() {
		t.Fatalf("sent %v, sent mark %d, committed %d", seqs, w.sent, st.Committed())
	}
	if _, ok := others[len(others)-1].(entry.Health); !ok || len(others) != 1+len(st.Seals()) { // the health goes last
		t.Fatalf("others %+v, %d seals", others, len(st.Seals()))
	}
	w.stream(t.Context()) // nothing new committed, health unchanged
	if seqs, others := taken(l); seqs != nil || others != nil {
		t.Fatalf("sent again: %v %v", seqs, others)
	}
}

func TestStreamResumesAfterTheLedgersBatch(t *testing.T) {
	st := openStore(t, 12)
	seal := st.Seals()[0]
	w, l := streamWriter(st)
	l.hello <- helloOf{2, link.Hello{Last: seal.Last, First: 2, Root: rootOf(t, st, 2, seal.Last)}}
	w.stream(t.Context())
	seqs, others := taken(l)
	if seqs[0] != seal.Last+1 || w.stopped != "" {
		t.Fatalf("resumed at %v, stopped %q", seqs[:1], w.stopped)
	}
	if fmt.Sprint(others[0]) != fmt.Sprint(sealEntry(seal)) { // the seal ending at the resume point, resent first
		t.Fatalf("others %+v", others)
	}
}

func TestStreamStopsWhenLedgerAndStoreDisagree(t *testing.T) {
	st := openStore(t, 4)
	for name, h := range map[string]link.Hello{
		"ahead of the store": {Last: st.Committed() + 1, First: 1, Root: rootOf(t, st, 1, 1)},
		"another root":       {Last: 2, First: 1, Root: rootOf(t, st, 1, 1)},
		"a huge batch":       {Last: maxBatchCheck + 1, First: 1, Root: rootOf(t, st, 1, 1)},
	} {
		w, l := streamWriter(st)
		l.hello <- helloOf{1, h}
		w.stream(t.Context())
		w.stream(t.Context())
		seqs, others := taken(l) // the ledger hears why, and never an OK first
		if want := []link.Message{entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStream}}; seqs != nil ||
			w.stopped == "" || fmt.Sprint(others) != fmt.Sprint(want) {
			t.Errorf("%s: sent %v %+v, stopped %q", name, seqs, others, w.stopped)
		}
	}
}

func TestStreamWaitsOnAFullQueueWithoutAGap(t *testing.T) {
	st := openStore(t, 12)
	w, l := streamWriter(st)
	l.hello <- helloOf{1, link.Hello{}}
	for range ledgerQueue { // no room for the records nor the health
		l.out <- group{epoch: 9}
	}
	w.stream(t.Context())
	if w.sent != 0 {
		t.Fatalf("sent mark %d with no room", w.sent)
	}
	for range ledgerQueue { // the connection takes everything queued
		<-l.out
	}
	w.stream(t.Context())
	if seqs, _ := taken(l); len(seqs) == 0 || seqs[0] != 1 || w.sent != st.Committed() {
		t.Fatalf("after room: %v, sent %d", seqs, w.sent)
	}
}

// While the store is down the ledger still hears the health (ADR 0017, point 7).
func TestStreamSendsHealthWhileTheStoreIsDown(t *testing.T) {
	w, l := streamWriter(nil)
	w.st, w.health = nil, "UNKNOWN store: store-open"
	w.pending[StageStore] = Loss{Count: 5}
	l.hello <- helloOf{1, link.Hello{}}
	w.stream(t.Context())
	if seqs, others := taken(l); seqs != nil || fmt.Sprint(others) != fmt.Sprint([]link.Message{
		entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStoreDown, Unstored: 5}}) {
		t.Fatalf("sent %v %+v", seqs, others)
	}
}

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	unixSockets(t, err)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn) //nolint:forcetypeassert // a unix socketpair
		t.Cleanup(func() { _ = c.Close() })
	}
	return conns[0], conns[1]
}

// A session passes the hello to the writer and sends only what was queued for it.
func TestSessionDropsGroupsOfAnEarlierConnection(t *testing.T) {
	collector, ledger := socketPair(t)
	l := NewLedger(func(context.Context) (*net.UnixConn, error) { return collector, nil }, slog.New(slog.DiscardHandler))
	done := make(chan error, 1)
	go func() { done <- l.session(t.Context()) }()
	if err := link.Write(ledger, link.Hello{}); err != nil {
		t.Fatal(err)
	}
	h := <-l.hello
	l.out <- group{epoch: h.epoch - 1, msgs: []link.Message{link.Records{{Seq: 7, Leaf: leafOf(7).Hash}}}}
	want := link.Records{{Seq: 1, Leaf: leafOf(1).Hash}}
	l.out <- group{epoch: h.epoch, msgs: []link.Message{want}}
	_ = ledger.SetReadDeadline(time.Now().Add(5 * time.Second))
	if m, err := link.Read(ledger); err != nil || fmt.Sprint(m) != fmt.Sprint(want) {
		t.Fatalf("ledger read %+v, %v", m, err)
	}
	_ = ledger.Close()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("session = %v", err)
	}
}

func TestDialLedgerTakesOnlyTheLedgersUID(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ledger.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	unixSockets(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // test end
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if c, err := DialLedger(sock, os.Getuid()+1)(t.Context()); err == nil {
		_ = c.Close()
		t.Fatal("dialled a socket held by another uid")
	}
	c, err := DialLedger(sock, os.Getuid())(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}

// Whatever lossOf accepts from a stored own record is a loss the ledger can log.
func FuzzLossOf(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"dropped":4,"first_received":1,"last_received":2}`), true)
	f.Add([]byte(`{"kind":"lost","stage":"queue","count":3,"bytes":1,"first_seq":1,"last_seq":3,"first_at":1,"last_at":2,"schema_version":1,"at":5,"note_seq":7}`), false)
	f.Fuzz(func(t *testing.T, data []byte, storeRecord bool) {
		provider := store.HealthProvider
		if storeRecord {
			provider = store.LossProvider
		}
		loss, err := lossOf(shard.Leaf{Seq: 5, Provider: provider, Data: data})
		if err != nil || loss == nil {
			return
		}
		if _, err := (entry.Entry{Body: *loss}).Encode(); err != nil || loss.Seq != 5 {
			t.Fatalf("lossOf(%q) = %+v, which the ledger refuses: %v", data, loss, err)
		}
	})
}

// Streaming as the writer does it, one record per tick: a shard sealed when the next record arrives ends
// at a record the ledger already has, and its seal still goes, once, before the records after it.
func TestTheLiveStreamSendsEverySealInPlace(t *testing.T) {
	st := openStore(t, 0)
	w, l := streamWriter(st)
	l.hello <- helloOf{1, link.Hello{}}
	var order []string
	for i := range 24 {
		data := bytes.Repeat([]byte{byte(i)}, 20<<10)
		if stored, _, err := st.Append(t.Context(), rawrecord.New(0, store.SensorProvider, uint64(i)+1, 1, data)); err != nil || !stored {
			t.Fatalf("append: %v %v", stored, err)
		}
		if _, err := st.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
		w.stream(t.Context())
		for drained := false; !drained; {
			select {
			case g := <-l.out:
				for _, m := range g.msgs {
					switch m := m.(type) {
					case link.Records:
						order = append(order, fmt.Sprintf("r%d-%d", m[0].Seq, m[len(m)-1].Seq))
					case entry.Seal:
						order = append(order, fmt.Sprintf("s%d", m.Last))
					}
				}
			default:
				drained = true
			}
		}
	}
	seals := st.Seals()
	if len(seals) < 3 {
		t.Fatalf("only %d shards sealed", len(seals))
	}
	got := strings.Join(order, " ")
	for _, s := range seals {
		// The seal right after the frame that ends at its last record, and once.
		if want := fmt.Sprintf("-%d s%d ", s.Last, s.Last); !strings.Contains(got+" ", want) || strings.Count(got, fmt.Sprintf("s%d ", s.Last)) > 1 {
			t.Fatalf("seal %d-%d not sent once in place: %s", s.First, s.Last, got)
		}
	}
}

// oneLeafStore reads one leaf a call, as the byte budget does when large records fill the backlog.
type oneLeafStore struct{ *store.Store }

func (s oneLeafStore) Leaves(ctx context.Context, after uint64, _ int, budget int64) ([]shard.Leaf, []store.Seal, error) {
	return s.Store.Leaves(ctx, after, 1, budget)
}

func healthOf(others []link.Message) []entry.Health {
	var out []entry.Health
	for _, m := range others {
		if h, ok := m.(entry.Health); ok {
			out = append(out, h)
		}
	}
	return out
}

// The ledger's last batch is read back over as many ticks as it takes: UNKNOWN meanwhile, then the stream
// goes on from it, and a batch that is not the store's stops the stream once it is read.
func TestStreamChecksTheResumeBatchOverTicks(t *testing.T) {
	st := openStore(t, 5)
	w, l := streamWriter(oneLeafStore{st})
	l.hello <- helloOf{1, link.Hello{Last: 3, First: 1, Root: rootOf(t, st, 1, 3)}}
	var seqs []uint64
	var health []entry.Health
	for range 4 {
		w.stream(t.Context())
		s, o := taken(l)
		seqs, health = append(seqs, s...), append(health, healthOf(o)...)
	}
	unknown := entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStream}
	if w.stopped != "" || len(seqs) == 0 || seqs[0] != 4 || len(health) != 2 || health[0] != unknown || health[1].State != entry.StateOK {
		t.Fatalf("stopped %q, records %v, health %+v", w.stopped, seqs, health)
	}
	w, l = streamWriter(oneLeafStore{st})
	l.hello <- helloOf{1, link.Hello{Last: 3, First: 1, Root: rootOf(t, st, 1, 2)}}
	for range 4 {
		w.stream(t.Context())
	}
	if seqs, _ := taken(l); seqs != nil || !strings.Contains(w.stopped, "not the store's") {
		t.Fatalf("a wrong root read over ticks: sent %v, stopped %q", seqs, w.stopped)
	}
}

// A stream fault takes precedence over every other UNKNOWN reason in what the ledger hears.
func TestStreamFaultTakesPrecedence(t *testing.T) {
	for _, h := range []string{"UNKNOWN laurel-disconnected", "UNKNOWN canary-missed", "UNKNOWN canary-pending", "UNKNOWN store: store-open"} {
		w, l := streamWriter(openStore(t, 2))
		w.health, w.stopped = h, "a stop"
		l.hello <- helloOf{1, link.Hello{}}
		w.stream(t.Context())
		if _, others := taken(l); fmt.Sprint(healthOf(others)) != fmt.Sprint([]entry.Health{{State: entry.StateUnknown, Reason: entry.ReasonStream}}) {
			t.Errorf("%s with a stopped stream: %+v", h, others)
		}
	}
}
