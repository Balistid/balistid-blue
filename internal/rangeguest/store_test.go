package rangeguest

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

var testLimits = store.Limits{Cap: shard.WALMaxBytes + 4<<20, ShardMax: 1 << 20, Headroom: shard.WALMaxBytes + 4*store.LossChunk}

// fakeCollector is the collector as a store read sees it: an open store that a stop closes (Close
// seals); afterStop then plays what happens next, such as systemd starting it again for Laurel.
type fakeCollector struct {
	t         *testing.T
	dir       string
	st        *store.Store
	afterStop func(*fakeCollector)
	stops     int
	after     []rawrecord.Record // what the read handed over as after its barrier

	mu      sync.Mutex
	commits chan uint64   // while a read follows the commit line
	ended   chan struct{} // closed once the last follower ended
	quiet   bool          // no commit line: the collector never journals one
	clock   *fakeClock    // the last read's
}

func newFakeCollector(t *testing.T) *fakeCollector {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := &fakeCollector{t: t, dir: dir}
	c.open()
	return c
}

func (c *fakeCollector) open() {
	c.t.Helper()
	st, err := store.Open(c.t.Context(), c.dir, testLimits)
	if err != nil {
		c.t.Fatal(err)
	}
	c.st = st
}

// add stores Laurel lines and flushes them, so the commit line rises past them.
func (c *fakeCollector) add(lines ...string) {
	c.t.Helper()
	for i, line := range lines {
		if ok, _, err := c.st.Append(c.t.Context(), rawrecord.New(0, store.SensorProvider, uint64(i+1), time.Now().UnixNano(), []byte(line))); err != nil || !ok {
			c.t.Fatalf("append: %v, %v", ok, err)
		}
	}
	if _, err := c.st.Flush(c.t.Context()); err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.commits != nil && !c.quiet {
		select {
		case c.commits <- c.st.Committed():
		default:
		}
	}
}

func (c *fakeCollector) Follow(ctx context.Context) (<-chan uint64, error) {
	ch := make(chan uint64, 1)
	c.mu.Lock()
	c.commits = ch
	c.mu.Unlock()
	ended := make(chan struct{})
	c.ended = ended
	go func() {
		<-ctx.Done()
		c.mu.Lock()
		c.commits = nil
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond) // a follower slow to exit: Read must still wait for it
		close(ended)
		close(ch) // as the guest's does once journalctl exited
	}()
	return ch, nil
}

func (c *fakeCollector) Stop(ctx context.Context) error {
	c.stops++
	if _, err := c.st.Close(ctx); err != nil {
		return err
	}
	c.st = nil
	if c.afterStop != nil {
		c.afterStop(c)
	}
	return nil
}

func (c *fakeCollector) read(t *testing.T, mark func(string), wait time.Duration) ([]string, error) {
	t.Helper()
	var got []string
	c.clock = &fakeClock{now: time.Unix(0, 0)}
	sr := StoreRead{
		Dir: c.dir, Collector: c, Clock: c.clock, Settle: time.Second, Poll: 100 * time.Millisecond,
		Mark: func(_ context.Context, token string) error { mark(token); return nil },
	}
	err := sr.Read(t.Context(), wait, func(r rawrecord.Record) error {
		if r.Provider == store.SensorProvider {
			got = append(got, string(r.Data))
		}
		return nil
	}, func(r rawrecord.Record) error {
		c.after = append(c.after, r)
		return nil
	})
	return got, err
}

// A read returns the records stored before its barrier and none after, from sealed shards only.
func TestStoreReadEndsAtTheBarrier(t *testing.T) {
	c := newFakeCollector(t)
	c.add(execLine("balistid-n-1"), execLine("balistid-n-2"))
	got, err := c.read(t, func(token string) { c.add(execLine("balistid-n-3"), execLine(token), execLine("balistid-n-4")) }, 30*time.Second)
	want := []string{execLine("balistid-n-1"), execLine("balistid-n-2"), execLine("balistid-n-3")}
	if err != nil || fmt.Sprint(got) != fmt.Sprint(want) || c.stops != 1 {
		t.Fatalf("read = %q, %v after %d stops; want %q", got, err, c.stops, want)
	}
	select {
	case <-c.ended:
	default:
		t.Error("Read returned while its journal follower still ran")
	}
}

// What the collector stores behind the barrier, up to the end of the run the read stopped, goes to
// after: a tick's health records follow its Laurel lines, so a reconnect before the barrier can be
// stored after it.
func TestStoreReadHandsOverWhatFollowsTheBarrier(t *testing.T) {
	c := newFakeCollector(t)
	c.add(execLine("balistid-n-1"))
	got, err := c.read(t, func(token string) {
		c.add(execLine(token), execLine("balistid-n-2"))
		if err := c.st.NoteHealth([]byte(`{"schema_version":1,"kind":"connection"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.st.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}, 30*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("read = %q, %v", got, err)
	}
	var kinds []string
	for _, r := range c.after {
		kinds = append(kinds, r.Provider+" "+string(r.Data))
	}
	if len(kinds) != 2 || kinds[0] != store.SensorProvider+" "+execLine("balistid-n-2") ||
		kinds[1] != store.HealthProvider+` {"schema_version":1,"kind":"connection"}` {
		t.Fatalf("after the barrier: %q", kinds)
	}
}

// Without an after callback a read still runs to its barrier and drops what follows it; a follower
// that ends before the stop fails the read, never lets it stop early.
func TestStoreReadEdges(t *testing.T) {
	c := newFakeCollector(t)
	mark := func(token string) { c.add(execLine(token), execLine("late")) }
	sr := StoreRead{Dir: c.dir, Collector: c, Clock: &fakeClock{now: time.Unix(0, 0)}, Settle: time.Second, Poll: 100 * time.Millisecond,
		Mark: func(_ context.Context, token string) error { mark(token); return nil }}
	if err := sr.Read(t.Context(), 30*time.Second, func(rawrecord.Record) error { return nil }, nil); err != nil {
		t.Fatalf("read without an after callback: %v", err)
	}
	sr.Collector, sr.Mark = endedFollower{}, func(context.Context, string) error { return nil }
	if err := sr.Read(t.Context(), 30*time.Second, func(rawrecord.Record) error { return nil }, nil); err == nil || !strings.Contains(err.Error(), "follower ended") {
		t.Fatalf("read with an ended follower: %v", err)
	}
}

// endedFollower is a collector whose journal follower ends at once.
type endedFollower struct{}

func (endedFollower) Follow(context.Context) (<-chan uint64, error) {
	ch := make(chan uint64)
	close(ch)
	return ch, nil
}

func (endedFollower) Stop(context.Context) error { return errors.New("stopped") }

// A shard the index does not list that starts inside the sealed range is no newer run's: the read
// fails even with its barrier found.
func TestUnindexedShardBelowTheSealsRefused(t *testing.T) {
	c := newFakeCollector(t)
	c.add(execLine("balistid-n-1"), execLine("balistid-n-2"))
	c.afterStop = func(c *fakeCollector) {
		if err := os.WriteFile(filepath.Join(c.dir, fmt.Sprintf("%020d.db", 2)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.read(t, func(token string) { c.add(execLine(token)) }, 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "not above") {
		t.Fatalf("read with an unindexed shard below the seals = %v", err)
	}
}

// A store read needs a positive settle time and poll interval: zero would spin or stop before the
// commit line settled.
func TestStoreReadRefusesZeroTimings(t *testing.T) {
	for _, sr := range []StoreRead{{Settle: 0, Poll: time.Millisecond}, {Settle: time.Second, Poll: 0}} {
		if err := sr.Read(t.Context(), time.Second, func(rawrecord.Record) error { return nil }, nil); err == nil {
			t.Errorf("%+v: read ran", sr)
		}
	}
}

// A barrier the collector did not seal by the one stop is missing, never a short read, and is not
// looked for again: a second stop would lose what Laurel sent meanwhile.
func TestStoreReadWithoutItsBarrierIsMissing(t *testing.T) {
	c := newFakeCollector(t)
	c.afterStop = (*fakeCollector).open
	c.add(execLine("balistid-n-1"))
	_, err := c.read(t, func(string) { c.add(execLine("balistid-n-2")) }, 30*time.Second)
	if !errors.Is(err, ErrBarrierMissing) || c.stops != 1 {
		t.Fatalf("read = %v after %d stops, want the barrier missing after one", err, c.stops)
	}
}

// The stop comes once the commit line moved after the barrier and then stayed for Settle, not at the
// end of the wait; a collector that never journals a commit is stopped only when the wait is over.
func TestStoreReadStopsWhenTheCommitLineSettles(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		c := newFakeCollector(t)
		c.quiet = quiet
		if _, err := c.read(t, func(token string) { c.add(execLine(token)) }, 30*time.Second); err != nil {
			t.Fatal(err)
		}
		took := c.clock.now.Sub(time.Unix(0, 0))
		if quiet && took < 30*time.Second || !quiet && (took < time.Second || took > 2*time.Second) {
			t.Errorf("quiet %v: stopped after %s", quiet, took)
		}
	}
}

// The collector restarts at once after the stop and writes a shard the index does not list yet: with
// the barrier sealed below it, the read is whole (ADR 0022, point 3).
func TestBarrierRequiredWithUnindexed(t *testing.T) {
	c := newFakeCollector(t)
	c.afterStop = func(c *fakeCollector) {
		c.open()
		st := c.st
		if ok, _, err := st.Append(t.Context(), rawrecord.New(0, store.SensorProvider, 9, time.Now().UnixNano(), []byte(execLine("late")))); err != nil || !ok {
			t.Fatalf("append after restart: %v, %v", ok, err)
		}
		if _, err := st.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	c.add(execLine("balistid-n-1"))
	got, err := c.read(t, func(token string) { c.add(execLine(token)) }, 30*time.Second)
	if err != nil || len(got) != 1 {
		t.Fatalf("read with a newer run's shard beside it = %q, %v", got, err)
	}

	// Without its barrier the same layout is never whole.
	c2 := newFakeCollector(t)
	c2.afterStop = c.afterStop
	c2.add(execLine("balistid-n-1"))
	if _, err := c2.read(t, func(string) {}, 5*time.Second); !errors.Is(err, ErrBarrierMissing) {
		t.Fatalf("read without its barrier = %v, want it missing", err)
	}
}

// What ReadSeals did not index counts as a newer run's only above the barrier's seal.
func TestNewerRunOnly(t *testing.T) {
	shardAt := func(first uint64) string { return fmt.Sprintf("%020d.db", first) }
	for name, c := range map[string]struct {
		u  store.UnindexedError
		ok bool
	}{
		"nothing":                {store.UnindexedError{}, true},
		"torn line":              {store.UnindexedError{Torn: true}, true},
		"shard above":            {store.UnindexedError{Pending: []string{shardAt(11)}, Sidecars: []string{shardAt(11) + "-wal"}}, true},
		"shard at the barrier":   {store.UnindexedError{Pending: []string{shardAt(10)}}, false},
		"shard below":            {store.UnindexedError{Pending: []string{shardAt(3)}}, false},
		"sidecar without shard":  {store.UnindexedError{Sidecars: []string{shardAt(12) + "-shm"}}, false},
		"sidecar of another one": {store.UnindexedError{Pending: []string{shardAt(11)}, Sidecars: []string{shardAt(12) + "-journal"}}, false},
	} {
		if err := newerRunOnly(&c.u, 10); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A sidecar beside a sealed shard holds data no seal covers: the read fails, barrier or not.
func TestSidecarBesideSealRefused(t *testing.T) {
	c := newFakeCollector(t)
	c.add(execLine("balistid-n-1"))
	c.afterStop = func(c *fakeCollector) {
		if err := os.WriteFile(filepath.Join(c.dir, fmt.Sprintf("%020d.db-wal", 1)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := c.read(t, func(token string) { c.add(execLine(token)) }, 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "beside") {
		t.Fatalf("read with a sidecar beside a seal = %v", err)
	}
}

func TestLastCommitted(t *testing.T) {
	journal := `{"time":"t","level":"INFO","msg":"committed through","seq":7}
{"time":"t","level":"INFO","msg":"lag","seq":99}
not json
{"time":"t","level":"INFO","msg":"committed through","seq":12}
{"time":"t","level":"INFO","msg":"committed through","seq":"13"}
`
	if got := LastCommitted(journal); got != 12 {
		t.Errorf("LastCommitted = %d, want 12", got)
	}
	if got := LastCommitted(""); got != 0 {
		t.Errorf("empty journal: %d", got)
	}
}

const (
	modulePath = "github.com/Balistid/balistid-blue"
	storePath  = modulePath + "/internal/store"
)

// The guest reads the store only through ReadSeals and shard.Read: no package of the guest's build
// calls store.Open, under whatever name it imports the store, since Open writes (recovery, the
// reserve, a new shard) into the store the guest measures (ADR 0022, point 1).
func TestGuestNeverOpensStore(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), goBin, "list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \" \"}}", modulePath+"/cmd/balistid-range-guest") //nolint:gosec // the go found on PATH, fixed arguments
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	checked := 0
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		pkg, rest, _ := strings.Cut(line, "\t")
		dir, files, _ := strings.Cut(rest, "\t")
		if !strings.HasPrefix(pkg, modulePath+"/") || pkg == storePath {
			continue
		}
		for _, f := range strings.Fields(files) {
			if opensStore(t, filepath.Join(dir, f)) {
				t.Errorf("%s/%s calls store.Open", pkg, f)
			}
			checked++
		}
	}
	if checked < 10 {
		t.Fatalf("checked only %d files of the guest's build", checked)
	}
}

// opensStore reports whether the Go file at path calls Open of the store package, or dot-imports it.
func opensStore(t *testing.T, path string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, spec := range f.Imports {
		if strings.Trim(spec.Path.Value, `"`) != storePath {
			continue
		}
		switch {
		case spec.Name == nil:
			names = append(names, "store")
		case spec.Name.Name == ".":
			return true
		default:
			names = append(names, spec.Name.Name)
		}
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Open" {
			if id, ok := sel.X.(*ast.Ident); ok && slices.Contains(names, id.Name) {
				found = true
			}
		}
		return !found
	})
	return found
}

// The check finds Open under the store's own name, an alias and a dot import, and nothing in a file
// that only reads seals or opens something else.
func TestOpensStoreSeesThroughAliases(t *testing.T) {
	for body, want := range map[string]bool{
		`import "` + storePath + `"; var _, _ = store.Open`:                                true,
		`import st "` + storePath + `"; func f() { _, _ = st.Open(nil, "", st.Limits{}) }`: true,
		`import . "` + storePath + `"; var _ = Seal{}`:                                     true,
		`import "` + storePath + `"; var _ = store.ReadSeals`:                              false,
		`import "os"; var _, _ = os.Open("x")`:                                             false,
	} {
		path := filepath.Join(t.TempDir(), "x.go")
		if err := os.WriteFile(path, []byte("package x\n"+body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := opensStore(t, path); got != want {
			t.Errorf("%s: %v, want %v", body, got, want)
		}
	}
}

// CommitTime is the collector's own slog time of a line, zero for a line without one in RFC 3339.
func TestCommitTime(t *testing.T) {
	line := `{"time":"2026-10-26T19:15:01.168193215Z","level":"INFO","msg":"committed through","seq":139}`
	if got := CommitTime(line); !got.Equal(time.Date(2026, 10, 26, 19, 15, 1, 168193215, time.UTC)) {
		t.Errorf("time %v", got)
	}
	for _, bad := range []string{`{"msg":"committed through","seq":1}`, `{"time":"yesterday"}`, `{"time":1}`, `not json`} {
		if got := CommitTime(bad); !got.IsZero() {
			t.Errorf("%s: %v", bad, got)
		}
	}
}
