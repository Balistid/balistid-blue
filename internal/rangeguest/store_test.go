package rangeguest

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
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
}

func (c *fakeCollector) Committed(context.Context) (uint64, error) {
	if c.st == nil {
		return 0, nil
	}
	return c.st.Committed(), nil
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
	sr := StoreRead{
		Dir: c.dir, Collector: c, Clock: &fakeClock{now: time.Unix(0, 0)}, Settle: time.Second, Poll: 100 * time.Millisecond,
		Mark: func(_ context.Context, token string) error { mark(token); return nil },
	}
	err := sr.Read(t.Context(), wait, func(r rawrecord.Record) error {
		if r.Provider == store.SensorProvider {
			got = append(got, string(r.Data))
		}
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
}

// A barrier the collector never stored is looked for again until the wait is over, then the read is
// missing, never a short read.
func TestStoreReadWithoutItsBarrierIsMissing(t *testing.T) {
	c := newFakeCollector(t)
	c.afterStop = (*fakeCollector).open
	c.add(execLine("balistid-n-1"))
	_, err := c.read(t, func(string) { c.add(execLine("balistid-n-2")) }, 30*time.Second)
	if !errors.Is(err, ErrBarrierMissing) || c.stops < 2 {
		t.Fatalf("read = %v after %d stops, want the barrier missing after more than one try", err, c.stops)
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

// The guest reads the store only through ReadSeals and shard.Read: it never calls store.Open, which
// writes (recovery, the reserve, a new shard) into the store it measures (ADR 0022, point 1).
func TestGuestNeverOpensStore(t *testing.T) {
	for _, dir := range []string{".", "../../cmd/balistid-range-guest"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v, %d files", dir, err, len(files))
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Open" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "store" {
						t.Errorf("%s calls store.Open", name)
					}
				}
				return true
			})
		}
	}
}
