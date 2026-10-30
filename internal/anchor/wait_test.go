package anchor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
	"github.com/Balistid/balistid-blue/internal/entry"
)

// announcedLog writes a log signed by f's ledger key: a batch (size 1, whose checkpoint it returns
// cosigned), then a shutdown announcement (size 2, cosigned too).
func announcedLog(t *testing.T, f *cosigntest.Fixture) (dir string, first, second []byte) {
	t.Helper()
	dir, c := t.TempDir(), &clock{t: time.Unix(1e9, 0)}
	cfg := Config{Dir: dir, Signer: f.Log, CapBytes: 1 << 30, CheckpointInterval: 100 * time.Millisecond, Now: c.now}
	cosigned := func() []byte {
		signed, err := os.ReadFile(filepath.Join(dir, layout.CheckpointPath)) //nolint:gosec // the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		return f.Cosign(t, signed, witnessAt)
	}
	l := openLog(t, cfg)
	records(t, l, 1, 2)
	closeLog(t, l)
	first = cosigned()
	l = openLog(t, cfg)
	if size, err := l.Announce(t.Context(), entry.AnnounceShutdown); err != nil || size != 2 {
		t.Fatalf("announce: size %d, %v", size, err)
	}
	closeLog(t, l)
	return dir, first, cosigned()
}

var shutdown = Wait{Size: 2, Entry: entry.Announce{Kind: entry.AnnounceShutdown}}

// writeServed writes the relay's served record of origin at path.
func writeServed(t *testing.T, path, origin string, entries uint64) {
	t.Helper()
	write(t, path, cosign.AppendServed(nil, origin, entries))
}

func TestWaitCosignedReturnsOnceTheEntryIsCosigned(t *testing.T) {
	f := cosigntest.New(t)
	dir, first, second := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	write(t, relay.Path, first)
	w := shutdown
	w.Dir, w.Served = dir, filepath.Join(filepath.Dir(relay.Path), cosign.ServedName)
	writeServed(t, w.Served, f.Keys.Origin, 2)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("returned on a checkpoint short of the announcement: %v", err)
	default:
	}
	write(t, relay.Path, second)
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
}

// Size alone proves nothing: the entry must be in the cosigned tree and be the one asked for.
func TestWaitCosignedProvesTheEntry(t *testing.T) {
	f := cosigntest.New(t)
	dir, _, second := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	for name, c := range map[string]struct {
		note  []byte
		entry entry.Body
	}{
		"another kind":     {second, entry.Announce{Kind: entry.AnnounceSuspend}},
		"a final":          {second, entry.Final{NextOrigin: next}},
		"another tree":     {f.Cosigned(t, 2, witnessAt), shutdown.Entry}, // same size, another root
		"a larger replica": {f.Cosigned(t, 3, witnessAt), shutdown.Entry},
	} {
		t.Run(name, func(t *testing.T) {
			write(t, relay.Path, c.note)
			w := Wait{Dir: dir, Size: 2, Entry: c.entry, Served: filepath.Join(t.TempDir(), cosign.ServedName)}
			writeServed(t, w.Served, f.Keys.Origin, 3)
			if _, err := WaitCosigned(t.Context(), relay, w, time.Millisecond); err == nil {
				t.Fatal("waited it out")
			}
		})
	}
}

// The wait ends only with its context: a relay file however old is read until then.
func TestWaitCosignedEndsWithItsContext(t *testing.T) {
	f := cosigntest.New(t)
	dir, first, _ := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	write(t, relay.Path, first)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(relay.Path, old, old); err != nil {
		t.Fatal(err)
	}
	w := shutdown
	w.Dir, w.Served = dir, filepath.Join(t.TempDir(), cosign.ServedName)
	writeServed(t, w.Served, f.Keys.Origin, 2)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a wait short of its entry: %v", err)
	}
	for _, bad := range []Wait{{Dir: dir, Size: 2, Served: w.Served}, {Size: 2, Entry: w.Entry, Served: w.Served},
		{Dir: dir, Entry: w.Entry, Served: w.Served}, {Dir: dir, Size: 2, Entry: w.Entry}} {
		if _, err := WaitCosigned(t.Context(), relay, bad, time.Millisecond); err == nil {
			t.Fatalf("waited for %+v", bad)
		}
	}
	if _, err := WaitCosigned(t.Context(), relay, w, 0); err == nil {
		t.Fatal("waited with no poll")
	}
}

// A log that grew past a cosigned checkpoint may keep only its full bundle and tiles: an entry of the older
// checkpoint is still proven from them. Here the log of 3 entries plays the full one: its partial files are
// moved to the full paths and the older checkpoint's partial files removed, as Tessera's cleanup leaves them.
func TestAnEntryIsProvenAfterItsPartialBundleIsGone(t *testing.T) {
	f := cosigntest.New(t)
	dir, _, second := announcedLog(t, f)
	c := &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, Config{Dir: dir, Signer: f.Log, CapBytes: 1 << 30, CheckpointInterval: 100 * time.Millisecond, Now: c.now})
	if _, err := l.Announce(t.Context(), entry.AnnounceSuspend); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)
	for _, path := range []func(uint8) string{
		func(p uint8) string { return layout.EntriesPath(0, p) },
		func(p uint8) string { return layout.TilePath(0, 0, p) },
	} {
		if err := os.Rename(filepath.Join(dir, path(3)), filepath.Join(dir, path(0))); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, path(2))); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	cp, err := cosign.Open(second, f.Keys)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := cosign.ProvenEntry(t.Context(), dir, cp, 1); err != nil || e.Body != shutdown.Entry {
		t.Fatalf("entry 1 of the older checkpoint: %+v, %v", e.Body, err)
	}
}

// Cosigned is not enough: the announcement is waited on until the relay served its bundle to the Pi
// (ADR 0030, point 4), and a record of another origin, as before a rollover, serves nothing.
func TestWaitCosignedWaitsForServed(t *testing.T) {
	f := cosigntest.New(t)
	dir, _, second := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	write(t, relay.Path, second)
	w := shutdown
	w.Dir, w.Served = dir, filepath.Join(filepath.Dir(relay.Path), cosign.ServedName)
	writeServed(t, w.Served, f.Keys.Origin, 1)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		_, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond)
		done <- err
	}()
	for _, step := range []func(){func() { writeServed(t, w.Served, "other/log", 9) }, func() {}} {
		step()
		time.Sleep(100 * time.Millisecond)
		select {
		case err := <-done:
			t.Fatalf("returned before the bundle was served: %v", err)
		default:
		}
	}
	writeServed(t, w.Served, f.Keys.Origin, 2)
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestWaitUnservedTimesOut(t *testing.T) {
	f := cosigntest.New(t)
	dir, _, second := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	write(t, relay.Path, second)
	w := shutdown
	w.Dir, w.Served = dir, filepath.Join(filepath.Dir(relay.Path), cosign.ServedName)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "size 2 not served to the Pi") {
		t.Fatalf("an unserved wait: %v", err)
	}
}

// The Pi's verified root at an earlier size is proven against a later cosigned checkpoint from the
// log's tiles (pi_verified, ADR 0031); another root, or a size past it, is refused.
func TestProvenConsistentWithAnEarlierRoot(t *testing.T) {
	f := cosigntest.New(t)
	dir, first, second := announcedLog(t, f)
	one, err := cosign.Open(first, f.Keys)
	if err != nil {
		t.Fatal(err)
	}
	two, err := cosign.Open(second, f.Keys)
	if err != nil {
		t.Fatal(err)
	}
	p, err := cosign.OpenProven(t.Context(), dir, two)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close() //nolint:errcheck // read-only
	if err := errors.Join(p.Consistent(t.Context(), 1, one.Root), p.Consistent(t.Context(), 2, two.Root)); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{7}, 32)
	for name, err := range map[string]error{"another root": p.Consistent(t.Context(), 1, other),
		"another root at the size": p.Consistent(t.Context(), 2, one.Root), "past it": p.Consistent(t.Context(), 3, two.Root),
		"nothing": p.Consistent(t.Context(), 0, nil)} {
		if err == nil {
			t.Errorf("%s: consistent", name)
		}
	}
}
