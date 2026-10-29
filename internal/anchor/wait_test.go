package anchor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestWaitCosignedReturnsOnceTheEntryIsCosigned(t *testing.T) {
	f := cosigntest.New(t)
	dir, first, second := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	write(t, relay.Path, first)
	w := shutdown
	w.Dir = dir
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
			if _, err := WaitCosigned(t.Context(), relay, Wait{Dir: dir, Size: 2, Entry: c.entry}, time.Millisecond); err == nil {
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
	w.Dir = dir
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a wait short of its entry: %v", err)
	}
	for _, bad := range []Wait{{Dir: dir, Size: 2}, {Size: 2, Entry: w.Entry}, {Dir: dir, Entry: w.Entry}} {
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
