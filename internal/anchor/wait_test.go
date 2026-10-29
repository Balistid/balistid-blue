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
		_, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond, time.Minute)
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
			if _, err := WaitCosigned(t.Context(), relay, Wait{Dir: dir, Size: 2, Entry: c.entry}, time.Millisecond, time.Minute); err == nil {
				t.Fatal("waited it out")
			}
		})
	}
}

func TestWitnessAwayEndsTheWaitAtOnce(t *testing.T) {
	f := cosigntest.New(t)
	dir, first, second := announcedLog(t, f)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	old := time.Now().Add(-2 * time.Minute)
	stale := func(note []byte) {
		write(t, relay.Path, note)
		if err := os.Chtimes(relay.Path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	w := Wait{Dir: dir, Size: 3, Entry: shutdown.Entry} // an entry the witness never cosigned
	// The ledger holds a checkpoint of 2, the relay one of 1, written two minutes ago: away.
	stale(first)
	start := time.Now()
	if _, err := WaitCosigned(t.Context(), relay, w, time.Second, time.Minute); !errors.Is(err, ErrWitnessAway) {
		t.Fatalf("a witness behind the log: %v", err)
	}
	if _, err := WaitCosigned(t.Context(), Relay{Path: relay.Path + ".missing", Keys: f.Keys}, w, time.Second, time.Minute); !errors.Is(err, ErrWitnessAway) {
		t.Fatalf("no relay file: %v", err)
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("waited %v for a witness that is away", waited)
	}
	// An idle log: the relay's file is as old, but it holds the ledger's own size. Not away: waited on.
	stale(second)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := WaitCosigned(ctx, relay, w, 10*time.Millisecond, time.Minute); errors.Is(err, ErrWitnessAway) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("an idle log: %v", err)
	}
	for _, bad := range [][2]time.Duration{{0, time.Minute}, {time.Second, 0}} {
		if _, err := WaitCosigned(t.Context(), relay, w, bad[0], bad[1]); err == nil {
			t.Fatalf("waited with poll %v, gap %v", bad[0], bad[1])
		}
	}
}
