package anchor

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
	"github.com/Balistid/balistid-blue/internal/entry"
)

var witnessAt = time.Date(2027, 1, 2, 12, 0, 0, 0, time.UTC)

// entrySealHash is where a seal entry's hash starts: label, zero, type, time, first and last seq.
const entrySealHash = len(entry.Label) + 1 + 1 + 8 + 8 + 8

// oldLog writes a yearly log that ends: a batch and its seal, an announcement, the final entry naming
// next, its checkpoint cosigned beside it. It returns the directory and the raw batch and seal.
func oldLog(t *testing.T, f *cosigntest.Fixture) (string, [][]byte) {
	t.Helper()
	dir, c := t.TempDir(), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, Config{Dir: dir, Signer: f.Log, CapBytes: 1 << 30, CheckpointInterval: 100 * time.Millisecond, Now: c.now})
	records(t, l, 1, 3)
	if err := l.Seal(t.Context(), entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("shard"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Announce(t.Context(), entry.AnnounceShutdown); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Final(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)
	signed, err := os.ReadFile(filepath.Join(dir, layout.CheckpointPath)) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, FinalCosignedName), f.Cosign(t, signed, witnessAt))
	return dir, rawEntries(t, dir, 4)[:2]
}

// rawEntries reads the first size entries of the log in dir as they are stored.
func rawEntries(t *testing.T, dir string, size uint64) [][]byte {
	t.Helper()
	b, err := client.GetEntryBundle(t.Context(), client.FileFetcher{Root: dir}.ReadEntryBundle, 0, size)
	if err != nil {
		t.Fatal(err)
	}
	return b.Entries
}

func nextConfig(t *testing.T, name string) Config {
	t.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Dir: t.TempDir(), Signer: s, CapBytes: 1 << 30, CheckpointInterval: 100 * time.Millisecond, Now: time.Now}
}

func TestRolloverCopiesTheTail(t *testing.T) {
	f := cosigntest.New(t)
	old, tail := oldLog(t, f)
	cfg := nextConfig(t, next)
	if err := Rollover(t.Context(), cfg, old, f.Keys); err != nil {
		t.Fatal(err)
	}
	if got := rawEntries(t, cfg.Dir, 2); !bytes.Equal(got[0], tail[0]) || !bytes.Equal(got[1], tail[1]) {
		t.Fatal("the new log does not start with the old log's batch and seal, byte for byte")
	}
	l := openLog(t, cfg)
	defer closeLog(t, l)
	if r := l.Resume(); r.Last != 3 || r.First != 1 || r.Root != rootOver(t, 1, 3) || l.size != 2 {
		t.Fatalf("resume %+v, size %d", r, l.size)
	}
	// The collector resends the seal at its resume point: logged already, not again.
	if err := l.Seal(t.Context(), entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("shard"))}); err != nil || l.size != 2 {
		t.Fatalf("resent seal: %v, size %d", err, l.size)
	}
	records(t, l, 4, 4)
}

func TestRolloverRefuses(t *testing.T) {
	f := cosigntest.New(t)
	for name, c := range map[string]struct {
		origin string
		change func(t *testing.T, old string)
		keys   func() *cosigntest.Fixture
	}{
		"another origin":    {origin: next + "x"},
		"another key":       {origin: next, keys: func() *cosigntest.Fixture { return cosigntest.New(t) }},
		"no cosigned final": {origin: next, change: func(t *testing.T, old string) { remove(t, filepath.Join(old, FinalCosignedName)) }},
		"a forged checkpoint": {origin: next, change: func(t *testing.T, old string) {
			write(t, filepath.Join(old, FinalCosignedName), f.Cosigned(t, 4, witnessAt))
		}},
		"a forged seal": {origin: next, change: func(t *testing.T, old string) {
			path := filepath.Join(old, layout.EntriesPath(0, 4))
			b, err := os.ReadFile(path) //nolint:gosec // the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			b[len(tailBundleHead(t, old))+2+entrySealHash+5] ^= 1 // inside the seal entry's hash: still a valid entry
			write(t, path, b)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			old, _ := oldLog(t, f)
			if c.change != nil {
				c.change(t, old)
			}
			keys := f.Keys
			if c.keys != nil {
				keys = c.keys().Keys
			}
			cfg := nextConfig(t, c.origin)
			if err := Rollover(t.Context(), cfg, old, keys); err == nil {
				t.Fatal("rolled over")
			}
			l := openLog(t, cfg)
			defer closeLog(t, l)
			if l.size != 0 {
				t.Fatalf("a refused rollover left %d entries", l.size)
			}
		})
	}
	t.Run("into a log with entries", func(t *testing.T) {
		old, _ := oldLog(t, f)
		cfg := nextConfig(t, next)
		l := openLog(t, cfg)
		if err := l.Health(t.Context(), entry.Health{State: entry.StateOK}); err != nil {
			t.Fatal(err)
		}
		closeLog(t, l)
		if err := Rollover(t.Context(), cfg, old, f.Keys); err == nil {
			t.Fatal("rolled over into a log with entries")
		}
	})
}

// tailBundleHead is the old log's first entry in its bundle file with its length prefix: the seal follows.
func tailBundleHead(t *testing.T, old string) []byte {
	t.Helper()
	first := rawEntries(t, old, 4)[0]
	return append([]byte{byte(len(first) >> 8), byte(len(first))}, first...) //nolint:gosec // entries are at most 256 bytes
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // the test's own directory
		t.Fatal(err)
	}
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
