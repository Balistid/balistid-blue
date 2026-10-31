package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
)

// The key units run under UMask=0077: the public halves must still be readable by the relay's uid.
func TestKeyFilesKeepTheirModeUnderTheUnitsUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "etc")
	env := filepath.Join(t.TempDir(), "range", "witness.env")
	if err := ledgerKey(dir); err != nil {
		t.Fatal(err)
	}
	if err := witnessKey(dir, env); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		dir: 0o755, filepath.Dir(env): 0o755, // the relay's uid must reach the public keys
		filepath.Join(dir, "ledger-key"): 0o600, filepath.Join(dir, "ledger-key.pub"): 0o644,
		filepath.Join(dir, "witness-key"): 0o600, filepath.Join(dir, "witness.vkey"): 0o644, env: 0o644,
	} {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v, %v; want %v", filepath.Base(path), st.Mode().Perm(), err, want)
		}
	}
}

func TestLedgerKeyWritesAPairOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	if err := ledgerKey(dir); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, "ledger-key")); err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private key: %v, %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ledger-key.pub")); err != nil {
		t.Fatal(err)
	}
	if err := ledgerKey(dir); err == nil {
		t.Fatal("a second key replaced the first")
	}
}

// writeLog writes a log of records 1..n in batches of three, signed by a key in dir, then calls each of
// then on it, and returns its root and verifier.
func writeLog(t *testing.T, n uint64, then ...func(*anchor.Log)) (string, note.Verifier) {
	t.Helper()
	keys := t.TempDir()
	if err := ledgerKey(keys); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(keys, name)) //nolint:gosec // the test's own files
		if err != nil {
			t.Fatal(err)
		}
		return string(b[:len(b)-1])
	}
	s, err := note.NewSigner(read("ledger-key"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(read("ledger-key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	l, err := anchor.Open(t.Context(), anchor.Config{Dir: root, Signer: s, CapBytes: 1 << 30,
		CheckpointInterval: 100 * time.Millisecond, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= n; seq++ {
		if err := l.Record(t.Context(), link.Record{Seq: seq, Leaf: sha256.Sum256([]byte(strconv.FormatUint(seq, 10)))}); err != nil {
			t.Fatal(err)
		}
		if seq%3 == 0 {
			if err := l.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, f := range then {
		f(l)
	}
	if err := l.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	return root, v
}

func TestLedgerBatchesOfASoundLog(t *testing.T) {
	root, v := writeLog(t, 8)
	if last, err := ledgerBatches(t.Context(), root, v); err != nil || last != 8 {
		t.Fatalf("batches end at %d, %v", last, err)
	}
}

func TestLedgerBatchesRefuseAnotherKeyAndNoLog(t *testing.T) {
	root, _ := writeLog(t, 3)
	_, other := writeLog(t, 1)
	if last, err := ledgerBatches(t.Context(), root, other); err == nil {
		t.Fatalf("checkpoint of another key accepted, batches end at %d", last)
	}
	if last, err := ledgerBatches(t.Context(), t.TempDir(), other); err == nil {
		t.Fatalf("an empty directory read as a log through %d", last)
	}
}

func TestLastAnnouncementIsTheNewestOfItsKind(t *testing.T) {
	announce := func(k entry.Announcement) func(*anchor.Log) {
		return func(l *anchor.Log) {
			if _, err := l.Announce(t.Context(), k); err != nil {
				t.Fatal(err)
			}
		}
	}
	// batches 1-3 and 4-5 (entries 0, 1), then shutdown, suspend, shutdown (2, 3, 4)
	root, v := writeLog(t, 5, announce(entry.AnnounceShutdown), announce(entry.AnnounceSuspend), announce(entry.AnnounceShutdown))
	for kind, want := range map[entry.Announcement]uint64{entry.AnnounceShutdown: 4, entry.AnnounceSuspend: 3} {
		if at, err := lastAnnouncement(t.Context(), root, v, kind); err != nil || at != want {
			t.Errorf("announcement %d at %d, %v; want %d", kind, at, err, want)
		}
	}
	plain, v := writeLog(t, 2)
	if at, err := lastAnnouncement(t.Context(), plain, v, entry.AnnounceShutdown); err == nil {
		t.Fatalf("an announcement found at %d in a log without one", at)
	}
}

// A store trial's first UNKNOWN after the checkpoint index is the store's only when the ledger logged it after the
// injection began; one logged before is "before N", which the judge does not attribute (ADR 0039, point 3).
func TestFirstUnknownByTheLedgersTime(t *testing.T) {
	health := func(r entry.Reason) func(*anchor.Log) {
		return func(l *anchor.Log) {
			if err := l.Health(t.Context(), entry.Health{State: entry.StateUnknown, Reason: r}); err != nil {
				t.Fatal(err)
			}
		}
	}
	var fromNs int64
	mark := func(*anchor.Log) { time.Sleep(time.Millisecond); fromNs = time.Now().UnixNano() }
	// batch 1-3 (entry 0), the store's UNKNOWN (1), the injection, auditstat's (2)
	root, v := writeLog(t, 3, health(entry.ReasonStoreDown), mark, health(entry.ReasonAuditStale))
	for _, c := range []struct {
		base, from int64
		want       string
	}{
		{0, fromNs, "before 2"}, {1, fromNs, "8"}, {0, 0, "2"}, {2, fromNs, "none"},
	} {
		if got := firstUnknownIn(t.Context(), root, v, c.base, c.from); got != c.want {
			t.Errorf("after %d from %d: %q, want %q", c.base, c.from, got, c.want)
		}
	}
}
