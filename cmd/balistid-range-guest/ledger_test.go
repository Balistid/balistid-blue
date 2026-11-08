package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/rangevm"
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

// A store trial's unknown alert is attributed by the ledger's stamps: an UNKNOWN logged within LossAlarm before
// the injection makes it "before N", else the first UNKNOWN from the injection on names it (ADR 0039, point 3); an
// UNKNOWN the Pi does not alert as unknown, as a pending canary, names neither.
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
	// batch 1-3, the store's UNKNOWN, the injection, auditstat's UNKNOWN
	root, v := writeLog(t, 3, health(entry.ReasonStoreDown), mark, health(entry.ReasonCanaryPending), health(entry.ReasonAuditStale),
		health(entry.ReasonCanaryPending))
	later := time.Now().Add(time.Hour).UnixNano()
	for from, want := range map[int64]string{fromNs: "before 2", 1: "2", later: "none",
		fromNs + rangevm.LossAlarm.Nanoseconds(): "before 8"} {
		if got := firstUnknownIn(t.Context(), root, v, from); got != want {
			t.Errorf("from %d: %q, want %q", from, got, want)
		}
	}
}

// A transient kernel trial's health after the resume is the health in force a window after it, by the ledger's
// stamps: OK then gives the ms from the resume to the start of that OK, "0" when it began before; anything else,
// an OK that fell to UNKNOWN after the resume among them, is "none" (ADR 0039, point 5).
func TestOKAfterResumeByTheLedgersTime(t *testing.T) {
	health := func(s entry.State, r entry.Reason) func(*anchor.Log) {
		return func(l *anchor.Log) {
			if err := l.Health(t.Context(), entry.Health{State: s, Reason: r}); err != nil {
				t.Fatal(err)
			}
		}
	}
	var resumeNs int64
	mark := func(*anchor.Log) { time.Sleep(time.Millisecond); resumeNs = time.Now().UnixNano() }
	hour := time.Hour.Nanoseconds()
	// batch 1-3, UNKNOWN, the resume, UNKNOWN, OK
	root, v := writeLog(t, 3, health(entry.StateUnknown, entry.ReasonCanaryMissed), mark,
		health(entry.StateUnknown, entry.ReasonAuditd), health(entry.StateOK, entry.ReasonNone))
	got := okAfterIn(t.Context(), root, v, resumeNs, hour)
	if ms, err := strconv.ParseInt(got, 10, 64); err != nil || ms < 0 || ms > 60_000 {
		t.Errorf("after the resume: %q", got)
	}
	if got := okAfterIn(t.Context(), root, v, resumeNs, 0); got != "none" {
		t.Errorf("with the window closed at the resume: %q, want none", got)
	}
	// OK, the resume, UNKNOWN that never clears
	fell, v := writeLog(t, 3, health(entry.StateOK, entry.ReasonNone), mark, health(entry.StateUnknown, entry.ReasonAuditStale))
	if got := okAfterIn(t.Context(), fell, v, resumeNs, hour); got != "none" {
		t.Errorf("OK before the resume, UNKNOWN after: %q, want none", got)
	}
	steady, v := writeLog(t, 3, health(entry.StateOK, entry.ReasonNone), mark)
	if got := okAfterIn(t.Context(), steady, v, resumeNs, hour); got != "0" {
		t.Errorf("OK throughout: %q, want 0", got)
	}
}

// bundle0 is the raw entries of the log's bundle 0 at its partial width n.
func bundle0(t *testing.T, root string, n uint8) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, layout.EntriesPath(0, n))) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	var eb api.EntryBundle
	if err := eb.UnmarshalText(b); err != nil {
		t.Fatal(err)
	}
	return eb.Entries
}

// writeBundle writes entries as root's bundle 0 at width n, 0 for the full one.
func writeBundle(t *testing.T, root string, n uint8, entries ...[]byte) {
	t.Helper()
	var b []byte
	for _, e := range entries {
		b = append(append(b, byte(len(e)>>8), byte(len(e))), e...) //nolint:gosec // test entries fit in 16 bits
	}
	path := filepath.Join(root, layout.EntriesPath(0, n))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// signCheckpoint replaces root's checkpoint with one for size and hash under a new key of the ledger's
// origin, and returns that key's verifier.
func signCheckpoint(t *testing.T, root string, size uint64, hash []byte) note.Verifier {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, ledgerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := note.Sign(&note.Note{Text: fmt.Sprintf("%s\n%d\n%s\n", ledgerOrigin, size, base64.StdEncoding.EncodeToString(hash))}, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, layout.CheckpointPath), cp, 0o600); err != nil {
		t.Fatal(err)
	}
	return v
}

// indices is what eachEntry hands out of the log at root: the indices and batch ends of its entries.
func indices(t *testing.T, root string, v note.Verifier) (uint64, []uint64, []uint64, error) {
	t.Helper()
	var at, last []uint64
	size, err := eachEntry(t.Context(), root, v, func(i uint64, e entry.Entry) {
		at = append(at, i)
		if b, ok := e.Body.(entry.Batch); ok {
			last = append(last, b.Last)
		}
	})
	return size, at, last, err
}

// An entry changed on disk but still decodable is refused by every reader of the log: the bundle no longer
// hashes to the signed root.
func TestLogReadersRefuseAnEntryOutsideTheSignedRoot(t *testing.T) {
	root, v := writeLog(t, 6) // batches 1-3 and 4-6
	path := filepath.Join(root, layout.EntriesPath(0, 2))
	b, err := os.ReadFile(path) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	// The last byte is inside the last batch's root: the entry still decodes.
	b[len(b)-1] ^= 1
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // the test's own directory
		t.Fatal(err)
	}
	const want = "the bundles do not hash to the checkpoint's root at 2 entries"
	if size, at, _, err := indices(t, root, v); err == nil || err.Error() != want || size != 0 || at != nil {
		t.Errorf("eachEntry: size %d, entries %v, %v", size, at, err)
	}
	if last, err := ledgerBatches(t.Context(), root, v); err == nil || err.Error() != want || last != 0 {
		t.Errorf("ledgerBatches: %d, %v", last, err)
	}
	if at, err := lastAnnouncement(t.Context(), root, v, entry.AnnounceShutdown); err == nil || err.Error() != want || at != 0 {
		t.Errorf("lastAnnouncement: %d, %v", at, err)
	}
	if got := okAfterIn(t.Context(), root, v, 0, time.Hour.Nanoseconds()); got != "error: "+want {
		t.Errorf("okAfterIn: %q", got)
	}
	if got := firstUnknownIn(t.Context(), root, v, 0); got != "error: "+want {
		t.Errorf("firstUnknownIn: %q", got)
	}
	if g, n := anchorGapsIn(t.Context(), root, v, 0, time.Now().UnixNano()); g != "error: "+want || n != g {
		t.Errorf("anchorGapsIn: %q, %q", g, n)
	}
	if l, err := ledgerLossesIn(t.Context(), root, v, 0); err == nil || err.Error() != want || l != (truncLosses{}) {
		t.Errorf("ledgerLossesIn: %+v, %v", l, err)
	}
}

// A bundle holding more entries than the checkpoint, as a partial file or as the full bundle a reader falls back
// to, yields exactly the checkpoint's entries, which hash to its root.
func TestEachEntryStopsAtTheSignedSize(t *testing.T) {
	for name, n := range map[string]uint8{"a partial bundle past the size": 2, "only the full bundle": 0} {
		t.Run(name, func(t *testing.T) {
			root, _ := writeLog(t, 9) // batches 1-3, 4-6 and 7-9
			raw := bundle0(t, root, 3)
			writeBundle(t, root, n, raw...)
			if n == 0 {
				if err := os.Remove(filepath.Join(root, layout.EntriesPath(0, 2))); err != nil && !errors.Is(err, fs.ErrNotExist) {
					t.Fatal(err)
				}
			}
			h := rfc6962.DefaultHasher
			v := signCheckpoint(t, root, 2, h.HashChildren(h.HashLeaf(raw[0]), h.HashLeaf(raw[1])))
			size, at, last, err := indices(t, root, v)
			if err != nil || size != 2 || !slices.Equal(at, []uint64{0, 1}) || !slices.Equal(last, []uint64{3, 6}) {
				t.Errorf("size %d, entries %v, batches ending %v, %v; want 2, [0 1], [3 6]", size, at, last, err)
			}
			if last, err := ledgerBatches(t.Context(), root, v); err != nil || last != 6 {
				t.Errorf("ledgerBatches: %d, %v; want 6", last, err)
			}
		})
	}
}

// A bundle with fewer entries than the checkpoint needs is an error, not a shorter log.
func TestEachEntryRefusesAShortBundle(t *testing.T) {
	root, _ := writeLog(t, 6) // batches 1-3 and 4-6
	writeBundle(t, root, 3, bundle0(t, root, 2)...)
	v := signCheckpoint(t, root, 3, make([]byte, 32))
	if size, at, _, err := indices(t, root, v); err == nil || err.Error() != "bundle 0 holds 2 entries, want 3" || at != nil {
		t.Errorf("size %d, entries %v, %v", size, at, err)
	}
}

// A bundle file is read up to a full bundle of the largest entries, and refused one byte past it.
func TestEachEntryCapsABundleFile(t *testing.T) {
	for _, extra := range []int{0, 1} {
		root, v := writeLog(t, 6) // batches 1-3 and 4-6
		raw := bundle0(t, root, 2)
		rest := ledgerBundleBytes - 2 - len(raw[0]) - 2 - len(raw[1]) + extra
		writeBundle(t, root, 2, raw[0], raw[1], make([]byte, rest/2-2), make([]byte, rest-rest/2-2))
		if st, err := os.Stat(filepath.Join(root, layout.EntriesPath(0, 2))); err != nil || st.Size() != int64(ledgerBundleBytes+extra) {
			t.Fatalf("bundle file: %v, %v", st, err)
		}
		size, _, last, err := indices(t, root, v)
		switch extra {
		case 0:
			if err != nil || size != 2 || !slices.Equal(last, []uint64{3, 6}) {
				t.Errorf("at the cap: size %d, batches ending %v, %v", size, last, err)
			}
		default:
			want := fmt.Sprintf("bundle 0: failed to fetch bundle at index 0: %s is over %d bytes", layout.EntriesPath(0, 2), 66048)
			if err == nil || err.Error() != want {
				t.Errorf("past the cap: %v, want %s", err, want)
			}
		}
	}
}

// A log signed empty has no entries under the empty root, and none under any other.
func TestEachEntryOfAnEmptyLog(t *testing.T) {
	empty := sha256.Sum256(nil)
	root := t.TempDir()
	v := signCheckpoint(t, root, 0, empty[:])
	if size, at, _, err := indices(t, root, v); err != nil || size != 0 || at != nil {
		t.Errorf("empty log: size %d, entries %v, %v", size, at, err)
	}
	if at, err := lastAnnouncement(t.Context(), root, v, entry.AnnounceShutdown); !errors.Is(err, errNoAnnouncement) ||
		err.Error() != "no announcement in 0 entries of kind 1" {
		t.Errorf("lastAnnouncement: %d, %v", at, err)
	}
	other := sha256.Sum256([]byte{0})
	v = signCheckpoint(t, root, 0, other[:])
	if size, _, _, err := indices(t, root, v); err == nil || err.Error() != "the bundles do not hash to the checkpoint's root at 0 entries" {
		t.Errorf("empty log under another root: size %d, %v", size, err)
	}
}

// A batch that does not start after the one before is an error naming the first such batch.
func TestLedgerBatchesRefuseAGap(t *testing.T) {
	root := t.TempDir()
	var raw [][]byte
	for _, b := range []entry.Batch{{First: 1, Last: 3, Root: [32]byte{1}}, {First: 5, Last: 6, Root: [32]byte{1}}, {First: 8, Last: 9, Root: [32]byte{1}}} {
		e, err := entry.Entry{At: 1, Body: b}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, e)
	}
	writeBundle(t, root, 3, raw...)
	h := rfc6962.DefaultHasher
	v := signCheckpoint(t, root, 3, h.HashChildren(h.HashChildren(h.HashLeaf(raw[0]), h.HashLeaf(raw[1])), h.HashLeaf(raw[2])))
	if size, at, _, err := indices(t, root, v); err != nil || size != 3 || !slices.Equal(at, []uint64{0, 1, 2}) {
		t.Fatalf("size %d, entries %v, %v", size, at, err)
	}
	if last, err := ledgerBatches(t.Context(), root, v); err == nil || err.Error() != "batch 5-6 after 3" || last != 0 {
		t.Errorf("ledgerBatches: %d, %v", last, err)
	}
}

// A log directory that is not there is an error before any checkpoint is read.
func TestEachEntryWithoutTheDirectory(t *testing.T) {
	_, v := writeLog(t, 1)
	missing := filepath.Join(t.TempDir(), "log")
	if size, _, _, err := indices(t, missing, v); !errors.Is(err, fs.ErrNotExist) || err.Error() != "checkpoint: open "+missing+": no such file or directory" {
		t.Errorf("size %d, %v", size, err)
	}
}
