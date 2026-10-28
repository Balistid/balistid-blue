package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/link"
)

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

// writeLog writes a log of records 1..n in batches of three, signed by a key in dir, and returns its
// root and verifier.
func writeLog(t *testing.T, n uint64) (string, note.Verifier) {
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
