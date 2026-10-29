package cosign_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
)

var at = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func TestOpenTakesTheWitnessTimeFromItsLine(t *testing.T) {
	f := cosigntest.New(t)
	b := f.Cosigned(t, 42, at)
	cp, err := cosign.Open(b, f.Keys)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 42 || !cp.Time.Equal(at) || !bytes.Equal(cp.Note, b) {
		t.Fatalf("got size %d time %v", cp.Size, cp.Time)
	}
}

func TestOpenRefuses(t *testing.T) {
	f := cosigntest.New(t)
	other := cosigntest.New(t)
	good := f.Cosigned(t, 42, at)
	cases := map[string]struct {
		note []byte
		keys cosign.Keys
	}{
		"ledger only":           {f.Signed(t, 42), f.Keys},
		"another witness":       {other.Cosigned(t, 42, at), cosign.Keys{Origin: f.Keys.Origin, Log: f.Keys.Log, Witness: other.Keys.Witness}},
		"another ledger":        {good, cosign.Keys{Origin: f.Keys.Origin, Log: other.Keys.Log, Witness: f.Keys.Witness}},
		"another origin":        {good, cosign.Keys{Origin: "other.test/log", Log: f.Keys.Log, Witness: f.Keys.Witness}},
		"a Pi clock in 1970":    {f.Cosigned(t, 42, time.Unix(1, 0)), f.Keys},
		"before 2026":           {f.Cosigned(t, 42, time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)), f.Keys},
		"past 2262":             {f.Cosigned(t, 42, time.Date(2262, 1, 1, 0, 0, 1, 0, time.UTC)), f.Keys},
		"a changed size":        {bytes.Replace(good, []byte("\n42\n"), []byte("\n43\n"), 1), f.Keys},
		"incomplete keys":       {good, cosign.Keys{Origin: f.Keys.Origin, Log: f.Keys.Log}},
		"over the cap":          {append(good, bytes.Repeat([]byte("x"), cosign.MaxNote)...), f.Keys},
		"empty":                 {nil, f.Keys},
		"the witness line only": {witnessOnly(t, good, f.Keys.Witness), f.Keys},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := cosign.Open(c.note, c.keys); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// witnessOnly drops the ledger's line from a cosigned note.
func witnessOnly(t *testing.T, b []byte, wv note.Verifier) []byte {
	t.Helper()
	n, err := note.Open(b, note.VerifierList(wv))
	if err != nil {
		t.Fatal(err)
	}
	var lines strings.Builder
	lines.WriteString(n.Text + "\n")
	for _, s := range n.Sigs {
		lines.WriteString("— " + s.Name + " " + s.Base64 + "\n")
	}
	return []byte(lines.String())
}

func TestReadRefusesALinkAFIFOAndAnOversizeFile(t *testing.T) {
	f := cosigntest.New(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, f.Cosigned(t, 7, at), 0o600); err != nil {
		t.Fatal(err)
	}
	if cp, err := cosign.Read(good, f.Keys); err != nil || cp.Size != 7 {
		t.Fatalf("a good file: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), cosign.MaxNote+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, fifo, big, filepath.Join(dir, "missing")} {
		if _, err := cosign.Read(p, f.Keys); err == nil {
			t.Errorf("%s accepted", filepath.Base(p))
		}
	}
}

func FuzzOpen(f *testing.F) {
	keys := cosigntest.New(f)
	f.Add(keys.Cosigned(f, 1, at))
	f.Add(keys.Signed(f, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		cp, err := cosign.Open(b, keys.Keys)
		if err != nil {
			return
		}
		if _, err := note.Open(cp.Note, note.VerifierList(keys.Keys.Log, keys.Keys.Witness)); err != nil || cp.Time.Year() < 2026 {
			t.Fatalf("accepted a note that does not verify, or a time of %v", cp.Time)
		}
	})
}
