// Package cosigntest makes cosigned checkpoints for tests: a ledger key, and a witness whose
// cosignature/v1 carries the time a test picks.
package cosigntest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/cosign"
)

// Origin is the log's origin in tests.
const Origin = "balistid.test/log"

// Fixture holds a ledger key and a witness key.
type Fixture struct {
	Keys    cosign.Keys
	Log     note.Signer
	witness ed25519.PrivateKey
	name    string
	hash    uint32
}

// New makes fresh keys.
func New(t testing.TB) *Fixture {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, Origin)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	lv, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const name = "witness.test/w1"
	wkey, err := note.NewEd25519VerifierKey(name, pub)
	if err != nil {
		t.Fatal(err)
	}
	wv, err := fnote.NewVerifierForCosignatureV1(wkey)
	if err != nil {
		t.Fatal(err)
	}
	return &Fixture{Keys: cosign.Keys{Origin: Origin, Log: lv, Witness: wv}, Log: ls, witness: priv, name: name, hash: wv.KeyHash()}
}

// Signed is the ledger's checkpoint of size with a root derived from it.
func (f *Fixture) Signed(t testing.TB, size uint64) []byte {
	t.Helper()
	root := make([]byte, 32)
	binary.BigEndian.PutUint64(root, size)
	b, err := note.Sign(&note.Note{Text: string(log.Checkpoint{Origin: Origin, Size: size, Hash: root}.Marshal())}, f.Log)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Cosigned is the ledger's checkpoint of size cosigned by the witness at at.
func (f *Fixture) Cosigned(t testing.TB, size uint64, at time.Time) []byte {
	t.Helper()
	return f.Cosign(t, f.Signed(t, size), at)
}

// Cosign is a checkpoint the fixture's ledger key signed, cosigned by the witness at at.
func (f *Fixture) Cosign(t testing.TB, signed []byte, at time.Time) []byte {
	t.Helper()
	n, err := note.Open(signed, note.VerifierList(f.Keys.Log))
	if err != nil {
		t.Fatal(err)
	}
	b, err := note.Sign(&note.Note{Text: n.Text, Sigs: n.Sigs}, witnessAt{f, uint64(at.Unix())}) //nolint:gosec // test times are after 1970
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// witnessAt signs cosignature/v1 at a fixed time (c2sp.org/tlog-cosignature).
type witnessAt struct {
	f *Fixture
	t uint64
}

func (w witnessAt) Name() string    { return w.f.name }
func (w witnessAt) KeyHash() uint32 { return w.f.hash }
func (w witnessAt) Sign(msg []byte) ([]byte, error) {
	m := fmt.Appendf(nil, "cosignature/v1\ntime %d\n%s", w.t, msg)
	return append(binary.BigEndian.AppendUint64(nil, w.t), ed25519.Sign(w.f.witness, m)...), nil
}
