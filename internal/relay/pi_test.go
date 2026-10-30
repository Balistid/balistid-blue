package relay

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/watch"
)

// The Pi's verifier over what this server serves from a log the ledger wrote: every entry verifies
// against the cosigned root, the log's rules hold, and the served record covers the cosigned size.
func TestPiVerifiesWhatTheRelayServes(t *testing.T) {
	f := newFixture(t)
	for range 5 {
		f.grow(t, 7)
	}
	if err := f.relay(t).Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	keys := cosign.Keys{Origin: origin, Log: f.logVer, Witness: f.witVer}
	cp, err := cosign.Read(filepath.Join(f.state, cosign.Name), keys)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	srv, err := NewServer(f.dir, state, origin)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close() //nolint:errcheck // read-only
	hs := httptest.NewServer(srv)
	defer hs.Close()
	h := watch.Head{Size: cp.Size, Root: [32]byte(cp.Root)}
	src := watch.Source{Relay: hs.URL + "/", HTTP: &http.Client{Timeout: 5 * time.Second}}
	l, found, err := watch.Advance(t.Context(), watch.Log{}, h, src.Bundle)
	if err != nil || l.Size != cp.Size || found.Broken != 0 || found.Entries != cp.Size {
		t.Fatalf("verified %d of %d, %+v, %v", l.Size, cp.Size, found, err)
	}
	// the record grows just after the answer left, as the announce client's poll allows for
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		n, err := cosign.ReadServed(filepath.Join(state, cosign.ServedName), origin)
		if err == nil && n >= cp.Size {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("served %d of %d, %v", n, cp.Size, err)
		}
	}
}
