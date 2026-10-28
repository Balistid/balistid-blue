package relay

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/link"
)

const origin = "balistid.test/log"

// witness is an in-process c2sp.org/tlog-witness add-checkpoint endpoint: it checks the log's
// signature, the old size and the consistency proof, then cosigns and persists, all under one lock.
type witness struct {
	mu       sync.Mutex
	logKey   note.Verifier
	signer   note.Signer
	size     uint64
	hash     []byte
	status   int // when set, every request gets it
	requests []string
}

func (w *witness) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	body, _ := io.ReadAll(req.Body)
	w.requests = append(w.requests, string(body))
	if w.status != 0 {
		rw.WriteHeader(w.status)
		return
	}
	r := bufio.NewReader(bytes.NewReader(body))
	line, _ := r.ReadString('\n')
	old, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(line, "old "), "\n"), 10, 64)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	var hashes [][]byte
	for {
		l, _ := r.ReadString('\n')
		if l == "\n" || l == "" {
			break
		}
		h, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(l, "\n"))
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}
		hashes = append(hashes, h)
	}
	raw, _ := io.ReadAll(r)
	n, err := note.Open(raw, note.VerifierList(w.logKey))
	if err != nil {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	var cp log.Checkpoint
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	switch {
	case old > cp.Size:
		rw.WriteHeader(http.StatusBadRequest)
		return
	case old != w.size:
		rw.Header().Set("Content-Type", "text/x.tlog.size")
		rw.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(rw, "%d\n", w.size)
		return
	case old == 0 && len(hashes) > 0,
		old == cp.Size && !bytes.Equal(w.hash, cp.Hash),
		old != 0 && old != cp.Size && proof.VerifyConsistency(rfc6962.DefaultHasher, old, cp.Size, hashes, w.hash, cp.Hash) != nil:
		rw.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	signed, err := note.Sign(&note.Note{Text: n.Text}, w.signer)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.size, w.hash = cp.Size, cp.Hash
	_, _ = rw.Write(signed[len(n.Text)+1:])
}

type fixture struct {
	dir, state string
	logKey     note.Signer
	logVer     note.Verifier
	wit        *witness
	witVer     note.Verifier
	srv        *httptest.Server
	next       uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ls, lv := keyPair(t, origin, false)
	ws, wv := keyPair(t, "witness.test/w1", true)
	f := &fixture{dir: t.TempDir(), state: t.TempDir(), logKey: ls, logVer: lv, witVer: wv, next: 1}
	f.wit = &witness{logKey: lv, signer: ws}
	f.srv = httptest.NewServer(f.wit)
	t.Cleanup(f.srv.Close)
	return f
}

func keyPair(t testing.TB, name string, cosig bool) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	if cosig {
		s, err := fnote.NewSignerForCosignatureV1(skey)
		if err != nil {
			t.Fatal(err)
		}
		v, err := fnote.NewVerifierForCosignatureV1(vkey)
		if err != nil {
			t.Fatal(err)
		}
		return s, v
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

// grow logs n more records and closes the log, which publishes its checkpoint.
func (f *fixture) grow(t *testing.T, n uint64) {
	t.Helper()
	l, err := anchor.Open(t.Context(), anchor.Config{Dir: f.dir, Signer: f.logKey, CapBytes: 1 << 30,
		CheckpointInterval: 100 * time.Millisecond, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	for end := f.next + n; f.next < end; f.next++ {
		if err := l.Record(t.Context(), link.Record{Seq: f.next, Leaf: sha256.Sum256([]byte(strconv.FormatUint(f.next, 10)))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) config() Config {
	return Config{Log: f.dir, State: f.state, Origin: origin, LogKey: f.logVer, Witness: f.witVer,
		Submit: f.srv.URL + "/add-checkpoint", HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (f *fixture) relay(t *testing.T) *Relay {
	t.Helper()
	r, err := New(f.config())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// cosigned opens the stored file with both keys and returns the size it covers; 0 when absent.
func (f *fixture) cosigned(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.state, CosignedName))
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(b, note.VerifierList(f.logVer, f.witVer))
	if err != nil || len(n.Sigs) != 2 || len(n.UnverifiedSigs) != 0 {
		t.Fatalf("stored checkpoint: %v, %d verified, %d unverified", err, len(n.Sigs), len(n.UnverifiedSigs))
	}
	var cp log.Checkpoint
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		t.Fatal(err)
	}
	return cp.Size
}

func TestRelayGetsEachNewCheckpointCosigned(t *testing.T) {
	f := newFixture(t)
	r := f.relay(t)
	f.grow(t, 3)
	if err := r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := f.cosigned(t)
	f.grow(t, 300)
	if err := r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if second := f.cosigned(t); first == 0 || second <= first || second != f.wit.size {
		t.Fatalf("cosigned %d then %d, witness at %d", first, second, f.wit.size)
	}
	last := f.wit.requests[len(f.wit.requests)-1]
	if !strings.HasPrefix(last, fmt.Sprintf("old %d\n", first)) || strings.Count(strings.SplitN(last, "\n\n", 2)[0], "\n") < 1 {
		t.Fatalf("second request did not prove consistency from %d: %q", first, last[:min(len(last), 80)])
	}
}

func TestRelayAsksAgainWithTheWitnessSizeAfter409(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 3)
	if err := f.relay(t).Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.grow(t, 5)
	fresh := f.relay(t) // a restarted relay knows nothing and starts from old 0
	before := len(f.wit.requests)
	if err := fresh.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := f.wit.requests[before:]; len(got) != 2 || !strings.HasPrefix(got[0], "old 0\n") || strings.HasPrefix(got[1], "old 0\n") {
		t.Fatalf("requests after restart: %d, first %q", len(got), got[0][:6])
	}
	if f.cosigned(t) != f.wit.size {
		t.Fatalf("stored %d, witness %d", f.cosigned(t), f.wit.size)
	}
}

func TestRelayRefusesACosignatureFromAnotherKey(t *testing.T) {
	f := newFixture(t)
	f.wit.signer, _ = keyPair(t, "witness.test/w1", true) // same name, other key
	f.grow(t, 3)
	err := f.relay(t).Step(t.Context())
	if err == nil || f.cosigned(t) != 0 {
		t.Fatalf("stored a cosignature the witness key does not verify: %v", err)
	}
}

func TestRelayStopsWhenTheWitnessIsAheadOfTheLog(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 3)
	r := f.relay(t)
	if err := r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored, _ := os.ReadFile(filepath.Join(f.state, CosignedName))
	f.wit.size += 10 // the witness cosigned more than the log now holds: history behind it is gone
	err := f.relay(t).Step(t.Context())
	if err == nil || !strings.Contains(err.Error(), "cosigned history is gone") {
		t.Fatalf("got %v", err)
	}
	if now, _ := os.ReadFile(filepath.Join(f.state, CosignedName)); !bytes.Equal(now, stored) {
		t.Fatal("the stored cosigned checkpoint changed")
	}
}

func TestRelayReportsAWitnessRefusal(t *testing.T) {
	for _, status := range []int{http.StatusUnprocessableEntity, http.StatusForbidden, http.StatusNotFound, http.StatusConflict} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := newFixture(t)
			f.wit.status = status // a 409 without the size body is a refusal too
			f.grow(t, 3)
			if err := f.relay(t).Step(t.Context()); err == nil || f.cosigned(t) != 0 {
				t.Fatalf("status %d: err %v", status, err)
			}
		})
	}
}

func TestRelayOnlyReadsTheLog(t *testing.T) {
	f := newFixture(t)
	f.grow(t, 3)
	r := f.relay(t)
	if err := r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.grow(t, 300)
	before := snapshot(t, f.dir)
	if err := filepath.WalkDir(f.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		if d.IsDir() {
			mode = 0o555
		}
		return os.Chmod(p, mode) //nolint:gosec // test temp dir
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(f.dir, func(p string, d fs.DirEntry, _ error) error {
			if d != nil && d.IsDir() {
				_ = os.Chmod(p, 0o755) //nolint:gosec // test temp dir, restored so cleanup can remove it
			}
			return nil
		})
	})
	if err := r.Step(t.Context()); err != nil {
		t.Fatalf("relay needs to write the log: %v", err)
	}
	if after := snapshot(t, f.dir); !reflect.DeepEqual(before, after) {
		t.Fatal("the log changed")
	}
}

func snapshot(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // test temp dir
		out[p] = sha256.Sum256(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The relay holds no key that signs: nothing in its config can.
func TestRelayHoldsNoSigningKey(t *testing.T) {
	signer := reflect.TypeFor[note.Signer]()
	c := reflect.TypeFor[Config]()
	for i := range c.NumField() {
		if f := c.Field(i); f.Type.Implements(signer) || f.Type == signer {
			t.Fatalf("Config.%s can sign", f.Name)
		}
	}
}

func TestNewRefusesAnIncompleteConfig(t *testing.T) {
	f := newFixture(t)
	for name, change := range map[string]func(*Config){
		"relative log":   func(c *Config) { c.Log = "log" },
		"relative state": func(c *Config) { c.State = "state" },
		"no origin":      func(c *Config) { c.Origin = "" },
		"no log key":     func(c *Config) { c.LogKey = nil },
		"no witness key": func(c *Config) { c.Witness = nil },
		"no client":      func(c *Config) { c.HTTP = nil },
		"no timeout":     func(c *Config) { c.HTTP = &http.Client{} },
		"other path":     func(c *Config) { c.Submit = f.srv.URL + "/checkpoint" },
		"other scheme":   func(c *Config) { c.Submit = "file:///add-checkpoint" },
		"no host":        func(c *Config) { c.Submit = "http:///add-checkpoint" },
	} {
		cfg := f.config()
		change(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzWitnessResponse feeds the two parsers of what the witness sends back; a cosignature they
// accept must verify with the witness key over the text.
func FuzzWitnessResponse(f *testing.F) {
	_, wv := keyPair(f, "witness.test/w1", true)
	r := &Relay{cfg: Config{Witness: wv}}
	text := origin + "\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	f.Add("text/x.tlog.size", []byte("12\n"))
	f.Add("text/x.tlog.size", []byte("012\n"))
	f.Add("", []byte("— witness.test/w1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"))
	f.Fuzz(func(t *testing.T, ct string, body []byte) {
		var c errConflict
		if err := conflict(ct, body); errors.As(err, &c) && strconv.FormatUint(c.size, 10)+"\n" != string(body) {
			t.Fatalf("size %d from %q", c.size, body)
		}
		sigs, err := r.cosignatures(text, body)
		if err != nil {
			return
		}
		if _, err := note.Open(append([]byte(text+"\n"), sigs...), note.VerifierList(wv)); err != nil {
			t.Fatalf("accepted lines that do not verify: %v", err)
		}
	})
}
