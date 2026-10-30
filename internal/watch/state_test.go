package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/entry"
)

func TestStoreRoundTrip(t *testing.T) {
	s, err := OpenStore(t.TempDir(), "balistid/log", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if l, q, err := s.Load(); err != nil || l.Size != 0 || q != nil {
		t.Fatalf("no state yet: %+v %v %v", l, q, err)
	}
	log := enc(t, batches(300)...)
	l := verified(t, log)
	l.Rules.Pending = true
	age := 5 * time.Hour
	if err := s.Save(l, &age); err != nil {
		t.Fatal(err)
	}
	got, q, err := s.Load()
	if err != nil || got.Size != 300 || got.Root != l.Root || len(got.Partial) != 44 || !got.Rules.Pending || q == nil || *q != age {
		t.Fatalf("%+v %v %v", got.Rules, q, err)
	}
	// the loaded state verifies on from where it stopped
	more := append(log, enc(t, batches(310)[300:]...)...)
	if _, _, err := Advance(context.Background(), got, headOf(more), fetchFrom(more), discard); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRefusesBadState(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir, "balistid/log", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	l := verified(t, enc(t, batches(3)...))
	if err := s.Save(l, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, stateName)
	good, err := os.ReadFile(path) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"an unknown field":   strings.Replace(string(good), `"origin"`, `"extra":1,"origin"`, 1),
		"another schema":     strings.Replace(string(good), `"schema_version":1`, `"schema_version":2`, 1),
		"another origin":     strings.Replace(string(good), `"balistid/log"`, `"other/log"`, 1),
		"a second document":  string(good) + "{}",
		"partial off size":   strings.Replace(string(good), `"size":3`, `"size":4`, 1),
		"not JSON":           "x",
		"a negative quiet":   strings.Replace(string(good), `"rules"`, `"quiet_s":-1,"rules"`, 1),
		"a short root":       strings.Replace(string(good), `"root":"`, `"root":"AAAA`, 1),
		"over the state cap": string(good) + strings.Repeat(" ", maxState),
	}
	for name, body := range cases {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Load(); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Errorf("a symlinked state file: %v", err)
	}
}

func TestPiStoreCapAlerts(t *testing.T) {
	log := enc(t, batches(3*width)...)
	size := int64(len(appendBundle(nil, log[:width])))
	s, err := OpenStore(t.TempDir(), "balistid/log", 2*size)
	if err != nil {
		t.Fatal(err)
	}
	l, _, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log), s.Stage)
	if err == nil {
		err = s.Keep()
	}
	if err != nil || l.Size != uint64(len(log)) || !s.Full() {
		t.Fatalf("size %d, full %v, err %v: verification must go on at the cap", l.Size, s.Full(), err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, layout.EntriesPath(2, 0))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the bundle past the cap was kept: %v", err)
	}
	reopened, err := OpenStore(filepath.Dir(s.dir), "balistid/log", 2*size)
	if err != nil || reopened.stored != 2*size || !reopened.Full() {
		t.Fatalf("reopened: stored %d, full %v, %v", reopened.stored, reopened.Full(), err)
	}
}

func TestStoreFullAtExactCap(t *testing.T) {
	log := enc(t, batches(width)...)
	s, err := OpenStore(t.TempDir(), "balistid/log", int64(len(appendBundle(nil, log))))
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(s.Stage(0, log), s.Keep()); err != nil || !s.Full() {
		t.Fatalf("full %v, %v", s.Full(), err)
	}
}

// A step whose root fails keeps nothing: what it staged is dropped, at the cap too, where a forged bundle
// would otherwise stay in place of the genuine one (the host failing the step on a later bundle, or forging).
func TestMirrorHoldsOnlyVerified(t *testing.T) {
	log := enc(t, batches(width+5)...)
	forged := append([][]byte(nil), log...)
	forged[7] = enc(t, batches(9)[8])[0]
	withheld := func(ctx context.Context, idx, w uint64) ([][]byte, error) {
		if idx == 1 {
			return nil, errMissing
		}
		return fetchFrom(forged)(ctx, idx, w)
	}
	for name, fetch := range map[string]Fetch{"a forged root": fetchFrom(forged), "a later bundle withheld": withheld} {
		s, err := OpenStore(t.TempDir(), "balistid/log", int64(len(appendBundle(nil, log[:width]))))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Advance(context.Background(), Log{}, headOf(log), fetch, s.Stage); err == nil {
			t.Fatalf("%s: verified", name)
		}
		if err := s.Discard(); err != nil {
			t.Fatal(err)
		}
		l, _, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log), s.Stage)
		if err == nil {
			err = errors.Join(s.Keep(), s.Save(l, nil))
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := os.ReadFile(filepath.Join(s.dir, layout.EntriesPath(0, 0)))
		if err != nil || !bytes.Equal(b, appendBundle(nil, log[:width])) {
			t.Fatalf("%s: kept bundle is not the verified one: %v", name, err)
		}
		if names, _ := os.ReadDir(s.staging()); len(names) != 0 {
			t.Fatalf("%s: %d files left staged", name, len(names))
		}
	}
}

// A state file whose range does not give its root is refused: a step from it would never verify, or
// verify a log the Pi never saw.
func TestStoreRefusesInconsistentRange(t *testing.T) {
	s, err := OpenStore(t.TempDir(), "balistid/log", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	l := verified(t, enc(t, batches(300)...))
	bad := l
	bad.Hashes = [][]byte{bytes.Repeat([]byte{7}, 32)}
	other := l
	other.Partial = append([][]byte(nil), l.Partial...)
	other.Partial[0] = enc(t, entry.Announce{Kind: entry.AnnounceSuspend})[0]
	for name, v := range map[string]Log{"a changed range": bad, "a changed partial entry": other} {
		if err := s.Save(v, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Load(); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func FuzzStateParse(f *testing.F) {
	l := verified(f, enc(f, batches(3)...))
	q := 5 * time.Hour
	b, err := json.Marshal(saved{Schema: stateSchema, Origin: "o/log", Size: l.Size, Root: l.Root[:], Hashes: l.Hashes,
		Partial: l.Partial, Rules: l.Rules, QuietS: new(int64(q.Seconds()))})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, q, err := parseState(b, "o/log")
		if err != nil {
			return
		}
		if l.check() != nil || (q != nil && *q < 0) {
			t.Fatalf("parsed a state that does not hold: %+v", l)
		}
	})
}
