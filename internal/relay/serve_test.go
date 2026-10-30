package relay

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/cosign"
)

const serveOrigin = "balistid-test/log"

// bundleLog is a log directory with a full bundle 0 and a partial bundle 1 of five entries.
func bundleLog(t *testing.T) (dir string, full, partial []byte) {
	t.Helper()
	dir = t.TempDir()
	full, partial = bytes.Repeat([]byte{0, 1, 'a'}, 256), bytes.Repeat([]byte{0, 1, 'b'}, 5)
	for name, b := range map[string][]byte{layout.EntriesPath(0, 0): full, layout.EntriesPath(1, 5): partial} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, full, partial
}

func newTestServer(t *testing.T, dir string) (*Server, string) {
	t.Helper()
	state := t.TempDir()
	s, err := NewServer(dir, state, serveOrigin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, filepath.Join(state, cosign.ServedName)
}

func get(s http.Handler, method, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, "http://relay"+target, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestServeOnlyEntryBundles(t *testing.T) {
	dir, full, partial := bundleLog(t)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte{0, 1, 's'}, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mk := range map[string]func(string) error{
		layout.EntriesPath(2, 0): func(p string) error { return os.Symlink(outside, p) },
		layout.EntriesPath(3, 0): func(p string) error { return syscall.Mkfifo(p, 0o600) },
		layout.EntriesPath(4, 0): func(p string) error { return os.Mkdir(p, 0o750) },
		layout.EntriesPath(5, 0): func(p string) error { return os.WriteFile(p, make([]byte, maxBundle+1), 0o600) },
		"checkpoint":             func(p string) error { return os.WriteFile(p, []byte("note"), 0o600) },
		layout.TilePath(0, 0, 0): func(p string) error { return os.WriteFile(p, make([]byte, 32), 0o600) },
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := errors.Join(os.MkdirAll(filepath.Dir(p), 0o750), mk(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := newTestServer(t, dir)
	ok := map[string][]byte{"/" + layout.EntriesPath(0, 0): full, "/" + layout.EntriesPath(1, 5): partial}
	for target, want := range ok {
		if w := get(s, http.MethodGet, target); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), want) {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
	refused := []string{
		"/" + layout.EntriesPath(1, 6), "/tile/entries/0", "/tile/entries/x000/000", "/tile/entries/%30%30%30",
		"/tile/entries/000/../001.p/5", "/tile/entries/001.p/05", "/tile/entries/001.p/0", "/tile/entries/001.p/256",
		"/tile/entries/000?x", "/tile/entries/000?", "/" + layout.TilePath(0, 0, 0), "/checkpoint", "/", "/tile/entries/",
		"/" + layout.EntriesPath(2, 0), "/" + layout.EntriesPath(3, 0), "/" + layout.EntriesPath(4, 0),
		"/" + layout.EntriesPath(5, 0),
	}
	for _, target := range refused {
		if w := get(s, http.MethodGet, target); w.Code == http.StatusOK {
			t.Errorf("%s: served", target)
		}
	}
	for _, m := range []string{http.MethodHead, http.MethodPost, http.MethodPut} {
		if w := get(s, m, "/"+layout.EntriesPath(0, 0)); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, w.Code)
		}
	}
}

func TestServeRecordsServedOnlyWhenWritten(t *testing.T) {
	dir, _, _ := bundleLog(t)
	s, path := newTestServer(t, dir)
	read := func() uint64 {
		t.Helper()
		n, err := cosign.ReadServed(path, serveOrigin)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := read(); n != 0 {
		t.Fatalf("a new server starts at %d", n)
	}
	get(s, http.MethodGet, "/"+layout.EntriesPath(9, 0)) // missing: nothing served
	if n := read(); n != 0 {
		t.Fatalf("a 404 counted: %d", n)
	}
	get(s, http.MethodGet, "/"+layout.EntriesPath(1, 5))
	get(s, http.MethodGet, "/"+layout.EntriesPath(0, 0))
	if n := read(); n != 261 {
		t.Fatalf("served %d, want 261", n)
	}
	if n, err := cosign.ReadServed(path, "other/log"); err != nil || n != 0 {
		t.Fatalf("another origin's view: %d %v", n, err)
	}
}

func TestServedRecordIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), cosign.ServedName)
	for _, b := range []string{"", "balistid-served 1\no\n01\n", "balistid-served 2\no\n1\n", "balistid-served 1\no\n1\nx",
		"balistid-served 1\no o\n1\n", "balistid-served 1\no\n99999999999999999999\n"} {
		if err := os.WriteFile(path, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cosign.ReadServed(path, "o"); err == nil {
			t.Errorf("%q: read", b)
		}
	}
}

// The server holds no more than its slots of requests: the rest are refused at once.
func TestServeRefusesBeyondItsSlots(t *testing.T) {
	dir, _, _ := bundleLog(t)
	s, _ := newTestServer(t, dir)
	for range maxInFlight {
		s.slots <- struct{}{}
	}
	if w := get(s, http.MethodGet, "/"+layout.EntriesPath(0, 0)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d", w.Code)
	}
}

func TestListenBeforeAddressExists(t *testing.T) {
	ln, err := Listen(t.Context(), "192.0.2.1:0") // TEST-NET-1: no interface holds it
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("sockets denied here; CI runs it")
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
}

func FuzzServePath(f *testing.F) {
	for _, p := range []string{"/tile/entries/000", "/tile/entries/x001/234/067.p/8", "/tile/entries/001.p", "/tile/entries/.p/1"} {
		f.Add(p, "")
	}
	f.Fuzz(func(t *testing.T, path, query string) {
		u := &url.URL{Path: path, RawQuery: query}
		name, end, ok := bundlePath(u)
		if !ok {
			return
		}
		n, w, err := layout.ParseTileIndexPartial(name[len("tile/entries/"):])
		if err != nil || layout.EntriesPath(n, w) != name || query != "" || end == 0 || end > n*layout.EntryBundleWidth+layout.EntryBundleWidth {
			t.Fatalf("accepted %q as %q, %d", path, name, end)
		}
	})
}
