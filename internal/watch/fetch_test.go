package watch

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/entry"
)

// index renders litewitness v0.10.0's index page (cmd/litewitness indexHandler) for the given logs.
func index(logs map[string]Head) []byte {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n# litewitness balistid-range/witness\n\nbalistid-range/witness+1234+AAAA\n\n## Logs\n\n")
	for origin, h := range logs {
		fmt.Fprintf(&b, "- %s\n  (size %d, root %s)\n\n", html.EscapeString(origin), h.Size, base64.StdEncoding.EncodeToString(h.Root[:]))
	}
	return []byte(b.String())
}

func TestParseIndex(t *testing.T) {
	h := Head{Size: 42, Root: [32]byte{1, 2, 3}}
	other := Head{Size: 7, Root: [32]byte{9}}
	got, err := ParseIndex(index(map[string]Head{"balistid/log": h, "other/log": other}), "balistid/log")
	if err != nil || got != h {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = ParseIndex(index(map[string]Head{"a&b/log": h}), "a&b/log")
	if err != nil || got != h {
		t.Fatalf("escaped origin: %+v %v", got, err)
	}
	root := base64.StdEncoding.EncodeToString(h.Root[:])
	bad := map[string]string{
		"not listed":        "- other/log\n  (size 1, root " + root + ")\n",
		"listed twice":      "- balistid/log\n  (size 1, root " + root + ")\n- balistid/log\n  (size 2, root " + root + ")\n",
		"no size line":      "- balistid/log\n",
		"a leading zero":    "- balistid/log\n  (size 01, root " + root + ")\n",
		"a short root":      "- balistid/log\n  (size 1, root AAAA)\n",
		"a size past 2^64":  "- balistid/log\n  (size 99999999999999999999, root " + root + ")\n",
		"trailing text":     "- balistid/log\n  (size 1, root " + root + ") x\n",
		"a prefix of names": "- balistid/logs\n  (size 1, root " + root + ")\n",
	}
	for name, page := range bad {
		if _, err := ParseIndex([]byte(page), "balistid/log"); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := ParseIndex(bytes.Repeat([]byte("x"), maxIndex+1), "balistid/log"); err == nil {
		t.Error("an index over the cap parsed")
	}
}

func TestParseBundleRoundTrip(t *testing.T) {
	entries := enc(t, batches(256)...)
	got, err := ParseBundle(appendBundle(nil, entries))
	if err != nil || len(got) != 256 || !bytes.Equal(got[255], entries[255]) {
		t.Fatalf("%d entries, %v", len(got), err)
	}
	over := appendBundle(nil, append(entries, entries[0]))
	tooLong := appendBundle(nil, [][]byte{bytes.Repeat([]byte{1}, entry.MaxBytes+1)})
	for name, b := range map[string][]byte{"257 entries": over, "an entry over 256 bytes": tooLong,
		"an empty entry": {0, 0}, "a dangling length": {0}, "a short entry": {0, 5, 1}, "nothing": nil} {
		if _, err := ParseBundle(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// relayServer serves log's bundles at their Tessera paths as the relay does: a full bundle, and any
// partial width of it or of the last one.
func relayServer(t *testing.T, log [][]byte, mutate func(path string, body []byte) []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n, p, err := layout.ParseTileIndexPartial(strings.TrimPrefix(r.URL.Path, "/tile/entries/"))
		w := uint64(p)
		if w == 0 {
			w = width
		}
		if err != nil || "/"+layout.EntriesPath(n, p) != r.URL.Path || n*width+w > uint64(len(log)) {
			http.NotFound(rw, r)
			return
		}
		body := appendBundle(nil, log[n*width:n*width+w])
		if mutate != nil {
			body = mutate(r.URL.Path, body)
		}
		_, _ = rw.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func testClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func TestFetchCapped(t *testing.T) {
	ctx := context.Background()
	log := enc(t, batches(300)...)
	ok := relayServer(t, log, nil)
	src := Source{Relay: ok.URL + "/", HTTP: testClient()}
	if got, err := src.Bundle(ctx, 1, 44); err != nil || len(got) != 44 || !bytes.Equal(got[0], log[256]) {
		t.Fatalf("partial bundle: %d, %v", len(got), err)
	}
	// the log grew past 256: the partial bundle is gone, the full one's prefix is taken
	if got, err := src.Bundle(ctx, 0, 100); err != nil || len(got) != 100 {
		t.Fatalf("prefix of the full bundle: %d, %v", len(got), err)
	}
	cases := map[string]func(string, []byte) []byte{
		"a body over the cap":   func(string, []byte) []byte { return bytes.Repeat([]byte{0}, maxBundle+1) },
		"one entry too few":     func(_ string, b []byte) []byte { return appendBundle(nil, log[256:299]) },
		"one entry too many":    func(_ string, b []byte) []byte { return appendBundle(nil, append(log[256:], log[0])) },
		"bytes after the entry": func(_ string, b []byte) []byte { return append(b, 0) },
	}
	for name, mutate := range cases {
		s := relayServer(t, log, mutate)
		if _, err := (Source{Relay: s.URL + "/", HTTP: testClient()}).Bundle(ctx, 1, 44); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	redirect := httptest.NewServer(http.RedirectHandler(ok.URL+"/"+layout.EntriesPath(1, 44), http.StatusFound))
	defer redirect.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	for name, s := range map[string]*httptest.Server{"a redirect": redirect, "a 500": failing} {
		if _, err := (Source{Relay: s.URL + "/", HTTP: testClient()}).Bundle(ctx, 1, 44); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
	if _, err := src.Bundle(ctx, 9, 1); err == nil {
		t.Error("a bundle the relay does not have was taken")
	}
}

// rawServer answers every connection with resp, as a hostile relay may: Go's server writes no reason
// phrase of its own choosing.
func rawServer(t *testing.T, resp string) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(c, 1)) // the request has started
			_, _ = c.Write([]byte(resp))
			_ = c.Close()
		}
	}()
	return "http://" + ln.Addr().String() + "/"
}

// Nothing of a peer's bytes reaches an error, and so the journal: not a reason phrase, not a malformed
// status line or header.
func TestHostileStatusTextIsNotRepeated(t *testing.T) {
	evil := strings.Repeat("EVIL", 1000)
	for name, resp := range map[string]string{
		"a reason phrase":    "HTTP/1.1 500 " + evil + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		"a malformed status": "HTTP/1.1 " + evil + "\r\n\r\n",
		"a malformed header": "HTTP/1.1 200 OK\r\n" + evil + "\r\n\r\n",
		"no HTTP at all":     evil + "\r\n\r\n",
	} {
		u := rawServer(t, resp)
		_, err := (Source{Relay: u, HTTP: testClient()}).Bundle(context.Background(), 0, 1)
		if err == nil || strings.Contains(err.Error(), "EVIL") || len(err.Error()) > 200 {
			t.Errorf("%s: relay error %.300q", name, err)
		}
		p, perr := NewPusher(u, testToken, testClient(), time.Now)
		if perr != nil {
			t.Fatal(perr)
		}
		if err := p.Send(context.Background(), KeyLossQueue, "x"); err == nil || strings.Contains(err.Error(), "EVIL") || len(err.Error()) > 200 {
			t.Errorf("%s: push error %.300q", name, err)
		}
	}
}

func TestCheckURLs(t *testing.T) {
	if err := CheckURLs("http://127.0.0.1:7380/", "http://10.0.0.1:7381/"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"ftp://x/", "http://y/"}, {"http://u@x/", "http://y/"}, {"http://x/?q", "http://y/"},
		{"http://x/", "http://y"}, {"http://x/", "http://y/#f"}, {"", "http://y/"}} {
		if err := CheckURLs(pair[0], pair[1]); err == nil {
			t.Errorf("%q, %q: accepted", pair[0], pair[1])
		}
	}
}

func FuzzTileParse(f *testing.F) {
	f.Add(appendBundle(nil, enc(f, batches(3)...)))
	f.Add([]byte{0, 1, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseBundle(b)
		if err != nil {
			return
		}
		if len(got) == 0 || len(got) > width || !bytes.Equal(appendBundle(nil, got), b) {
			t.Fatalf("%d entries do not encode back to the input", len(got))
		}
	})
}

func FuzzWitnessIndex(f *testing.F) {
	f.Add(index(map[string]Head{"balistid/log": {Size: 3, Root: [32]byte{7}}}), "balistid/log")
	f.Add([]byte("- a\n  (size 0, root AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=)\n"), "a")
	f.Fuzz(func(t *testing.T, b []byte, origin string) {
		h, err := ParseIndex(b, origin)
		if err != nil {
			return
		}
		line := fmt.Sprintf("  (size %d, root %s)", h.Size, base64.StdEncoding.EncodeToString(h.Root[:]))
		if !bytes.Contains(b, []byte(line)) {
			t.Fatalf("parsed %+v that the page does not say", h)
		}
	})
}
