package watch

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "tk_testtokenfortheunittestsonly"

// ntfy is a fake ntfy server that fails its first fail posts.
type ntfy struct {
	mu    sync.Mutex
	fail  int
	got   []http.Header
	texts []string
}

func (n *ntfy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail > 0 {
		n.fail--
		rw.WriteHeader(http.StatusTooManyRequests)
		return
	}
	n.got = append(n.got, r.Header.Clone())
	n.texts = append(n.texts, string(b))
}

func (n *ntfy) wait(t *testing.T, count int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n.mu.Lock()
		if len(n.texts) >= count {
			out := append([]string(nil), n.texts...)
			n.mu.Unlock()
			return out
		}
		n.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fewer than %d pushes arrived", count)
	return nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestPusher(t *testing.T, n *ntfy, c *clock) *Pusher {
	t.Helper()
	s := httptest.NewServer(n)
	t.Cleanup(s.Close)
	p, err := NewPusher(s.URL+"/balistid", testToken, testClient(), c.Now)
	if err != nil {
		t.Fatal(err)
	}
	p.backoff = []time.Duration{time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return p
}

func TestPushDedupRetry(t *testing.T) {
	n := &ntfy{fail: 2}
	c := &clock{now: time.Now()}
	p := newTestPusher(t, n, c)
	p.Raise(KeySilence, "first", remindEvery)
	n.wait(t, 1) // after two refusals: retried, not dropped
	p.Raise(KeySilence, "again", remindEvery)
	p.Raise(KeySilence, "again", remindEvery)
	c.add(remindEvery)
	p.Raise(KeySilence, "reminder", remindEvery)
	texts := n.wait(t, 2)
	if texts[0] != "first" || texts[1] != "reminder (and 2 more since the last alert)" {
		t.Fatalf("pushes %q", texts)
	}
	p.Clear(KeySilence)
	p.Raise(KeySilence, "back", remindEvery)
	if texts := n.wait(t, 3); texts[2] != "back" {
		t.Fatalf("a cleared condition did not alert at once: %q", texts)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	h := n.got[0]
	if h.Get("Authorization") != "Bearer "+testToken || h.Get("Title") != "Balistid: host silent" || h.Get("Priority") != "5" {
		t.Fatalf("headers %v", h)
	}
}

func TestPushNeverLogsToken(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	n := &ntfy{fail: 3}
	p := newTestPusher(t, n, &clock{now: time.Now()})
	p.Raise(KeyFork, "fork", eventEvery)
	n.wait(t, 1)
	if !strings.Contains(buf.String(), "push failed") || strings.Contains(buf.String(), testToken) {
		t.Fatalf("log %q: failures not logged, or the token in it", buf.String())
	}
}

func TestNewPusherRefuses(t *testing.T) {
	c := testClient()
	for name, tok := range map[string]string{"empty": "", "a space": "tk a", "a newline": "tk\n", "long": strings.Repeat("a", 257)} {
		if _, err := NewPusher("https://ntfy.example/t", tok, c, time.Now); err == nil {
			t.Errorf("token %s: accepted", name)
		}
	}
	for _, u := range []string{"https://user@ntfy.example/t", "http://ntfy.example/t", "http://10.0.0.1/t", "http://localhost/t"} {
		if _, err := NewPusher(u, testToken, c, time.Now); err == nil {
			t.Errorf("%s: accepted", u)
		}
	}
	for _, u := range []string{"https://ntfy.example/t", "http://127.0.0.1:8080/t", "http://[::1]/t"} {
		if _, err := NewPusher(u, testToken, c, time.Now); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := NewPusher("https://ntfy.example/t", testToken, &http.Client{}, time.Now); err == nil {
		t.Error("a client without a timeout: accepted")
	}
}
