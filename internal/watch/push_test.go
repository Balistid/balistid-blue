package watch

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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
	p.Hold(KeySilence, "first")
	n.wait(t, 1) // after two refusals: retried, not dropped
	p.Hold(KeySilence, "still")
	c.add(remind)
	p.Hold(KeySilence, "reminder")
	texts := n.wait(t, 2)
	if texts[0] != "first" || texts[1] != "reminder" {
		t.Fatalf("pushes %q", texts)
	}
	n.mu.Lock()
	h := n.got[0]
	n.mu.Unlock()
	if h.Get("Authorization") != "Bearer "+testToken || h.Get("Title") != "Balistid: host silent" || h.Get("Priority") != "5" {
		t.Fatalf("headers %v", h)
	}
}

// Events and conditions that return within the spacing are held, never dropped: they go out once it passed.
func TestPushHoldsNothingBack(t *testing.T) {
	n := &ntfy{}
	c := &clock{now: time.Now()}
	p := newTestPusher(t, n, c)
	p.Event(KeyLoss, "1 record lost")
	n.wait(t, 1)
	c.add(10 * time.Second)
	p.Event(KeyLoss, "9000 records lost")
	p.Hold(KeyFork, "fork")
	p.Clear(KeyFork)
	n.wait(t, 2)
	p.Hold(KeyFork, "fork again") // within the spacing of the first fork alert
	p.Flush()
	c.add(spacing)
	p.Flush()
	texts := n.wait(t, 4)
	slices.Sort(texts)
	want := []string{"1 record lost", "9000 records lost", "fork", "fork again"}
	if !slices.Equal(texts, want) {
		t.Fatalf("pushes %q, want %q", texts, want)
	}
	c.add(spacing)
	p.Flush()
	time.Sleep(20 * time.Millisecond)
	if got := n.wait(t, 4); len(got) != 4 {
		t.Fatalf("a flush with nothing held sent %q", got[4:])
	}
}

// A message whose send failed and one raised after it merge, counted: the second never overwrites the first.
func TestPushFailedMessageIsNotOverwritten(t *testing.T) {
	c := &clock{now: time.Now()}
	p, err := NewPusher("https://ntfy.example/t", testToken, testClient(), c.Now)
	if err != nil {
		t.Fatal(err)
	}
	p.Event(KeyLoss, "first loss")
	k, m, _ := p.next()
	p.requeue(k, m) // its send failed
	c.add(spacing)
	p.Event(KeyLoss, "second loss")
	if _, m, _ := p.next(); m.render() != "second loss (the latest of 2 alerts)" {
		t.Fatalf("waiting message %q", m.render())
	}
	p.Event(KeyHealth, "first unknown")
	k, m, _ = p.next() // being sent when the next one comes, past the spacing
	c.add(spacing)
	p.Event(KeyHealth, "second unknown")
	p.requeue(k, m) // the send failed
	if _, m, _ := p.next(); m.render() != "second unknown (the latest of 2 alerts)" {
		t.Fatalf("waiting message %q", m.render())
	}
	p.Event(KeyFork, "fork")
	k, m, _ = p.next()
	p.Event(KeyFork, "fork again") // raised while the first is being sent, within the spacing
	p.requeue(k, m)
	c.add(spacing)
	p.Flush()
	if _, m, _ := p.next(); m.render() != "fork again (the latest of 2 alerts)" {
		t.Fatalf("waiting message %q", m.render())
	}
}

func TestPushNeverLogsToken(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	n := &ntfy{fail: 3}
	p := newTestPusher(t, n, &clock{now: time.Now()})
	p.Event(KeyFork, "fork")
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
