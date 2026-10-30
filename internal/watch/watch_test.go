package watch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWitness serves an index page whose head the test sets.
type fakeWitness struct {
	mu   sync.Mutex
	head Head
}

func (w *fakeWitness) set(h Head) { w.mu.Lock(); defer w.mu.Unlock(); w.head = h }

func (w *fakeWitness) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = rw.Write(index(map[string]Head{"balistid/log": w.head}))
}

func runWatch(t *testing.T, c Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func keysOf(n *ntfy) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, h := range n.got {
		out = append(out, h.Get("Tags"))
	}
	return out
}

func waitKey(t *testing.T, n *ntfy, key Key) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if slices.Contains(keysOf(n), string(key)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %s alert, got %v", key, keysOf(n))
}

func TestRunVerifiesAndAlertsOnFork(t *testing.T) {
	log := enc(t, batches(300)...)
	forged := false
	var mu sync.Mutex
	relay := relayServer(t, log, func(_ string, b []byte) []byte {
		mu.Lock()
		defer mu.Unlock()
		if forged {
			b = append([]byte(nil), b...)
			b[len(b)-1] ^= 1
		}
		return b
	})
	wit := &fakeWitness{head: headOf(log[:200])}
	ws := httptest.NewServer(wit)
	defer ws.Close()
	n := &ntfy{}
	c := &clock{now: time.Now()}
	push := newTestPusher(t, n, c)
	store, err := OpenStore(t.TempDir(), "balistid/log", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	notified := make(chan string, 1000)
	runWatch(t, Config{Origin: "balistid/log", Source: Source{Witness: ws.URL + "/", Relay: relay.URL + "/", HTTP: testClient()},
		Store: store, Push: push, Limits: DefaultLimits, Poll: 2 * time.Millisecond, Now: c.Now,
		Notify: func(s string) error {
			select {
			case notified <- s:
			default:
			}
			return nil
		}})
	waitKey(t, n, KeyStart)
	mu.Lock()
	forged = true
	mu.Unlock()
	wit.set(headOf(log))
	waitKey(t, n, KeyFork)
	if got := <-notified; got != "WATCHDOG=1" {
		t.Fatalf("notify %q", got)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, text := range n.texts {
		if strings.Contains(text, testToken) {
			t.Fatal("the token in a message")
		}
	}
}

func TestDailyStatus(t *testing.T) {
	log := enc(t, batches(10)...)
	relay := relayServer(t, log, nil)
	wit := &fakeWitness{head: headOf(log)}
	ws := httptest.NewServer(wit)
	defer ws.Close()
	n := &ntfy{}
	c := &clock{now: time.Now()}
	push := newTestPusher(t, n, c)
	store, err := OpenStore(t.TempDir(), "balistid/log", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { c.add(time.Hour); return c.Now() }
	runWatch(t, Config{Origin: "balistid/log", Source: Source{Witness: ws.URL + "/", Relay: relay.URL + "/", HTTP: testClient()},
		Store: store, Push: push, Limits: DefaultLimits, Poll: time.Millisecond, Now: now, Notify: func(string) error { return nil }})
	waitKey(t, n, KeyDaily)
	waitKey(t, n, KeySilence) // a log that stopped growing for a day
}
