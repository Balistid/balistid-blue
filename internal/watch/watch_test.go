package watch

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
)

// fakeWitness serves an index page whose head the test sets.
type fakeWitness struct {
	mu   sync.Mutex
	head Head
	down bool
}

func (w *fakeWitness) set(h Head) { w.mu.Lock(); defer w.mu.Unlock(); w.head = h }

func (w *fakeWitness) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.down {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
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
	store, err := OpenStore(t.TempDir(), "balistid/log")
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

func TestRunRefusesAConfigThatSilences(t *testing.T) {
	store, err := OpenStore(t.TempDir(), "balistid/log")
	if err != nil {
		t.Fatal(err)
	}
	push, err := NewPusher("https://ntfy.example/t", testToken, testClient(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	good := Config{Origin: "balistid/log", Source: Source{Witness: "http://127.0.0.1:1/", Relay: "http://127.0.0.1:2/",
		HTTP: testClient()}, Store: store, Push: push, Limits: DefaultLimits, Poll: time.Second, Now: time.Now,
		Notify: func(string) error { return nil }}
	if err := good.check(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*Config){
		"no gap":            func(c *Config) { c.Limits.Gap = 0 },
		"no silence limit":  func(c *Config) { c.Limits.Silence = 0 },
		"no poll":           func(c *Config) { c.Poll = 0 },
		"no clock":          func(c *Config) { c.Now = nil },
		"no client timeout": func(c *Config) { c.Source.HTTP = &http.Client{} },
		"no relay slash":    func(c *Config) { c.Source.Relay = "http://127.0.0.1:2" },
	}
	for name, mutate := range bad {
		c := good
		mutate(&c)
		if err := Run(context.Background(), c); err == nil {
			t.Errorf("%s: accepted", name)
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
	store, err := OpenStore(t.TempDir(), "balistid/log")
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { c.add(time.Hour); return c.Now() }
	runWatch(t, Config{Origin: "balistid/log", Source: Source{Witness: ws.URL + "/", Relay: relay.URL + "/", HTTP: testClient()},
		Store: store, Push: push, Limits: DefaultLimits, Poll: time.Millisecond, Now: now, Notify: func(string) error { return nil }})
	waitKey(t, n, KeyDaily)
	waitKey(t, n, KeySilence) // a log that stopped growing for a day
}

// harness runs the watcher against a fake relay, witness and ntfy, with a clock that moves by tick on
// every reading.
type harness struct {
	wit    *fakeWitness
	n      *ntfy
	notify chan string
	clock  *clock
	start  time.Time
}

func startWatch(t *testing.T, log [][]byte, tick, poll time.Duration) harness {
	t.Helper()
	relay := relayServer(t, log, nil)
	h := harness{wit: &fakeWitness{head: headOf(log)}, n: &ntfy{}, notify: make(chan string, 1<<16)}
	ws := httptest.NewServer(h.wit)
	t.Cleanup(ws.Close)
	c := &clock{now: time.Now()}
	h.clock, h.start = c, c.Now()
	push := newTestPusher(t, h.n, c)
	store, err := OpenStore(t.TempDir(), "balistid/log")
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { c.add(tick); return c.Now() }
	runWatch(t, Config{Origin: "balistid/log", Source: Source{Witness: ws.URL + "/", Relay: relay.URL + "/", HTTP: testClient()},
		Store: store, Push: push, Limits: DefaultLimits, Poll: poll, Now: now,
		Notify: func(s string) error { h.notify <- s; return nil }})
	return h
}

// An unreadable witness proves nothing: after an announcement it does not hold off the silence alarm.
func TestUnreadableWitnessDoesNotQuiet(t *testing.T) {
	log := enc(t, append(batches(3), entry.Announce{Kind: entry.AnnounceShutdown})...)
	h := startWatch(t, log, 10*time.Second, time.Millisecond)
	waitKey(t, h.n, KeyStart)
	h.wit.mu.Lock()
	h.wit.down = true
	h.wit.mu.Unlock()
	waitKey(t, h.n, KeySilence)
	if d := h.clock.Now().Sub(h.start); d >= DefaultLimits.Quiet {
		t.Fatalf("silence alarmed only after %v, past the quiet cap", d)
	}
}

// A long backlog feeds systemd's watchdog and the alarms after every bundle, not once at its end.
func TestAlarmsRunBetweenBundles(t *testing.T) {
	log := enc(t, batches(4*width)...)
	h := startWatch(t, log, time.Second, time.Hour)
	for range 5 { // four bundles and the step's end
		select {
		case <-h.notify:
		case <-time.After(5 * time.Second):
			t.Fatal("the watchdog was not fed between bundles")
		}
	}
}

// Every condition that starts or ends is a decision, logged with its reason and rule version.
func TestConditionTransitionsAreLogged(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	t0 := time.Now()
	c := &clock{now: t0}
	push, err := NewPusher("https://ntfy.example/t", testToken, testClient(), c.Now)
	if err != nil {
		t.Fatal(err)
	}
	x := &watcher{c: Config{Push: push, Notify: func(string) error { return nil }},
		dog: NewWatchdog(DefaultLimits, t0, nil, false), active: map[Key]bool{}}
	x.alarm(context.Background(), t0.Add(DefaultLimits.Silence), false)
	x.dog.Grew(t0.Add(DefaultLimits.Silence+time.Second), grow, Rules{})
	x.alarm(context.Background(), t0.Add(DefaultLimits.Silence+time.Second), false)
	out := buf.String()
	for _, want := range []string{"decision=alarm reason=silence rule=\"" + RuleVersion + "\"",
		"decision=clear reason=silence rule=\"" + RuleVersion + "\""} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
}

// A restart keeps auditd's dispatcher overflow through the saved state: the condition alerts again.
func TestRunKeepsTheOverflowAcrossARestart(t *testing.T) {
	log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}},
		entry.Health{State: entry.StateUnknown, Reason: entry.ReasonDispatcher})
	relay := relayServer(t, log, func(_ string, b []byte) []byte { return b })
	ws := httptest.NewServer(&fakeWitness{head: headOf(log)})
	defer ws.Close()
	store, err := OpenStore(t.TempDir(), "balistid/log")
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{now: time.Now()}
	run := func(n *ntfy) func() {
		push := newTestPusher(t, n, c)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, Config{Origin: "balistid/log", Source: Source{Witness: ws.URL + "/", Relay: relay.URL + "/",
				HTTP: testClient()}, Store: store, Push: push, Limits: DefaultLimits,
				Poll: 2 * time.Millisecond, Now: c.Now, Notify: func(string) error { return nil }})
		}()
		return func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}
	first := &ntfy{}
	stop := run(first)
	waitKey(t, first, KeyLossDispatcher)
	c.add(saveEvery) // the watcher saves its state once a minute of its clock
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if l, _, err := store.Load(); err == nil && l.Rules.Overflow {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the overflow was never saved")
		}
	}
	stop()
	second := &ntfy{}
	defer run(second)()
	waitKey(t, second, KeyLossDispatcher)
}
