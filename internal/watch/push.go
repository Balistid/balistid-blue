package watch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxToken    = 256
	maxPushResp = 4 << 10
)

// titles and priorities of the alerts, fixed: nothing the host sends becomes a title.
var pushTitle = map[Key]struct {
	title string
	prio  int
}{
	KeyFork: {"Balistid: log fork", 5}, KeyLog: {"Balistid: log rules broken", 5}, KeyLoss: {"Balistid: records lost", 5},
	KeyUnknown: {"Balistid: collector UNKNOWN", 5}, KeyHealth: {"Balistid: collector UNKNOWN", 5},
	KeyTruncated: {"Balistid: truncated records", 5}, KeySilence: {"Balistid: host silent", 5},
	KeyFresh: {"Balistid: Pi not verifying", 4}, KeyStore: {"Balistid: Pi store", 4}, KeySave: {"Balistid: Pi state", 4}, KeyFailed: {"Balistid: Pi failed", 4},
	KeyFinal: {"Balistid: log ended", 4}, KeyStart: {"Balistid: Pi watching", 3}, KeyDaily: {"Balistid: daily status", 2},
}

// Pusher sends alerts to an ntfy topic. Raise only queues, so a slow or failing push never holds up
// verification; one message per key waits at most, and one goroutine (Run) sends.
type Pusher struct {
	url, token string
	http       *http.Client
	now        func() time.Time
	backoff    []time.Duration

	mu    sync.Mutex
	last  map[Key]time.Time // when a key was last queued
	held  map[Key]int       // raised again since then, within its interval
	queue map[Key]string
	wake  chan struct{}
}

// NewPusher posts to url (an ntfy topic) with token as its bearer. The token is never logged.
func NewPusher(url, token string, c *http.Client, now func() time.Time) (*Pusher, error) {
	if err := checkPushURL(url); err != nil {
		return nil, err
	}
	if token == "" || len(token) > maxToken || strings.ContainsFunc(token, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return nil, errors.New("watch: the push token must be 1 to 256 visible ASCII characters")
	}
	if c == nil || c.Timeout <= 0 {
		return nil, errors.New("watch: the push client needs a timeout")
	}
	return &Pusher{url: url, token: token, http: c, now: now,
		backoff: []time.Duration{5 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute},
		last:    map[Key]time.Time{}, held: map[Key]int{}, queue: map[Key]string{}, wake: make(chan struct{}, 1)}, nil
}

// Raise queues text under key unless key was queued less than every ago; then it is counted and the
// next message says how many were held back.
func (p *Pusher) Raise(key Key, text string, every time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if t, ok := p.last[key]; ok && now.Sub(t) < every {
		p.held[key]++
		return
	}
	p.last[key] = now
	if n := p.held[key]; n > 0 {
		text += fmt.Sprintf(" (and %d more since the last alert)", n)
	}
	p.held[key] = 0
	p.queue[key] = text
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Clear ends a condition: when it holds again, it alerts at once.
func (p *Pusher) Clear(key Key) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.last, key)
	p.held[key] = 0
}

// Run sends queued messages until ctx ends, retrying a failed one with backoff unless a newer one of
// the same key replaced it.
func (p *Pusher) Run(ctx context.Context) {
	fails := 0
	for {
		key, text, ok := p.next()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-p.wake:
				continue
			}
		}
		if err := p.Send(ctx, key, text); err != nil {
			slog.WarnContext(ctx, "watch: push failed", "key", string(key), "err", err)
			p.requeue(key, text)
			t := time.NewTimer(p.backoff[min(fails, len(p.backoff)-1)])
			fails++
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}
		fails = 0
	}
}

func (p *Pusher) next() (Key, string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queue) == 0 {
		return "", "", false
	}
	keys := make([]Key, 0, len(p.queue))
	for k := range p.queue {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b Key) int {
		if d := pushTitle[b].prio - pushTitle[a].prio; d != 0 {
			return d
		}
		return strings.Compare(string(a), string(b))
	})
	k := keys[0]
	text := p.queue[k]
	delete(p.queue, k)
	return k, text, true
}

func (p *Pusher) requeue(key Key, text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, newer := p.queue[key]; !newer {
		p.queue[key] = text
	}
}

// Send posts one message now.
func (p *Pusher) Send(ctx context.Context, key Key, text string) error {
	t, ok := pushTitle[key]
	if !ok {
		return fmt.Errorf("watch: no alert %q", key)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, strings.NewReader(text))
	if err != nil {
		return fmt.Errorf("watch: push request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Title", t.title)
	req.Header.Set("Priority", strconv.Itoa(t.prio))
	req.Header.Set("Tags", string(key))
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("watch: push: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxPushResp))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("watch: push: %s", resp.Status)
	}
	return nil
}
