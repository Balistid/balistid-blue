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
	KeyFresh: {"Balistid: Pi not verifying", 4}, KeySave: {"Balistid: Pi state", 4}, KeyFailed: {"Balistid: Pi failed", 4},
	KeyFinal: {"Balistid: log ended", 4}, KeyStart: {"Balistid: Pi watching", 3}, KeyDaily: {"Balistid: daily status", 2},
}

// The same key alerts again after spacing at the earliest, so a flapping condition cannot flood the
// topic; what is held back then goes out once spacing has passed. A condition that holds reminds every
// remind.
const (
	spacing = time.Minute
	remind  = 6 * time.Hour
)

// Pusher sends alerts to an ntfy topic. Its methods only queue, so a slow or failing push never holds
// up verification. Per key one message waits at most: alerts merge into it, counted, with the latest
// text, whether they come within the spacing or while a send fails, so none is dropped unseen.
type Pusher struct {
	url, token string
	http       *http.Client
	now        func() time.Time
	backoff    []time.Duration

	mu     sync.Mutex
	sent   map[Key]time.Time // when a key was last queued
	active map[Key]bool      // conditions that hold
	held   map[Key]msg       // raised within spacing, queued once it passed
	queue  map[Key]msg
	wake   chan struct{}
}

// msg is n alerts of one key, text the latest.
type msg struct {
	n    int
	text string
}

func (m msg) merge(o msg) msg { return msg{n: m.n + o.n, text: o.text} }

func (m msg) render() string {
	if m.n > 1 {
		return fmt.Sprintf("%s (the latest of %d alerts)", m.text, m.n)
	}
	return m.text
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
		sent:    map[Key]time.Time{}, active: map[Key]bool{}, held: map[Key]msg{}, queue: map[Key]msg{},
		wake: make(chan struct{}, 1)}, nil
}

// Event alerts one occurrence.
func (p *Pusher) Event(key Key, text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raise(key, msg{1, text})
}

// Hold alerts a condition when it starts, then every remind while it holds.
func (p *Pusher) Hold(key Key, text string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case !p.active[key]:
		p.active[key] = true
		p.raise(key, msg{1, text})
	case p.now().Sub(p.sent[key]) >= remind:
		p.enqueue(key, msg{1, text})
	}
}

// Clear ends a condition: when it holds again, it alerts again, spacing allowing. A start that is still
// held back is sent all the same.
func (p *Pusher) Clear(key Key) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, key)
}

// Flush queues what was held back once its spacing has passed.
func (p *Pusher) Flush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, m := range p.held {
		if p.now().Sub(p.sent[key]) >= spacing {
			delete(p.held, key)
			p.enqueue(key, m)
		}
	}
}

func (p *Pusher) raise(key Key, m msg) {
	if t, ok := p.sent[key]; ok && p.now().Sub(t) < spacing {
		p.held[key] = p.held[key].merge(m)
		return
	}
	p.enqueue(key, m)
}

// enqueue merges m into the key's waiting message, or makes it the waiting one.
func (p *Pusher) enqueue(key Key, m msg) {
	p.sent[key] = p.now()
	if h, ok := p.held[key]; ok {
		delete(p.held, key)
		m = h.merge(m)
	}
	if q, ok := p.queue[key]; ok {
		m = q.merge(m)
	}
	p.queue[key] = m
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run sends queued messages until ctx ends; a failed one goes back into its key's message, with backoff.
func (p *Pusher) Run(ctx context.Context) {
	fails := 0
	for {
		key, m, ok := p.next()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-p.wake:
				continue
			}
		}
		if err := p.Send(ctx, key, m.render()); err != nil {
			slog.WarnContext(ctx, "watch: push failed", "key", string(key), "err", err)
			p.requeue(key, m)
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

func (p *Pusher) next() (Key, msg, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queue) == 0 {
		return "", msg{}, false
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
	m := p.queue[k]
	delete(p.queue, k)
	return k, m, true
}

// requeue puts a failed message back before whatever of its key came since, so its count stays.
func (p *Pusher) requeue(key Key, m msg) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if q, ok := p.queue[key]; ok {
		m = m.merge(q)
	}
	p.queue[key] = m
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
		return fmt.Errorf("watch: push: status %d", resp.StatusCode)
	}
	return nil
}
