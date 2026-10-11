package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const (
	// CanaryKey is the audit rule key on the canary directory (ADR 0017, point 2).
	CanaryKey = "balistid-canary"
	// CanaryEvery is how often a probe goes out and how long it has to come back (canary_interval_s).
	CanaryEvery = 30 * time.Second
	// canaryMisses missed probes in a row make the sensor UNKNOWN.
	canaryMisses = 2
)

// Canary proves the whole path kernel, auditd, Laurel, collector, store: it creates c-<n> in a directory
// an audit rule watches, and probe n counts only once the writer stored the record of that create
// (ADR 0017). Only the writer's goroutine calls its methods; the probe itself runs in a goroutine of
// its own, because an audited syscall can sleep while the kernel backlog is full.
type Canary struct {
	dir      string
	uid, pid int
	n        uint64
	sent     time.Time // when probe n went out; zero when no probe is outstanding
	seen     bool      // probe n was stored
	seenSent time.Time // when the latest stored probe went out
	misses   int
	inFlight chan struct{} // holds a token while a probe goroutine has not returned
	failures chan error
	touch    func(dir string, n uint64) error
}

// NewCanary returns a canary in dir for the collector's own uid and pid and removes c-* files a
// previous run left.
func NewCanary(dir string, uid, pid int) (*Canary, error) {
	left, err := filepath.Glob(filepath.Join(dir, "c-*"))
	if err != nil {
		return nil, fmt.Errorf("collector: canary: %w", err)
	}
	for _, p := range left {
		if err := os.Remove(p); err != nil {
			return nil, fmt.Errorf("collector: canary: %w", err)
		}
	}
	return &Canary{
		dir: dir, uid: uid, pid: pid, inFlight: make(chan struct{}, 1), failures: make(chan error, 1), touch: touch,
	}, nil
}

// Probe sends probe n+1 without waiting for its syscall. While an earlier probe's goroutine has not
// returned no new one starts; scheduled says this was the round's probe, which then counts as a miss.
func (c *Canary) Probe(now time.Time, scheduled bool) {
	select {
	case c.inFlight <- struct{}{}:
	default:
		if scheduled {
			c.misses++
			c.sent = time.Time{}
		}
		return
	}
	c.n++
	c.sent, c.seen = now, false
	n, dir, touch := c.n, c.dir, c.touch
	go func() {
		defer func() { <-c.inFlight }()
		if err := touch(dir, n); err != nil {
			select {
			case c.failures <- err:
			default:
			}
		}
	}()
}

// touch creates c-<n> and removes c-<n-1>; the create is what the audit rule records.
func touch(dir string, n uint64) error {
	f, err := os.OpenFile(filepath.Join(dir, "c-"+strconv.FormatUint(n, 10)), //nolint:gosec // the canary's own directory
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("collector: canary: %w", err)
	}
	return errors.Join(f.Close(), removeIfThere(filepath.Join(dir, "c-"+strconv.FormatUint(n-1, 10))))
}

func removeIfThere(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err //nolint:wrapcheck // joined with the create's error by the caller
	}
	return nil
}

// Failure returns an error a probe goroutine hit, if any, for the writer to log.
func (c *Canary) Failure() error {
	select {
	case err := <-c.failures:
		return err
	default:
		return nil
	}
}

// Observe marks the outstanding probe seen when r, already stored, is its record: the canary key, the
// collector's uid and pid, a successful syscall and the basename c-<n>. A record of an older probe or
// of any other process does not count.
func (c *Canary) Observe(r rawrecord.Record) {
	if c.sent.IsZero() || c.seen || !bytes.Contains(r.Data, []byte(CanaryKey)) {
		return
	}
	if canaryProbe(r.Data, c.uid, c.pid) == "c-"+strconv.FormatUint(c.n, 10) {
		c.seen, c.misses, c.seenSent = true, 0, c.sent
	}
}

// Due ends a probe whose deadline passed without its record: a miss. It reports whether the canary
// now counts as failing (two misses in a row).
func (c *Canary) Due(now time.Time) bool {
	if !c.sent.IsZero() && !c.seen && now.Sub(c.sent) >= CanaryEvery {
		c.misses++
		c.sent = time.Time{}
	}
	return c.misses >= canaryMisses
}

// SeenSince reports whether a probe sent at or after t was stored: only such a probe proves a
// connection made at t.
func (c *Canary) SeenSince(t time.Time) bool { return !c.seenSent.IsZero() && !c.seenSent.Before(t) }

// canaryProbe returns the basename the record's PATH names when the record is a successful syscall of
// uid and pid under the canary key, else "".
func canaryProbe(data []byte, uid, pid int) string {
	var e struct {
		SYSCALL struct {
			Key     json.RawMessage `json:"key"`
			UID     json.Number     `json:"uid"`
			PID     json.Number     `json:"pid"`
			Success string          `json:"success"`
		}
		PATH []struct {
			Name string `json:"name"`
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&e); err != nil || e.SYSCALL.Success != "yes" ||
		e.SYSCALL.UID.String() != strconv.Itoa(uid) || e.SYSCALL.PID.String() != strconv.Itoa(pid) ||
		!hasKey(e.SYSCALL.Key, CanaryKey) {
		return ""
	}
	for _, p := range e.PATH {
		if base := filepath.Base(p.Name); strings.HasPrefix(base, "c-") {
			return base
		}
	}
	return ""
}

// hasKey reports whether an audit key field, a string or a list of strings, holds key.
func hasKey(raw json.RawMessage, key string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == key
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, k := range many {
			if k == key {
				return true
			}
		}
	}
	return false
}
