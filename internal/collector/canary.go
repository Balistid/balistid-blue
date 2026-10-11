package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	seen     bool      // probe n's record was stored
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

// Probe sends probe n+1 without waiting for its syscall. A probe still outstanding past its deadline is
// first counted as missed, so a new probe never hides one. While an earlier probe's goroutine has not
// returned no syscall starts; a scheduled round then still takes number n+1, which nothing can match,
// so it misses at its own deadline, one miss per round as with any other probe.
func (c *Canary) Probe(now time.Time, scheduled bool) {
	c.expire(now)
	select {
	case c.inFlight <- struct{}{}:
	default:
		if scheduled {
			c.n++
			c.sent, c.seen = now, false
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

// touch creates c-<n> and removes every other c-* file, also one a stuck probe left behind a round
// that took a number without a syscall; the create is what the audit rule records.
func touch(dir string, n uint64) error {
	name := "c-" + strconv.FormatUint(n, 10)
	f, err := os.OpenFile(filepath.Join(dir, name), //nolint:gosec // the canary's own directory
		os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("collector: canary: %w", err)
	}
	errs := []error{f.Close()}
	old, err := filepath.Glob(filepath.Join(dir, "c-*"))
	errs = append(errs, err)
	for _, p := range old {
		if filepath.Base(p) != name {
			errs = append(errs, removeIfThere(p))
		}
	}
	return errors.Join(errs...)
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

// Observe marks the outstanding probe seen when r, just stored, is its record: the canary key, the
// collector's uid and pid, a successful syscall and the basename c-<n>. A record of an older probe, of a
// probe past its deadline or of any other process does not count. A store that fails before its next
// commit takes the writer to UNKNOWN, and only a probe sent after the store reopened proves it again.
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
	c.expire(now)
	return c.misses >= canaryMisses
}

// expire counts the outstanding probe as missed once its deadline passed.
func (c *Canary) expire(now time.Time) {
	if !c.sent.IsZero() && !c.seen && now.Sub(c.sent) >= CanaryEvery {
		c.misses++
		c.sent = time.Time{}
	}
}

// SeenSince reports whether a probe sent at or after t was stored: only such a probe proves a
// connection made at t.
func (c *Canary) SeenSince(t time.Time) bool { return !c.seenSent.IsZero() && !c.seenSent.Before(t) }

// canaryProbe returns the basename the record's PATH names when the record is a successful syscall of
// uid and pid under the canary key, else "". Keys are matched exactly: Laurel puts an enriched "PID"
// object beside "pid", which a case-insensitive decoder would take for it.
func canaryProbe(data []byte, uid, pid int) string {
	var top map[string]json.RawMessage
	var sc map[string]json.RawMessage
	var paths []map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil || json.Unmarshal(top["SYSCALL"], &sc) != nil ||
		json.Unmarshal(top["PATH"], &paths) != nil {
		return ""
	}
	var success string
	if json.Unmarshal(sc["success"], &success) != nil || success != "yes" ||
		string(sc["uid"]) != strconv.Itoa(uid) || string(sc["pid"]) != strconv.Itoa(pid) || !hasKey(sc["key"], CanaryKey) {
		return ""
	}
	for _, p := range paths {
		var name string
		if json.Unmarshal(p["name"], &name) == nil {
			if base := filepath.Base(name); strings.HasPrefix(base, "c-") {
				return base
			}
		}
	}
	return ""
}

// hasKey reports whether an audit key field holds key: a string, in which the kernel joins several keys
// with \x01, or a list of strings.
func hasKey(raw json.RawMessage, key string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return slices.Contains(strings.Split(one, "\x01"), key)
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, key)
}
