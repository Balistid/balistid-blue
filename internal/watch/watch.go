package watch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	saveEvery = time.Minute
	daily     = 24 * time.Hour
	// RuleVersion names the rules a verification decision follows, in its log line (ENGINEERING.md 3).
	RuleVersion = "balistid/watch v1"
)

// Config is one Pi watching one origin.
type Config struct {
	Origin string
	Source Source
	Store  *Store
	Push   *Pusher
	Limits Limits
	Poll   time.Duration
	Now    func() time.Time
	Notify func(string) error // systemd's watchdog
}

// Run watches until ctx ends. Only a state file that cannot be read stops it: the unit then fails and
// its OnFailure alert reaches the phone.
func Run(ctx context.Context, c Config) error {
	if err := c.check(); err != nil {
		return err
	}
	l, quiet, err := c.Store.Load()
	if err != nil {
		return err
	}
	now := c.Now()
	x := &watcher{c: c, log: l, dog: NewWatchdog(c.Limits, now, quiet, l.Rules.Pending), saved: now, daily: now,
		active: map[Key]bool{}}
	x.dog.capped = l.Rules.Capped && !l.Rules.Final // a restart keeps the cap's condition (ADR 0036)
	x.dog.overflow = l.Rules.Overflow && !l.Rules.Final
	c.Push.Event(KeyStart, fmt.Sprintf("watching the log from %d verified entries", l.Size))
	t := time.NewTicker(c.Poll)
	defer t.Stop()
	for {
		x.step(ctx)
		select {
		case <-ctx.Done():
			x.save(ctx, c.Now())
			return nil
		case <-t.C:
		}
	}
}

// check refuses a config whose zero value would silence an alarm or hang a step rather than fail.
func (c Config) check() error {
	lim := c.Limits
	switch {
	case c.Origin == "" || c.Store == nil || c.Push == nil || c.Now == nil || c.Notify == nil:
		return errors.New("watch: incomplete config")
	case c.Source.HTTP == nil || c.Source.HTTP.Timeout <= 0 || CheckURLs(c.Source.Witness, c.Source.Relay) != nil:
		return errors.New("watch: the source needs its URLs and a client with a timeout")
	case c.Poll <= 0 || lim.Silence <= 0 || lim.Quiet <= 0 || lim.Fresh <= 0 || lim.Truncated < 0 || lim.Grace <= 0 ||
		lim.Settle <= 0 || lim.Gap <= 0:
		return errors.New("watch: a poll interval or limit that is not positive")
	}
	return nil
}

type watcher struct {
	c            Config
	log          Log
	dog          *Watchdog
	fork         string       // the last step's fork or mismatch, until a step verifies
	grown        uint64       // entries verified since the last accept line
	active       map[Key]bool // conditions holding after the last alarm
	saved, daily time.Time
}

func (x *watcher) step(ctx context.Context) {
	// unread, the witness may have grown: only a read that shows it has not lets an announcement quiet
	behind := true
	h, err := x.c.Source.Head(ctx, x.c.Origin)
	if err != nil {
		slog.WarnContext(ctx, "watch: witness unreadable", "err", err)
	} else {
		x.advance(ctx, h)
		behind = h.Size > x.log.Size
	}
	now := x.c.Now()
	conds := x.alarm(ctx, now, behind)
	if now.Sub(x.saved) >= saveEvery {
		x.save(ctx, now)
	}
	if now.Sub(x.daily) >= daily {
		x.daily = now
		x.c.Push.Event(KeyDaily, fmt.Sprintf("%d entries verified, %d alerts holding", x.log.Size, conds))
	}
}

// alarm raises the conditions that hold at now and clears the others, sends what was held back and
// tells systemd the watcher lives. It runs after each step and after each bundle of a long one, so a
// relay that serves slowly delays no alarm.
func (x *watcher) alarm(ctx context.Context, now time.Time, behind bool) int {
	conds := x.dog.Conditions(now, behind)
	if x.fork != "" {
		conds[KeyFork] = x.fork
	}
	for _, k := range conditions {
		text, ok := conds[k]
		switch {
		case ok && !x.active[k]:
			slog.WarnContext(ctx, "watch: condition", "decision", "alarm", "reason", string(k), "rule", RuleVersion, "text", text)
		case !ok && x.active[k]:
			slog.InfoContext(ctx, "watch: condition", "decision", "clear", "reason", string(k), "rule", RuleVersion)
		}
		x.active[k] = ok
		if ok {
			x.c.Push.Hold(k, text)
		} else {
			x.c.Push.Clear(k)
		}
	}
	x.c.Push.Flush()
	if err := x.c.Notify("WATCHDOG=1"); err != nil {
		slog.WarnContext(ctx, "watch: watchdog notify failed", "err", err)
	}
	return len(conds)
}

// advance verifies up to the witness's head, however long the backlog: each request has its timeout, and
// the alarms run between bundles. A fetch that fails is logged and left to the silence and freshness
// alarms: the host withholding bundles looks exactly like that.
func (x *watcher) advance(ctx context.Context, h Head) {
	fetch := func(ctx context.Context, idx, w uint64) ([][]byte, error) {
		b, err := x.c.Source.Bundle(ctx, idx, w)
		x.alarm(ctx, x.c.Now(), true)
		return b, err
	}
	next, f, err := Advance(ctx, x.log, h, fetch)
	now := x.c.Now()
	if err != nil {
		if errors.Is(err, ErrFork) || errors.Is(err, ErrMismatch) {
			if x.fork != err.Error() {
				slog.WarnContext(ctx, "watch: log refused", "decision", "refuse", "reason", reason(err), "rule", RuleVersion,
					"size", x.log.Size, "witness_size", h.Size, "err", err)
			}
			x.fork = err.Error()
			return
		}
		slog.WarnContext(ctx, "watch: log not verified", "err", err)
		return
	}
	x.fork = ""
	x.log = next
	if f.Entries > 0 {
		x.grown += f.Entries
		for _, e := range x.dog.Grew(now, f, next.Rules) {
			slog.WarnContext(ctx, "watch: log alarm", "decision", "alarm", "reason", string(e.Key), "rule", RuleVersion,
				"size", next.Size, "text", e.Text)
			x.c.Push.Event(e.Key, e.Text)
		}
	}
	x.dog.Caught(now)
}

func reason(err error) string {
	if errors.Is(err, ErrFork) {
		return "fork"
	}
	return "mismatch"
}

func (x *watcher) save(ctx context.Context, now time.Time) {
	if err := x.c.Store.Save(x.log, x.dog.Quiet(now)); err != nil {
		slog.ErrorContext(ctx, "watch: state not saved", "err", err)
		x.c.Push.Event(KeySave, "the Pi could not save its state")
		return
	}
	x.c.Push.Clear(KeySave)
	if x.grown > 0 {
		slog.InfoContext(ctx, "watch: log verified", "decision", "accept", "reason", "root", "rule", RuleVersion,
			"size", x.log.Size, "entries", x.grown)
		x.grown = 0
	}
	x.saved = now
}
