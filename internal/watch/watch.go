package watch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

const (
	stepLimit   = 5 * time.Minute // one step's fetches, a day's log at worst
	saveEvery   = time.Minute
	daily       = 24 * time.Hour
	eventEvery  = 10 * time.Minute // the same kind of event alerts again after this
	remindEvery = 6 * time.Hour    // a condition that holds alerts again after this
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
	x := &watcher{c: c, log: l, dog: NewWatchdog(c.Limits, now, quiet), saved: now, daily: now}
	c.Push.Raise(KeyStart, fmt.Sprintf("watching the log from %d verified entries", l.Size), 0)
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
	fork         string // the last step's fork or mismatch, until a step verifies
	dirty        bool
	saved, daily time.Time
}

func (x *watcher) step(ctx context.Context) {
	now := x.c.Now()
	behind := false
	h, err := x.c.Source.Head(ctx, x.c.Origin)
	if err != nil {
		slog.WarnContext(ctx, "watch: witness unreadable", "err", err)
	} else {
		behind = h.Size > x.log.Size
		x.advance(ctx, now, h)
		behind = behind && h.Size > x.log.Size
	}
	conds := x.dog.Conditions(now, behind)
	if x.fork != "" {
		conds[KeyFork] = x.fork
	}
	if x.c.Store.Full() {
		conds[KeyStore] = "the Pi's store reached its cap: bundles are no longer kept, verification goes on"
	}
	for _, k := range conditions {
		if text, ok := conds[k]; ok {
			x.c.Push.Raise(k, text, remindEvery)
		} else {
			x.c.Push.Clear(k)
		}
	}
	if x.dirty || now.Sub(x.saved) >= saveEvery {
		x.save(ctx, now)
	}
	if now.Sub(x.daily) >= daily {
		x.daily = now
		x.c.Push.Raise(KeyDaily, fmt.Sprintf("%d entries verified, %d alerts holding", x.log.Size, len(conds)), 0)
	}
	if err := x.c.Notify("WATCHDOG=1"); err != nil {
		slog.WarnContext(ctx, "watch: watchdog notify failed", "err", err)
	}
}

// advance verifies up to the witness's head. A fetch that fails is logged and left to the silence and
// freshness alarms: the host withholding bundles looks exactly like that.
func (x *watcher) advance(ctx context.Context, now time.Time, h Head) {
	sctx, cancel := context.WithTimeout(ctx, stepLimit)
	next, f, err := Advance(sctx, x.log, h, x.c.Source.Bundle, x.c.Store.Keep)
	cancel()
	switch {
	case errors.Is(err, ErrFork) || errors.Is(err, ErrMismatch):
		x.fork = err.Error()
		return
	case err != nil:
		slog.WarnContext(ctx, "watch: log not verified", "err", err)
		return
	}
	x.fork = ""
	x.log = next
	x.dirty = x.dirty || f.Complete
	if f.Entries > 0 {
		for _, e := range x.dog.Grew(now, f, next.Rules) {
			x.c.Push.Raise(e.Key, e.Text, eventEvery)
		}
	}
	x.dog.Caught(now)
}

func (x *watcher) save(ctx context.Context, now time.Time) {
	if err := x.c.Store.Save(x.log, x.dog.Quiet(now)); err != nil {
		slog.ErrorContext(ctx, "watch: state not saved", "err", err)
		x.c.Push.Raise(KeySave, "the Pi could not save its state", eventEvery)
		return
	}
	x.saved, x.dirty = now, false
}
