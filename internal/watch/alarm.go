package watch

import (
	"fmt"
	"time"
)

// Key names one alert: a condition that holds for a while, or a kind of event.
type Key string

// The alerts (ADR 0031).
const (
	KeyFork      Key = "fork"
	KeyLog       Key = "log"
	KeyLoss      Key = "loss"
	KeyHealth    Key = "health"
	KeyUnknown   Key = "unknown"
	KeyLogCap    Key = "logcap"
	KeyTruncated Key = "truncated"
	KeySilence   Key = "silence"
	KeyFresh     Key = "freshness"
	KeySave      Key = "save"
	KeyFinal     Key = "final"
	KeyStart     Key = "start"
	KeyDaily     Key = "daily"
	KeyFailed    Key = "failed"
)

// conditions are the keys that hold until their cause ends: raised on every step, cleared after it.
var conditions = []Key{KeyFork, KeyHealth, KeyTruncated, KeySilence, KeyFresh}

// Limits are when the Pi alerts. The first four follow acceptance numbers (acceptance/0.toml), a minute
// early so that the alert reaches the phone within them.
type Limits struct {
	Silence   time.Duration // silence_alarm_s
	Quiet     time.Duration // announced_quiet_max_h
	Fresh     time.Duration // verify_freshness_s
	Truncated int           // truncation_alarm_per_hour
	Grace     time.Duration // an UNKNOWN that clears by itself
	Settle    time.Duration // growth without an announcement that ends a quiet episode
	Gap       time.Duration // a pause in growth longer than this restarts its run
}

// DefaultLimits are the acceptance numbers of floor 0 and the defaults of ADR 0031.
var DefaultLimits = Limits{Silence: 840 * time.Second, Quiet: 24*time.Hour - time.Minute, Fresh: time.Hour - time.Minute,
	Truncated: 10, Grace: time.Minute, Settle: time.Hour, Gap: 2 * time.Minute}

// WithQuiet returns l with a shorter quiet cap, which only the range sets (ADR 0036): a longer one would hold
// off the silence alarm longer, and one not over Silence would let the silence alarm hide the cap.
func (l Limits) WithQuiet(d time.Duration) (Limits, error) {
	if d <= l.Silence || d > l.Quiet {
		return Limits{}, fmt.Errorf("watch: quiet cap %s must be over the silence limit %s and at most %s", d, l.Silence, l.Quiet)
	}
	l.Quiet = d
	return l, nil
}

// Event is one alert to send.
type Event struct {
	Key  Key
	Text string
}

// Watchdog turns verified steps into alerts. Its times come from the Pi's monotonic clock; a host time
// never reaches it (T22). Not safe for concurrent use.
type Watchdog struct {
	lim     Limits
	grew    time.Time   // the last verified growth, or the start
	run     time.Time   // when the current run of growth began
	fresh   time.Time   // the last step caught up with the witness, or the start
	trunc   []time.Time // truncated records of the last hour
	pending time.Time   // since when the last health is a pending UNKNOWN; zero: it is not
	quiet   *episode
}

// episode is a quiet window opened by an announcement; times are the Pi's.
type episode struct{ opened, announced time.Time }

// NewWatchdog starts at now; quiet is an open episode's age saved before a restart, or nil, and pending
// says the saved log's last health is a pending UNKNOWN, whose grace then starts again.
func NewWatchdog(lim Limits, now time.Time, quiet *time.Duration, pending bool) *Watchdog {
	w := &Watchdog{lim: lim, grew: now, run: now, fresh: now}
	if pending {
		w.pending = now
	}
	if quiet != nil {
		at := now.Add(-*quiet)
		w.quiet = &episode{opened: at, announced: at}
	}
	return w
}

// Grew takes a verified step's findings at now and returns the events they raise.
func (w *Watchdog) Grew(now time.Time, f Findings, r Rules) []Event {
	if f.Entries > 0 {
		if now.Sub(w.grew) > w.lim.Gap {
			w.run = now
		}
		w.grew = now
	}
	if f.Announced > 0 {
		if w.quiet == nil {
			w.quiet = &episode{opened: now}
		}
		w.quiet.announced = now
	}
	if w.quiet != nil && now.Sub(w.grew) <= w.lim.Gap && now.Sub(later(w.run, w.quiet.announced)) >= w.lim.Settle {
		w.quiet = nil
	}
	switch {
	case !r.Pending:
		w.pending = time.Time{}
	case w.pending.IsZero():
		w.pending = now
	}
	// the newest Truncated+1 times decide "more than Truncated within an hour"; the host sets the count
	for range min(f.Truncated, w.lim.Truncated+1) {
		w.trunc = append(w.trunc, now)
	}
	if n := len(w.trunc) - (w.lim.Truncated + 1); n > 0 {
		w.trunc = w.trunc[n:]
	}
	var out []Event
	if f.Broken > 0 {
		out = append(out, Event{KeyLog, fmt.Sprintf("%d new entries break the log's rules, first: %s", f.Broken, f.Problem)})
	}
	if f.Lost > 0 {
		out = append(out, Event{KeyLoss, fmt.Sprintf("%d new entries report lost records", f.Lost)})
	}
	if f.Unknown > 0 {
		out = append(out, Event{KeyUnknown, fmt.Sprintf("%d new health entries report UNKNOWN", f.Unknown)})
	}
	if f.LogCap > 0 {
		out = append(out, Event{KeyLogCap, "the host's log reports it reached host_log_cap_gib: only its final entry may follow"})
	}
	if f.Final {
		out = append(out, Event{KeyFinal, "the log ended with a cosigned final: add the next origin by hand"})
	}
	return out
}

// Caught records a step that ended at the witness's size.
func (w *Watchdog) Caught(now time.Time) { w.fresh = now }

// Conditions returns the conditions that hold at now; behind says the witness is past the Pi.
func (w *Watchdog) Conditions(now time.Time, behind bool) map[Key]string {
	out := map[Key]string{}
	if s := now.Sub(w.grew); s >= w.lim.Silence && !w.quieted(now, behind) {
		out[KeySilence] = fmt.Sprintf("no verified growth of the log for %d s", int64(s.Seconds()))
	}
	if s := now.Sub(w.fresh); s >= w.lim.Fresh {
		out[KeyFresh] = fmt.Sprintf("no verification caught up with the witness for %d s", int64(s.Seconds()))
	}
	for len(w.trunc) > 0 && now.Sub(w.trunc[0]) >= time.Hour {
		w.trunc = w.trunc[1:]
	}
	if len(w.trunc) > w.lim.Truncated {
		out[KeyTruncated] = fmt.Sprintf("%d records stored truncated within the last hour", len(w.trunc))
	}
	if !w.pending.IsZero() && now.Sub(w.pending) >= w.lim.Grace {
		out[KeyHealth] = fmt.Sprintf("the collector has been UNKNOWN for %d s", int64(now.Sub(w.pending).Seconds()))
	}
	return out
}

// quieted: an announcement holds off the silence alarm while the witness has not grown past the Pi,
// up to Quiet from the episode's first announcement (ADR 0031, point 4).
func (w *Watchdog) quieted(now time.Time, behind bool) bool {
	return w.quiet != nil && !behind && now.Sub(w.quiet.opened) < w.lim.Quiet
}

// Quiet is the open episode's age at now, saved so that a restart of the Pi does not restart the cap.
func (w *Watchdog) Quiet(now time.Time) *time.Duration {
	if w.quiet == nil {
		return nil
	}
	d := now.Sub(w.quiet.opened)
	return &d
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
