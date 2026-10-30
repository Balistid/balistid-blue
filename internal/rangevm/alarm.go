package rangevm

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of an alarm trial (ADR 0036): whether the injection is proven, and when, on the guest's uptime in ms,
// as the range's ntfy sink records its posts; when the cosigned size last grew before it and whether it grew
// after; the posts the sink accepted with the range token, "ms:tag" joined by commas or "none", and how many
// it refused; the watcher's restarts before and after; the second announcement of quiet-again or "none"; and
// the largest gap between cosigned sizes before the injection, a trend for cosign_gap_s.
const (
	FactInject       = "inject"
	FactInjectMS     = "inject_ms"
	FactCosignedMS   = "cosigned_ms"
	FactGrownAfter   = "grown_after"
	FactPosts        = "posts"
	FactRefused      = "posts_refused"
	FactRestartsPre  = "pi_restarts_before"
	FactRestartsPost = "pi_restarts_after"
	FactAgainMS      = "again_ms"
	FactCosignGapMS  = "cosign_gap_ms"
	// MeasureAlarmMS is how long after the silence began, or the first announcement, the alert came.
	MeasureAlarmMS = "alarm_ms"

	maxPosts = 64
)

// The windows the sink must see the silence alert in. The Pi alerts at 840 s, a minute before
// silence_alarm_s, which is delivery's; it sees growth a poll after the cosign, and alerts at the next poll.
// The quiet cap is the range's 20 min (range/balistid-pi-range.conf); the announcing client returns up to a
// poll after the Pi saw the announcement. A cap restarted by quiet-again's second announcement alerts after
// the window.
const (
	silenceFrom = 825 * time.Second
	silenceTo   = 845 * time.Second
	RangeQuiet  = 20 * time.Minute
	quietFrom   = RangeQuiet - 5*time.Second
	quietTo     = RangeQuiet + time.Minute
	againAfter  = 2 * time.Minute
	// SettleAfter is how long after the injection a cosign already on its way may still land; growth after it
	// is growth the injection did not stop (grown_after).
	SettleAfter = 30 * time.Second
)

var alarmFacts = []string{FactTrial, FactPhase, FactKernel, FactInject, FactInjectMS, FactCosignedMS, FactGrownAfter, FactPosts,
	FactRefused, FactRestartsPre, FactRestartsPost, FactAgainMS, FactCosignGapMS}

// Post is one push the sink accepted: the guest's uptime in ms and the alert's key.
type Post struct {
	MS  uint64
	Tag string
}

// ParsePosts reads a posts fact: "none", or up to maxPosts "ms:tag" in time order, tags lowercase.
func ParsePosts(s string) ([]Post, error) {
	if s == "none" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > maxPosts {
		return nil, fmt.Errorf("%d posts, over %d", len(parts), maxPosts)
	}
	posts := make([]Post, 0, len(parts))
	for _, p := range parts {
		ms, tag, ok := strings.Cut(p, ":")
		n, err := plainNumber(ms)
		if !ok || err != nil || tag == "" || len(tag) > 16 || strings.Trim(tag, "abcdefghijklmnopqrstuvwxyz") != "" {
			return nil, fmt.Errorf("post \"%s\" is not ms:tag", Printable(p, 64))
		}
		if len(posts) > 0 && n < posts[len(posts)-1].MS {
			return nil, fmt.Errorf("posts out of time order at %d", n)
		}
		posts = append(posts, Post{n, tag})
	}
	return posts, nil
}

// judgeAlarm: the closed facts and a proven injection that stopped the cosigned size, with the watcher's
// start pushed through the sink before it, else INVALID: the observer or the injection failed. A silence
// alert before the injection is INVALID too, the range was not quiet. With those, a restarted watcher, no
// silence alert, or one outside the window is a MISS.
func judgeAlarm(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, alarmFacts, []string{FactInjectMS, FactCosignedMS, FactRefused, FactRestartsPre,
		FactRestartsPost, FactCosignGapMS})
	if why != "" {
		return Invalid, why
	}
	posts, err := ParsePosts(f[FactPosts])
	switch {
	case err != nil:
		return Invalid, err.Error()
	case f[FactInject] != "ok":
		return Invalid, fmt.Sprintf("the injection is not proven: \"%s\"", Printable(f[FactInject], 256))
	case f[FactGrownAfter] != "no":
		return Invalid, fmt.Sprintf("the cosigned size grew after the injection: \"%s\"", Printable(f[FactGrownAfter], 64))
	case n[FactCosignedMS] > n[FactInjectMS]+uint64(SettleAfter/time.Millisecond):
		return Invalid, "the last growth came over 30 s after the injection"
	}
	again, why := againMS(tr, f[FactAgainMS], n[FactInjectMS])
	if why != "" {
		return Invalid, why
	}
	start, alarm := firstPost(posts, "start", 0), firstPost(posts, "silence", 0)
	switch {
	case start == nil || start.MS > n[FactInjectMS]:
		if n[FactRefused] > 0 {
			return Miss, fmt.Sprintf("the sink refused %d of the watcher's pushes: its token is not the range's", n[FactRefused])
		}
		return Invalid, "the sink saw no start of the watcher before the injection"
	case alarm != nil && alarm.MS <= n[FactInjectMS]:
		return Invalid, fmt.Sprintf("a silence alert at %d ms, before the injection at %d", alarm.MS, n[FactInjectMS])
	case n[FactRestartsPost] != n[FactRestartsPre]:
		return Miss, fmt.Sprintf("the watcher restarted (%d to %d), which restarts its silence", n[FactRestartsPre], n[FactRestartsPost])
	case alarm == nil:
		return Miss, "no silence alert reached the sink"
	}
	from, lo, hi := n[FactCosignedMS], silenceFrom, silenceTo
	if tr.Metric == rangejob.MetricQuiet {
		from, lo, hi = n[FactInjectMS], quietFrom, quietTo
	}
	at := msDuration(alarm.MS - from)
	if at < lo || at > hi {
		return Miss, fmt.Sprintf("silence alert %s after %d ms, outside %s to %s%s", at, from, lo, hi, again)
	}
	return Pass, fmt.Sprintf("silence alert %s after %d ms%s", at, from, again)
}

// againMS checks quiet-again's second announcement: after the first by at least againAfter, so a cap it
// restarted alerts outside the window; any other trial has none.
func againMS(tr rangejob.Trial, v string, inject uint64) (string, string) {
	if tr.Inject != rangejob.InjectQuietAgain {
		if v != "none" {
			return "", "a second announcement in a trial without one"
		}
		return "", ""
	}
	ms, err := plainNumber(v)
	if err != nil || ms < inject+uint64(againAfter/time.Millisecond) {
		return "", fmt.Sprintf("the second announcement \"%s\" is not %s after the first", Printable(v, 64), againAfter)
	}
	return fmt.Sprintf(" (announced again %s after the first)", msDuration(ms-inject)), ""
}

// msDuration is ms as a Duration; ms beyond a Duration's range comes out as the longest one, past every window.
func msDuration(ms uint64) time.Duration {
	if ms > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return math.MaxInt64
	}
	return time.Duration(ms) * time.Millisecond
}

// firstPost is the first post of tag after ms, or nil.
func firstPost(posts []Post, tag string, after uint64) *Post {
	for i := range posts {
		if posts[i].Tag == tag && posts[i].MS >= after {
			return &posts[i]
		}
	}
	return nil
}

// alarmMeasures are an alarm run's largest cosign gap and, when it came, the alert's delay.
func alarmMeasures(tr rangejob.Trial, o Outcome, m map[string]uint64) {
	f, n, why := probeFacts(tr, o, alarmFacts, []string{FactInjectMS, FactCosignedMS, FactCosignGapMS})
	if why != "" {
		return
	}
	m[FactCosignGapMS] = n[FactCosignGapMS]
	posts, err := ParsePosts(f[FactPosts])
	alarm := firstPost(posts, "silence", n[FactInjectMS]+1)
	from := n[FactCosignedMS]
	if tr.Metric == rangejob.MetricQuiet {
		from = n[FactInjectMS]
	}
	if err == nil && alarm != nil && alarm.MS >= from {
		m[MeasureAlarmMS] = alarm.MS - from
	}
}

// FormatPost is how the guest writes one post into the posts fact.
func FormatPost(p Post) string { return strconv.FormatUint(p.MS, 10) + ":" + p.Tag }
