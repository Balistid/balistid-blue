package rangevm

import (
	"fmt"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a truncation trial (truncation_alarm_per_hour, ADR 0069) besides an alarm trial's posts, watcher and
// restarts and a loss trial's kernel and dispatcher counters: how many oversized execs ran, the uptime in ms at the
// start of the first and the last and when the sink was read; the ledger's truncated entries before the first exec
// and after it, and its entries of any other loss after it; and "yes" once the watcher is shown to have verified the
// log past the last truncated entry, else why not. The posts are the first start and every truncated alert.
const (
	FactTruncExecs   = "trunc_execs"
	FactTruncFirstMS = "trunc_first_ms"
	FactTruncLastMS  = "trunc_last_ms"
	FactTruncEndMS   = "trunc_end_ms"
	FactTruncBefore  = "ledger_truncated_before"
	FactTruncEntries = "ledger_truncated"
	FactOtherLoss    = "ledger_other_loss"
	FactPiVerified   = "pi_verified"
)

// TruncatedTag is the Pi's alert key of more than truncation_alarm_per_hour truncated records in an hour.
const TruncatedTag = "truncated"

// truncationLimit is truncation_alarm_per_hour: more truncated records than this within an hour alert.
const truncationLimit = 10

// TruncationWait is how long after the last oversized exec the guest reads the sink: lossAlarm, the bound of the
// same watcher step that alerts a loss, and a margin.
const TruncationWait = lossAlarm + 15*time.Second

const truncationWaitMS = uint64(TruncationWait / time.Millisecond)

var truncationFacts = []string{FactTrial, FactPhase, FactKernel, FactTruncExecs, FactTruncFirstMS, FactTruncLastMS, FactTruncEndMS,
	FactTruncBefore, FactTruncEntries, FactOtherLoss, FactPosts, FactRefused, FactPiActive, FactRestartsPre, FactRestartsPost,
	FactPiVerified, FactLostBefore, FactLostAfter, FactOverflowBefore, FactOverflowAfter}

var truncationNums = []string{FactTruncExecs, FactTruncFirstMS, FactTruncLastMS, FactTruncEndMS, FactTruncBefore, FactTruncEntries,
	FactOtherLoss, FactRefused, FactRestartsPre, FactRestartsPost, FactLostBefore, FactLostAfter}

// judgeTruncation: the closed facts, tr's count of execs and of the ledger's truncated entries and none before them,
// no other loss, the watcher's start at the sink before the first exec, the sink read TruncationWait after the last
// and the watcher shown to have verified it, else INVALID. With those, a refused push, a watcher that restarted or
// is not running at the end is a MISS; then the alerts decide (truncationAlerts).
func judgeTruncation(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, truncationFacts, truncationNums)
	if why != "" {
		return Invalid, why
	}
	posts, err := ParsePosts(f[FactPosts])
	if err != nil {
		return Invalid, err.Error()
	}
	if v, why := truncationRun(tr, f, n, posts); v != "" {
		return v, why
	}
	return truncationAlerts(tr, posts, n[FactTruncLastMS])
}

// truncationRun is INVALID or MISS and why when the run cannot show tr's alert or its absence, else "".
func truncationRun(tr rangejob.Trial, f map[string]string, n map[string]uint64, posts []Post) (string, string) {
	want := uint64(rangejob.TruncatedExecs(tr.Inject)) //nolint:gosec // a small table value
	start := firstPost(posts, "start", 0)
	switch {
	case want == 0 || n[FactTruncExecs] != want:
		return Invalid, fmt.Sprintf("%d oversized execs ran, the trial runs %d", n[FactTruncExecs], want)
	case n[FactTruncLastMS] < n[FactTruncFirstMS]:
		return Invalid, "the last exec starts before the first"
	case n[FactTruncEndMS] < n[FactTruncLastMS] || n[FactTruncEndMS]-n[FactTruncLastMS] < truncationWaitMS:
		return Invalid, fmt.Sprintf("the sink was read %d ms after the last exec, before %s", n[FactTruncEndMS]-min(n[FactTruncEndMS],
			n[FactTruncLastMS]), TruncationWait)
	case n[FactTruncBefore] != 0 || n[FactTruncEntries] != want:
		return Invalid, fmt.Sprintf("the ledger holds %d truncated entries before the execs and %d after, want 0 and %d",
			n[FactTruncBefore], n[FactTruncEntries], want)
	case n[FactOtherLoss] != 0 || n[FactLostAfter] != n[FactLostBefore] || f[FactOverflowBefore] != "no" || f[FactOverflowAfter] != "no":
		return Invalid, fmt.Sprintf("records lost besides the truncated: %d loss entries, kernel lost %d to %d, overflow %s to %s",
			n[FactOtherLoss], n[FactLostBefore], n[FactLostAfter], Printable(f[FactOverflowBefore], 16), Printable(f[FactOverflowAfter], 16))
	case f[FactPiActive] == "missing":
		return Invalid, "the watcher's state could not be read"
	case n[FactRefused] > 0:
		// a refused push may be the alert itself
		return Miss, fmt.Sprintf("the sink refused %d of the watcher's pushes: its token is not the range's", n[FactRefused])
	case start == nil || start.MS > n[FactTruncFirstMS]:
		return Invalid, "the sink saw no start of the watcher before the first exec"
	case f[FactPiVerified] != "yes":
		return Invalid, fmt.Sprintf("the watcher is not shown to have verified the truncated entries: \"%s\"", Printable(f[FactPiVerified], 256))
	case f[FactPiActive] != "active" || n[FactRestartsPost] != n[FactRestartsPre]:
		return Miss, fmt.Sprintf("the watcher is %s at the end, restarts %d to %d", Printable(f[FactPiActive], 64),
			n[FactRestartsPre], n[FactRestartsPost])
	}
	return "", ""
}

// truncationAlerts: over the limit, exactly one truncated alert after the last exec began at lastMS, within
// lossAlarm of it, passes; at the limit only no truncated alert passes.
func truncationAlerts(tr rangejob.Trial, posts []Post, lastMS uint64) (string, string) {
	var alerts []Post
	for _, p := range posts {
		if p.Tag == TruncatedTag {
			alerts = append(alerts, p)
		}
	}
	if rangejob.TruncatedExecs(tr.Inject) <= truncationLimit {
		if len(alerts) > 0 {
			return Miss, fmt.Sprintf("a truncated alert at %d ms for %d truncated records", alerts[0].MS, rangejob.TruncatedExecs(tr.Inject))
		}
		return Pass, fmt.Sprintf("no truncated alert for %d truncated records", rangejob.TruncatedExecs(tr.Inject))
	}
	switch {
	case len(alerts) == 0:
		return Miss, "no truncated alert reached the sink"
	case alerts[0].MS <= lastMS:
		return Miss, fmt.Sprintf("a truncated alert at %d ms, before the last exec at %d", alerts[0].MS, lastMS)
	case len(alerts) > 1:
		return Miss, fmt.Sprintf("%d truncated alerts, the second at %d ms", len(alerts), alerts[1].MS)
	case msDuration(alerts[0].MS-lastMS) > lossAlarm:
		return Miss, fmt.Sprintf("the truncated alert %s after the last exec, over %s", msDuration(alerts[0].MS-lastMS), lossAlarm)
	}
	return Pass, fmt.Sprintf("one truncated alert %s after the last exec", msDuration(alerts[0].MS-lastMS))
}
