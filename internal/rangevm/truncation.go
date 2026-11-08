package rangevm

import (
	"fmt"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a truncation trial (truncation_alarm_per_hour, ADR 0069) besides an alarm trial's posts, watcher and
// restarts and a loss trial's kernel and dispatcher counters: the uptime in ms at the start of each oversized exec,
// in order and comma-separated, and when the sink was read; the ledger's truncated entries before the first exec and
// after it, and its entries of any other loss after it; the watcher's restarts as its verification began; and "yes"
// once the watcher is shown to have verified the log past the last truncated entry, else why not. The posts are the
// first start and every truncated alert.
const (
	FactTruncStartsMS  = "trunc_starts_ms"
	FactTruncEndMS     = "trunc_end_ms"
	FactTruncBefore    = "ledger_truncated_before"
	FactTruncEntries   = "ledger_truncated"
	FactOtherLoss      = "ledger_other_loss"
	FactRestartsVerify = "pi_restarts_verify"
	FactPiVerified     = "pi_verified"
)

// TruncatedTag is the Pi's alert key of more than truncation_alarm_per_hour truncated records in an hour.
const TruncatedTag = "truncated"

// truncationLimit is truncation_alarm_per_hour: more truncated records than this within an hour alert.
const truncationLimit = 10

// TruncationEvery spaces all but the last oversized exec: 2 MB records at 2 execs/s overflowed auditd's dispatcher
// (ADR 0054), and at one every 5 s Laurel is idle between them.
const TruncationEvery = 5 * time.Second

// TruncationWait is how long the guest waits before the last oversized exec and after it before it reads the sink:
// lossAlarm, the bound of the same watcher step that alerts a loss, and a margin. An alert the execs before the last
// raised has reached the sink before the last starts.
const TruncationWait = lossAlarm + 15*time.Second

const (
	truncationWaitMS  = uint64(TruncationWait / time.Millisecond)
	truncationEveryMS = uint64(TruncationEvery / time.Millisecond)
	// how late each of the guest's waits may end
	truncationSlackMS = 1000
	// the window truncation_alarm_per_hour counts in holds the whole run
	truncationHourMS = uint64(time.Hour / time.Millisecond)
)

var truncationFacts = []string{FactTrial, FactPhase, FactKernel, FactTruncStartsMS, FactTruncEndMS, FactTruncBefore,
	FactTruncEntries, FactOtherLoss, FactPosts, FactRefused, FactPiActive, FactRestartsPre, FactRestartsVerify, FactRestartsPost,
	FactPiVerified, FactLostBefore, FactLostAfter, FactOverflowBefore, FactOverflowAfter}

var truncationNums = []string{FactTruncEndMS, FactTruncBefore, FactTruncEntries, FactOtherLoss, FactRefused, FactRestartsPre,
	FactRestartsVerify, FactRestartsPost, FactLostBefore, FactLostAfter}

// judgeTruncation: the closed facts, tr's count of execs each on the guest's schedule, of the ledger's truncated
// entries and none before them, no other loss, the watcher's start at the sink before the first exec, the sink read
// TruncationWait after the last and within the hour, and the watcher shown to have verified it, else INVALID. With
// those, a refused push, a watcher that restarted or is not running at the end is a MISS; then the alerts decide
// (truncationAlerts).
func judgeTruncation(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, truncationFacts, truncationNums)
	if why != "" {
		return Invalid, why
	}
	posts, err := ParsePosts(f[FactPosts])
	if err != nil {
		return Invalid, err.Error()
	}
	starts, why := truncationStarts(f[FactTruncStartsMS], rangejob.TruncatedExecs(tr.Inject))
	if why != "" {
		return Invalid, why
	}
	if v, why := truncationRun(tr, f, n, posts, starts); v != "" {
		return v, why
	}
	return truncationAlerts(tr, posts, starts[len(starts)-1])
}

// truncationStarts reads want exec starts from s, each after the one before: all but the last up to a second after
// TruncationEvery times its place from the first, the last up to a second after TruncationWait from the one before;
// else why not.
func truncationStarts(s string, want int) ([]uint64, string) {
	parts := strings.Split(s, ",")
	if len(parts) != want {
		return nil, fmt.Sprintf("%d oversized execs ran, the trial runs %d", len(parts), want)
	}
	starts := make([]uint64, want)
	for i, p := range parts {
		var err error
		if starts[i], err = plainNumber(p); err != nil {
			return nil, fmt.Sprintf("fact %s is not %d plain numbers", FactTruncStartsMS, want)
		}
	}
	for i := 1; i < want; i++ {
		ref, due := 0, uint64(i)*truncationEveryMS
		if i == want-1 {
			ref, due = i-1, truncationWaitMS
		}
		// the order check comes first, so the gap cannot wrap
		gap := starts[i] - starts[ref]
		switch {
		case starts[i] <= starts[i-1]:
			return nil, fmt.Sprintf("exec %d starts at %d ms, not after exec %d at %d", i+1, starts[i], i, starts[i-1])
		case gap < due || gap > due+truncationSlackMS:
			return nil, fmt.Sprintf("exec %d starts %d ms after exec %d, the trial %d to %d", i+1, gap, ref+1, due, due+truncationSlackMS)
		}
	}
	return starts, ""
}

// truncationRun is INVALID or MISS and why when the run cannot show tr's alert or its absence, else "".
func truncationRun(tr rangejob.Trial, f map[string]string, n map[string]uint64, posts []Post, starts []uint64) (string, string) {
	want := uint64(rangejob.TruncatedExecs(tr.Inject)) //nolint:gosec // a small table value
	start := firstPost(posts, "start", 0)
	first, last := starts[0], starts[len(starts)-1]
	switch {
	case n[FactTruncEndMS]-min(n[FactTruncEndMS], last) < truncationWaitMS:
		return Invalid, fmt.Sprintf("the sink was read %d ms after the last exec, before %s", n[FactTruncEndMS]-min(n[FactTruncEndMS], last),
			TruncationWait)
	case n[FactTruncEndMS]-first > truncationHourMS:
		return Invalid, fmt.Sprintf("the sink was read %d ms after the first exec, over %d", n[FactTruncEndMS]-first, truncationHourMS)
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
	case start == nil || start.MS > first:
		return Invalid, "the sink saw no start of the watcher before the first exec"
	case f[FactPiVerified] != "yes":
		return Invalid, fmt.Sprintf("the watcher is not shown to have verified the truncated entries: \"%s\"", Printable(f[FactPiVerified], 256))
	case n[FactRestartsVerify] != n[FactRestartsPre]:
		// the verification's own start of the watcher resets the count read after it
		return Miss, fmt.Sprintf("the watcher restarted before its verification, restarts %d to %d", n[FactRestartsPre],
			n[FactRestartsVerify])
	case n[FactRestartsPost] < n[FactRestartsVerify]:
		return Invalid, fmt.Sprintf("the watcher's restarts fell from %d to %d over its verification", n[FactRestartsVerify],
			n[FactRestartsPost])
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
