package rangevm

import (
	"fmt"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// FactLossEntry of a loss trial (ADR 0036, point 4) is "yes" when the ledger logged an entry of the injected
// cause after the injection began (a loss of its stage, for the store also its UNKNOWN), else what it found.
// A loss trial also reports the alarm trial's injection bracket, posts and watcher, and the kernel's lost
// counter around the run and the dispatcher's overflow flag after it.
const FactLossEntry = "loss_entry"

// LossStoreDown starts a full filesystem's loss_entry when, instead of a loss at the cap, the store went down: the
// fill came between its check of free space and its write, and the shard's write failed.
const LossStoreDown = "store down"

// FactCollectorRestarts is the collector's NRestarts before and after a loss trial, "before after".
const FactCollectorRestarts = "collector_restarts"

// lossAlarm bounds the alert at the sink after the loss, somewhere in the injection's bracket: loss_alarm_s's
// 120 s less the minute that delivery has (ADR 0036, point 1), with a poll's slack.
const lossAlarm = 65 * time.Second

var lossFacts = []string{FactTrial, FactPhase, FactKernel, FactInject, FactInjectMS, FactInjectEndMS, FactLossEntry, FactPosts,
	FactRefused, FactPiActive, FactLostBefore, FactLostAfter, FactOverflowAfter, FactCollectorRestarts}

// judgeLoss: the closed facts, a proven injection, a readable watcher and its start through the sink, else
// INVALID; kernel and dispatcher cases are INVALID until balistid-auditstat detects them, and a moved kernel
// lost counter spoils a collector case or the control. With those, a refused token, a watcher not running, no
// entry of the cause in the ledger or no alert within lossAlarm is a MISS, and a bracket too wide to prove
// lossAlarm or a full filesystem's store gone down (LossStoreDown) INVALID; the control MISSes on any alert since
// the watcher started.
func judgeLoss(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, lossFacts, []string{FactInjectMS, FactInjectEndMS, FactRefused, FactLostBefore, FactLostAfter})
	if why != "" {
		return Invalid, why
	}
	posts, err := ParsePosts(f[FactPosts])
	start := firstPost(posts, "start", 0)
	lost := fmt.Sprintf("kernel lost %d to %d, overflow %s", n[FactLostBefore], n[FactLostAfter], Printable(f[FactOverflowAfter], 16))
	switch {
	case err != nil:
		return Invalid, err.Error()
	case f[FactInject] != "ok":
		return Invalid, fmt.Sprintf("the injection is not proven: \"%s\"", Printable(f[FactInject], 256))
	case n[FactInjectEndMS] < n[FactInjectMS]:
		return Invalid, "the injection ends before it begins"
	case f[FactPiActive] == "missing":
		return Invalid, "the watcher's state could not be read"
	case tr.Inject == rangejob.InjectKernel || tr.Inject == rangejob.InjectDispatcher:
		return Invalid, "no detector: balistid-auditstat reports kernel and dispatcher loss (ADR 0036, point 4); " + lost
	case (start == nil || start.MS > n[FactInjectMS]) && n[FactRefused] > 0:
		return Miss, fmt.Sprintf("the sink refused %d of the watcher's pushes: its token is not the range's", n[FactRefused])
	case start == nil || start.MS > n[FactInjectMS]:
		return Invalid, "the sink saw no start of the watcher before the injection"
	case n[FactLostAfter] != n[FactLostBefore] || f[FactOverflowAfter] != "no":
		return Invalid, "the kernel or the dispatcher lost records too: " + lost
	case strings.HasPrefix(f[FactLossEntry], "error"):
		return Invalid, fmt.Sprintf("the ledger could not be read: \"%s\"", Printable(f[FactLossEntry], 256))
	case tr.Inject == rangejob.InjectQueue && !sameRestarts(f[FactCollectorRestarts]):
		// a restarted collector takes its queued losses with it: the queue's loss was never shown
		return Invalid, fmt.Sprintf("the collector restarted during the queue's injection: %s", Printable(f[FactCollectorRestarts], 64))
	case f[FactPiActive] != "active":
		return Miss, fmt.Sprintf("the watcher is %s at the end", Printable(f[FactPiActive], 64))
	}
	if tr.Inject == rangejob.InjectNone {
		// an alert while the watcher warms up, before the control's moment of injection, is a false alarm too
		if alarm := lossPost(tr, posts, 0); alarm != nil {
			return Miss, fmt.Sprintf("a %s alert at %d ms without a loss", alarm.Tag, alarm.MS)
		}
		return Pass, "no loss alert without a loss"
	}
	alarm := lossPost(tr, posts, n[FactInjectMS])
	switch {
	case tr.Inject == rangejob.InjectFullFS && strings.HasPrefix(f[FactLossEntry], LossStoreDown):
		// the race of the fill and a write is the store's, not the alarm's: the cap was never met
		return Invalid, fmt.Sprintf("the fill raced a store write, the store went down: \"%s\"", Printable(f[FactLossEntry], 256))
	case f[FactLossEntry] != "yes":
		return Miss, fmt.Sprintf("no entry of the loss in the ledger: \"%s\"", Printable(f[FactLossEntry], 256))
	case alarm == nil:
		return Miss, "no loss alert reached the sink"
	}
	// the loss fell somewhere in the bracket: the alert's youngest delay counts from its end, its oldest from its start
	young, old := msDuration(alarm.MS-min(alarm.MS, n[FactInjectEndMS])), msDuration(alarm.MS-n[FactInjectMS])
	switch {
	case young > lossAlarm:
		return Miss, fmt.Sprintf("%s alert %s after the injection, over %s", alarm.Tag, young, lossAlarm)
	case old > lossAlarm:
		return Invalid, fmt.Sprintf("%s alert %s to %s after the injection: its bracket is too wide to prove %s", alarm.Tag,
			young, old, lossAlarm)
	}
	return Pass, fmt.Sprintf("%s alert %s to %s after the injection", alarm.Tag, young, old)
}

// sameRestarts is "n n": the collector's restart count did not move.
func sameRestarts(v string) bool {
	before, after, ok := strings.Cut(v, " ")
	_, err := plainNumber(before)
	return ok && err == nil && before == after
}

// lossPost is the first alert of a loss after ms: a loss, for the store also its UNKNOWN, for the control either.
func lossPost(tr rangejob.Trial, posts []Post, ms uint64) *Post {
	for i := range posts {
		p := &posts[i]
		unknown := p.Tag == "unknown" && (tr.Inject == rangejob.InjectStore || tr.Inject == rangejob.InjectNone)
		if p.MS > ms && (p.Tag == "loss" || unknown) {
			return p
		}
	}
	return nil
}

// lossMeasures is a loss run's alert delay after its injection began, the bound a PASS proves, when it came.
func lossMeasures(tr rangejob.Trial, o Outcome, m map[string]uint64) {
	f, n, why := probeFacts(tr, o, lossFacts, []string{FactInjectMS, FactInjectEndMS})
	if why != "" {
		return
	}
	posts, err := ParsePosts(f[FactPosts])
	if alarm := lossPost(tr, posts, n[FactInjectMS]); err == nil && alarm != nil {
		m[MeasureAlarmMS] = alarm.MS - n[FactInjectMS]
	}
}
