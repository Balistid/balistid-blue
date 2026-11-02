package rangevm

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	logentry "github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// FactLossEntry of a loss trial (ADR 0036, point 4) is "yes" when the ledger logged an entry of the injected
// cause after the injection began (a loss of its stage, for the store also its UNKNOWN), else what it found.
// A loss trial also reports the alarm trial's injection bracket, posts and watcher, and the kernel's lost
// counter around the run and the dispatcher's overflow flag before it, as the state file read unsignalled, and
// after it.
const FactLossEntry = "loss_entry"

// Facts of a loss trial's bracket, in uptime ms (ADR 0039, point 4): where the loss fell. A collector case's is
// its injection's; the kernel's is its own log's time of the first lost record, in uptime by two marks (ADR
// 0045); the dispatcher's from the mtime of the last state file that read no to that of the first that read yes.
const (
	FactLossFromMS = "loss_from_ms"
	FactLossToMS   = "loss_to_ms"
)

// FactOKAfterResume of a transient kernel trial is the ms from auditd's resume to the ledger's first health OK at
// or after it, "0" when its health was OK then, "none" without one; "-" in every other loss trial.
const FactOKAfterResume = "ok_after_resume_ms"

// FactFirstUnknown of a loss trial is the reason of the ledger's first health UNKNOWN after the injection began,
// "none" without one, "before N" when the ledger logged one within LossAlarm before it: a store trial's unknown alert is its cause's only when that reason is the store's (ADR 0039,
// point 3), not another UNKNOWN that came first.
const FactFirstUnknown = "first_unknown"

// lossTags are the Pi's alert keys of the collector's loss cases, one per stage (internal/watch, ADR 0039 point 1).
var lossTags = map[string]string{rangejob.InjectQueue: "lossqueue", rangejob.InjectFullFS: "losscap", rangejob.InjectStore: "lossstore",
	rangejob.InjectKernelTransient: "losskernel", rangejob.InjectKernelSustained: "losskernel", rangejob.InjectDispatcher: "lossdispatcher"}

// LossTag is the alert key of loss case inject's stage, "" for a case without one.
func LossTag(inject string) string { return lossTags[inject] }

// FactCollectorRestarts is the collector's NRestarts before and after a loss trial, "before after".
const FactCollectorRestarts = "collector_restarts"

// lossAlarm bounds the alert at the sink after the loss, somewhere in the injection's bracket: loss_alarm_s's
// 120 s less the minute that delivery has (ADR 0036, point 1), with a poll's slack.
const lossAlarm = 65 * time.Second

// LossAlarm is lossAlarm for the guest: an UNKNOWN the ledger logged that long before an injection can still have
// its alert land after it.
const LossAlarm = lossAlarm

var lossFacts = []string{FactTrial, FactPhase, FactKernel, FactInject, FactInjectMS, FactInjectEndMS, FactLossFromMS, FactLossToMS,
	FactLossEntry, FactPosts, FactRefused, FactPiActive, FactLostBefore, FactLostAfter, FactOverflowBefore, FactOverflowAfter,
	FactCollectorRestarts, FactFirstUnknown, FactOKAfterResume}

// kernelLoss is whether inject is one of the kernel's two shapes.
func kernelLoss(inject string) bool {
	return inject == rangejob.InjectKernelTransient || inject == rangejob.InjectKernelSustained
}

// judgeLoss: the closed facts, a proven injection, a loss bracket inside the run after the injection began, a
// readable watcher and its start through the sink, an unset overflow flag before the injection, else INVALID; a
// lost counter or a flag moved by another case than its own spoils the run. With those, a refused token, a watcher
// not running, no entry of the cause in the ledger or no alert within lossAlarm of the bracket's end is a MISS, an
// alert before the bracket or one whose bracket is too wide to prove lossAlarm INVALID, and a transient kernel run
// without health OK within lossAlarm of the resume a MISS; the control MISSes on any alert since the watcher started.
func judgeLoss(tr rangejob.Trial, o Outcome) (string, string) {
	f, n, why := probeFacts(tr, o, lossFacts, []string{FactInjectMS, FactInjectEndMS, FactLossFromMS, FactLossToMS, FactRefused,
		FactLostBefore, FactLostAfter})
	if why != "" {
		return Invalid, why
	}
	posts, err := ParsePosts(f[FactPosts])
	start := firstPost(posts, "start", 0)
	lost := fmt.Sprintf("kernel lost %d to %d, overflow %s", n[FactLostBefore], n[FactLostAfter], Printable(f[FactOverflowAfter], 16))
	kernelMoved, flagSet := n[FactLostAfter] != n[FactLostBefore], f[FactOverflowAfter] != "no"
	switch {
	case err != nil:
		return Invalid, err.Error()
	case f[FactInject] != "ok":
		return Invalid, fmt.Sprintf("the injection is not proven: \"%s\"", Printable(f[FactInject], 256))
	case n[FactInjectEndMS] < n[FactInjectMS]:
		return Invalid, "the injection ends before it begins"
	case n[FactLossToMS] < n[FactInjectMS] || n[FactLossToMS] < n[FactLossFromMS]:
		// a dispatcher's may start before the injection, at the last state file written before it
		return Invalid, fmt.Sprintf("the loss's bracket %d to %d ms does not end after the injection's start at %d", n[FactLossFromMS],
			n[FactLossToMS], n[FactInjectMS])
	case f[FactPiActive] == "missing":
		return Invalid, "the watcher's state could not be read"
	case (start == nil || start.MS > n[FactInjectMS]) && n[FactRefused] > 0:
		return Miss, fmt.Sprintf("the sink refused %d of the watcher's pushes: its token is not the range's", n[FactRefused])
	case start == nil || start.MS > n[FactInjectMS]:
		return Invalid, "the sink saw no start of the watcher before the injection"
	case f[FactOverflowBefore] != "no":
		return Invalid, fmt.Sprintf("the dispatcher's overflow flag read \"%s\" before the injection", Printable(f[FactOverflowBefore], 16))
	case kernelLoss(tr.Inject) && (!kernelMoved || flagSet):
		return Invalid, "the kernel did not lose, or the dispatcher lost too: " + lost
	case tr.Inject == rangejob.InjectDispatcher && kernelMoved:
		return Invalid, "the kernel lost records too: " + lost
	case !kernelLoss(tr.Inject) && tr.Inject != rangejob.InjectDispatcher && (kernelMoved || flagSet):
		return Invalid, "the kernel or the dispatcher lost records too: " + lost
	case (tr.Inject == rangejob.InjectKernelTransient) == (f[FactOKAfterResume] == "-"):
		return Invalid, fmt.Sprintf("health after a resume \"%s\" in a run that does not resume, or none in one that does",
			Printable(f[FactOKAfterResume], 16))
	case strings.HasPrefix(f[FactLossEntry], "error"):
		return Invalid, fmt.Sprintf("the ledger could not be read: \"%s\"", Printable(f[FactLossEntry], 256))
	case strings.HasPrefix(f[FactFirstUnknown], "error"):
		return Invalid, fmt.Sprintf("the ledger's UNKNOWNs could not be read: \"%s\"", Printable(f[FactFirstUnknown], 256))
	case tr.Inject == rangejob.InjectQueue && !sameRestarts(f[FactCollectorRestarts]):
		// a restarted collector takes its queued losses with it: the queue's loss was never shown
		return Invalid, fmt.Sprintf("the collector restarted during the queue's injection: %s", Printable(f[FactCollectorRestarts], 64))
	case f[FactPiActive] != "active":
		return Miss, fmt.Sprintf("the watcher is %s at the end", Printable(f[FactPiActive], 64))
	}
	if tr.Inject == rangejob.InjectNone {
		// an alert while the watcher warms up, before the control's moment of injection, is a false alarm too
		if alarm := lossPost(tr, posts, 0, ""); alarm != nil {
			return Miss, fmt.Sprintf("a %s alert at %d ms without a loss", alarm.Tag, alarm.MS)
		}
		return Pass, "no loss alert without a loss"
	}
	alarm := lossPost(tr, posts, n[FactInjectMS], f[FactFirstUnknown])
	switch {
	case alarm != nil && alarm.MS < n[FactLossFromMS]:
		return Invalid, fmt.Sprintf("a %s alert at %d ms, before the loss's bracket from %d", alarm.Tag, alarm.MS, n[FactLossFromMS])
	case alarm != nil && alarm.Tag == "unknown" && strings.HasPrefix(f[FactFirstUnknown], "before"):
		// an UNKNOWN the ledger logged within lossAlarm before the injection: its alert may be this one
		return Invalid, fmt.Sprintf("an unknown alert with an UNKNOWN logged %s the injection", Printable(f[FactFirstUnknown], 32))
	case f[FactLossEntry] != "yes":
		return Miss, fmt.Sprintf("no entry of the loss in the ledger: \"%s\"", Printable(f[FactLossEntry], 256))
	case alarm == nil:
		return Miss, "no loss alert reached the sink"
	}
	// the loss fell somewhere in the bracket: the alert's youngest delay counts from its end, its oldest from its start
	young, old := msDuration(alarm.MS-min(alarm.MS, n[FactLossToMS])), msDuration(alarm.MS-n[FactLossFromMS])
	switch {
	case young > lossAlarm:
		return Miss, fmt.Sprintf("%s alert %s after the loss, over %s", alarm.Tag, young, lossAlarm)
	case old > lossAlarm:
		return Invalid, fmt.Sprintf("%s alert %s to %s after the loss: its bracket is too wide to prove %s", alarm.Tag,
			young, old, lossAlarm)
	}
	if tr.Inject == rangejob.InjectKernelTransient {
		ok, err := plainNumber(f[FactOKAfterResume])
		switch {
		case f[FactOKAfterResume] == "none" || err == nil && msDuration(ok) > lossAlarm:
			return Miss, fmt.Sprintf("health OK \"%s\" ms after auditd resumed, not within %s", Printable(f[FactOKAfterResume], 16), lossAlarm)
		case err != nil:
			return Invalid, fmt.Sprintf("health after the resume \"%s\" is not a plain number", Printable(f[FactOKAfterResume], 64))
		}
	}
	return Pass, fmt.Sprintf("%s alert %s to %s after the loss", alarm.Tag, young, old)
}

// sameRestarts is "n n": the collector's restart count did not move.
func sameRestarts(v string) bool {
	before, after, ok := strings.Cut(v, " ")
	_, err := plainNumber(before)
	return ok && err == nil && before == after
}

// lossPost is the first alert of tr's cause after ms (ADR 0039, point 3): its stage's key, for the store also an
// unknown when firstUnknown, the ledger's first UNKNOWN after the injection, is the store's; for the control any
// loss or unknown alert.
func lossPost(tr rangejob.Trial, posts []Post, ms uint64, firstUnknown string) *Post {
	storeDown := strconv.Itoa(int(logentry.ReasonStoreDown))
	for i := range posts {
		p := &posts[i]
		var cause bool
		switch tr.Inject {
		case rangejob.InjectNone:
			cause = strings.HasPrefix(p.Tag, "loss") || p.Tag == "unknown"
		case rangejob.InjectStore:
			cause = p.Tag == LossTag(tr.Inject) || p.Tag == "unknown" && (firstUnknown == storeDown || strings.HasPrefix(firstUnknown, "before"))
		default:
			cause = p.Tag != "" && p.Tag == LossTag(tr.Inject)
		}
		if p.MS > ms && cause {
			return p
		}
	}
	return nil
}

// lossMeasures is a loss run's alert delay after its bracket began, the bound a PASS proves, when it came.
func lossMeasures(tr rangejob.Trial, o Outcome, m map[string]uint64) {
	f, n, why := probeFacts(tr, o, lossFacts, []string{FactInjectMS, FactLossFromMS})
	if why != "" {
		return
	}
	posts, err := ParsePosts(f[FactPosts])
	if alarm := lossPost(tr, posts, n[FactInjectMS], f[FactFirstUnknown]); err == nil && alarm != nil && alarm.MS >= n[FactLossFromMS] {
		m[MeasureAlarmMS] = alarm.MS - n[FactLossFromMS]
	}
}
