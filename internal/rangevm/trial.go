package rangevm

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Miss is a trial's verdict when the run was valid and the metric did not hold (ADR 0018, point 6).
const Miss = "MISS"

// Facts of a rate trial after its echo and kernel (ADR 0018, point 4). Counts are decimal; follow is
// "ok" only when the reader saw every record up to the canary that ends the run.
const (
	FactGenerated      = "generated"
	FactWindowMin      = "window_min"
	FactLostBefore     = "audit_lost_before"
	FactLostAfter      = "audit_lost_after"
	FactOverflowBefore = "overflow_before"
	FactOverflowAfter  = "overflow_after"
	// FactStealWindows is the guest's /proc/stat read every second from just before the load to the end of its
	// read: "ms:total:steal" for each span between two reads, comma-separated (ADR 0057).
	FactStealWindows = "steal_windows"
	FactFollow       = "follow"
	FactStored       = "stored"
	FactMissing      = "missing"
	FactDuplicate    = "duplicate"
	FactOutside      = "outside"
	// FactTrialError replaces the counts when the guest could not run the trial; boot reports it.
	FactTrialError = "trial_error"
)

// rateFacts also carry the collector's CPU µs over the load and its cgroup's memory peak: measures
// only, not judged, a number or why there is none.
var rateFacts = []string{
	FactTrial, FactPhase, FactKernel, FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter,
	FactOverflowBefore, FactOverflowAfter, FactStealWindows, FactFollow,
	FactStored, FactMissing, FactDuplicate, FactOutside, FactCollectorUS, FactCollectorMem,
}

// counts are the rate facts that must be plain decimal numbers.
var counts = []string{
	FactGenerated, FactWindowMin, FactLostBefore, FactLostAfter, FactStored, FactMissing, FactDuplicate, FactOutside,
}

// maxStealWindows bounds a report's spans: 68 min of reads every second, for runs that end within 40 min.
const maxStealWindows = 4096

// stealWindow is one span of FactStealWindows; the digits cap keeps steal*100 far below 2^64.
var stealWindow = regexp.MustCompile(`^(0|[1-9][0-9]{0,8}):(0|[1-9][0-9]{0,11}):(0|[1-9][0-9]{0,11})$`)

// hostSteal is why host steal leaves the run unproven either way (ADR 0057): the first span with more than 1 % of
// its ticks stolen, of 1 s or more without ticks, or over 2 s, which leaves its seconds unmeasured; "" when none.
// worst is the largest share of steal in any span, in parts per million. A series not of that form, with steal
// over its ticks, too many spans or covering less than the load is an error.
func hostSteal(series string, loadSeconds int) (why string, worst uint64, err error) {
	spans := strings.Split(series, ",")
	if len(spans) > maxStealWindows {
		return "", 0, fmt.Errorf("%d steal windows, at most %d", len(spans), maxStealWindows)
	}
	covered, bad := uint64(0), 0
	for i, span := range spans {
		m := stealWindow.FindStringSubmatch(span)
		if m == nil {
			return "", 0, fmt.Errorf("steal window %d \"%s\" is not ms:total:steal", i, Printable(span, 64))
		}
		ms, _ := strconv.ParseUint(m[1], 10, 64)
		total, _ := strconv.ParseUint(m[2], 10, 64)
		steal, _ := strconv.ParseUint(m[3], 10, 64)
		if steal > total {
			return "", 0, fmt.Errorf("steal window %d has %d steal of %d ticks", i, steal, total)
		}
		if total > 0 {
			worst = max(worst, steal*1_000_000/total)
		}
		issue := ""
		switch {
		case ms > 2000:
			issue = fmt.Sprintf("%d ms unmeasured from %d ms on", ms, covered)
		case total == 0 && ms >= 1000:
			issue = fmt.Sprintf("no CPU ticks in %d ms from %d ms on", ms, covered)
		case steal*100 > total:
			issue = fmt.Sprintf("guest steal %d of %d ticks in %d ms from %d ms on", steal, total, ms, covered)
		}
		if issue != "" {
			bad++
			if why == "" {
				why = issue
			}
		}
		covered += ms
	}
	if covered < uint64(loadSeconds)*1000 { //nolint:gosec // positive table value
		return "", 0, fmt.Errorf("steal windows cover %d ms of a %d s load", covered, loadSeconds)
	}
	if bad > 1 {
		why = fmt.Sprintf("%s; %d of %d spans", why, bad, len(spans))
	}
	return why, worst, nil
}

// judgeRate judges a run of rate trial tr. The guest's facts form a closed set, each once, as plain
// values; anything else, another kernel, a reader that did not see the run's end or host steal in any
// span (ADR 0057) is INVALID. Loss, a changed audit lost counter, a plugin-queue overflow or a rate not
// held in every 10 s window is a MISS, so a control, whose reader drops one number, must come out MISS
// (ADR 0018, point 4).
func judgeRate(tr rangejob.Trial, o Outcome) (verdict, reason string) {
	f := map[string]string{}
	for _, r := range o.Facts {
		if !slices.Contains(rateFacts, r.Name) {
			return Invalid, fmt.Sprintf("unexpected fact \"%s\" in a trial report", Printable(r.Name, 64))
		}
		if _, dup := f[r.Name]; dup {
			return Invalid, fmt.Sprintf("fact %s reported twice", r.Name)
		}
		f[r.Name] = r.Value
	}
	if len(f) != len(rateFacts) {
		return Invalid, fmt.Sprintf("trial report has %d of %d facts", len(f), len(rateFacts))
	}
	n := map[string]uint64{}
	for _, name := range counts {
		v, err := strconv.ParseUint(f[name], 10, 64)
		if err != nil || strconv.FormatUint(v, 10) != f[name] {
			return Invalid, fmt.Sprintf("fact %s is not a plain number", name)
		}
		n[name] = v
	}
	planned := uint64(tr.Load.Rate) * uint64(tr.Load.Seconds) //nolint:gosec // positive table values
	steal, _, stealErr := hostSteal(f[FactStealWindows], tr.Load.Seconds)
	switch {
	case stealErr != nil:
		return Invalid, stealErr.Error()
	case steal != "":
		return Invalid, "host steal: " + steal
	case f[FactTrial] != tr.Name:
		return Invalid, "the guest ran another trial"
	case f[FactKernel] != TargetKernel:
		return Invalid, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	case f[FactFollow] != "ok":
		return Invalid, fmt.Sprintf("the reader did not see the whole run: \"%s\"", Printable(f[FactFollow], 256))
	case f[FactOverflowBefore] != "no" || (f[FactOverflowAfter] != "no" && f[FactOverflowAfter] != "yes"):
		return Invalid, "the plugin queue state is unknown"
	case n[FactGenerated] == 0 || n[FactGenerated] > planned || n[FactStored] > n[FactGenerated] ||
		n[FactMissing] != n[FactGenerated]-n[FactStored]:
		return Invalid, fmt.Sprintf("generated %d of %d planned, stored %d and missing %d do not add up",
			n[FactGenerated], planned, n[FactStored], n[FactMissing])
	case n[FactWindowMin] > n[FactGenerated]/uint64(tr.Load.Seconds/10): //nolint:gosec // positive table value
		return Invalid, fmt.Sprintf("the slowest 10 s window holds %d of %d generated", n[FactWindowMin], n[FactGenerated])
	case n[FactLostAfter] < n[FactLostBefore]:
		return Invalid, "the audit lost counter went backwards"
	}
	loss := fmt.Sprintf("generated %d, stored %d, missing %d, duplicate %d, outside %d",
		n[FactGenerated], n[FactStored], n[FactMissing], n[FactDuplicate], n[FactOutside])
	switch {
	case n[FactMissing] > 0 || n[FactDuplicate] > 0 || n[FactOutside] > 0:
		return Miss, loss
	case n[FactLostAfter] != n[FactLostBefore]:
		return Miss, fmt.Sprintf("audit lost %d before, %d after", n[FactLostBefore], n[FactLostAfter])
	case f[FactOverflowAfter] == "yes":
		return Miss, "the plugin queue overflowed"
	case n[FactGenerated] < planned || n[FactWindowMin] < uint64(tr.Load.Rate)*10: //nolint:gosec // positive table value
		return Miss, fmt.Sprintf("rate not held: generated %d of %d, %d in the slowest 10 s", n[FactGenerated], planned, n[FactWindowMin])
	}
	return Pass, loss
}

// ExpectedVerdict is what a sound run of tr gives: a control's Expect, else PASS.
func ExpectedVerdict(tr rangejob.Trial) string {
	if tr.Expect != "" {
		return tr.Expect
	}
	return Pass
}

// Measures of a trial run, kept beside its verdict so a margin can be read, not only a threshold
// that held: the guest's counts that are reported exactly once as plain numbers, and of a failure
// trial the host's marks and how long after the fail mark QEMU exited or the kill mark came.
const (
	MeasureH               = "h"
	MeasureSynced          = "synced"
	MeasureCommitted       = "committed_seq"
	MeasureExitAfterFail   = "exit_after_fail_us"
	MeasureKilledAfterFail = "killed_after_fail_us"
	// MeasureStealWorstPPM is the largest share of steal in any span of a rate or CPU run, in parts per million.
	MeasureStealWorstPPM = "steal_worst_ppm"
)

// Measures returns the measures of a run of tr; a count missing, repeated or not a plain number is
// left out, never guessed (T30).
func Measures(tr rangejob.Trial, o Outcome) map[string]uint64 {
	var names []string
	switch tr.Method() {
	case rangejob.MethodRate:
		names = append(slices.Clone(counts), FactCollectorUS, FactCollectorMem)
	case rangejob.MethodWriterFailure:
		names = []string{FactStoredPrefix, FactStoredCount}
	case rangejob.MethodCollectorFailure:
		names = []string{FactStoredPrefix, FactStoredCount, FactRecoveredLast}
	case rangejob.MethodReady:
		names = []string{FactReadyMS}
	case rangejob.MethodCPU:
		names = []string{FactGenerated, FactWindowMin, FactCollectorUS, FactAuditdUS}
	case rangejob.MethodLogCap:
		names = []string{FactCapEntries, FactFullBundles, FactFullBytes}
	case rangejob.MethodRSS:
		names = []string{FactGenerated, FactWindowMin, FactRSSSamples, FactRSSMaxKiB, FactRSSHWMKiB, FactRSSAuditKiB}
	case rangejob.MethodCanary:
		names = []string{FactCanaryCount, FactCanaryGapMS}
		for _, s := range CanaryStages() {
			names = append(names, CanaryFact(s.Name, CanaryFirstMS), CanaryFact(s.Name, CanaryUnknownMS), CanaryFact(s.Name, CanaryOKMS))
		}
	}
	m := map[string]uint64{}
	for _, name := range names {
		var values []string
		for _, r := range o.Facts {
			if r.Name == name {
				values = append(values, r.Value)
			}
		}
		if len(values) != 1 {
			continue
		}
		if v, err := plainNumber(values[0]); err == nil {
			m[name] = v
		}
	}
	switch tr.Method() {
	case rangejob.MethodAlarm:
		alarmMeasures(tr, o, m)
	case rangejob.MethodLoss:
		lossMeasures(tr, o, m)
	case rangejob.MethodRate, rangejob.MethodCPU:
		stealMeasure(tr, o, m)
	}
	if tr.Failure == "" || o.Marks.Fail.IsZero() {
		return m
	}
	m[MeasureH] = o.Marks.H
	if tr.Method() == rangejob.MethodCollectorFailure {
		m[MeasureCommitted] = o.Marks.Synced // S of a collector is a store seq, not a number (ADR 0023)
	} else {
		m[MeasureSynced] = o.Marks.Synced
	}
	after := func(key string, t time.Time) {
		if d := t.Sub(o.Marks.Fail); !t.IsZero() && d >= 0 {
			m[key] = uint64(d / time.Microsecond)
		}
	}
	after(MeasureExitAfterFail, o.Marks.Exited)
	after(MeasureKilledAfterFail, o.Marks.Killed)
	return m
}

// stealMeasure keeps a run's worst span of steal, so a result shows how close it came to the limit; a series
// reported other than once, or not well formed, is left out.
func stealMeasure(tr rangejob.Trial, o Outcome, m map[string]uint64) {
	var series []string
	for _, r := range o.Facts {
		if r.Name == FactStealWindows {
			series = append(series, r.Value)
		}
	}
	if len(series) != 1 {
		return
	}
	if _, worst, err := hostSteal(series[0], tr.Load.Seconds); err == nil {
		m[MeasureStealWorstPPM] = worst
	}
}

// Facts of a failure trial (ADR 0018, point 3): after a reset the second boot reports the scratch
// disk's superblock as it found it before mounting, and both kinds report the longest run 1..N of
// numbers the stored file holds and how many records it holds.
const (
	FactScratchJournal  = "scratch_journal"
	FactScratchRecovery = "scratch_recovery"
	FactStoredPrefix    = "stored_prefix"
	FactStoredCount     = "stored_count"
)

// JudgeTrial judges a run of tr by its method: a rate trial by its counts, a failure trial by what
// survived. A trial no method judges is INVALID.
func JudgeTrial(tr rangejob.Trial, o Outcome, launcher, image string) (verdict, reason string) {
	if why := runInvalid(o, launcher, image); why != "" {
		return Invalid, why
	}
	switch tr.Method() {
	case rangejob.MethodRate:
		return judgeRate(tr, o)
	case rangejob.MethodWriterFailure:
		return judgeFailure(tr, o)
	case rangejob.MethodCollectorFailure:
		return judgeCrash(tr, o)
	case rangejob.MethodRecord:
		return judgeRecord(tr, o)
	case rangejob.MethodRefusal:
		return judgeRefusal(tr, o)
	case rangejob.MethodReady:
		return judgeReady(tr, o)
	case rangejob.MethodExposure:
		return judgeExposure(tr, o)
	case rangejob.MethodCPU:
		return judgeCPU(tr, o)
	case rangejob.MethodAlarm:
		return judgeAlarm(tr, o)
	case rangejob.MethodLogCap:
		return judgeLogCap(tr, o)
	case rangejob.MethodLoss:
		return judgeLoss(tr, o)
	case rangejob.MethodAuditSet:
		return judgeAuditSet(tr, o)
	case rangejob.MethodStatus:
		return judgeStatus(tr, o)
	case rangejob.MethodRSS:
		return judgeRSS(tr, o)
	case rangejob.MethodCanary:
		return judgeCanary(tr, o)
	}
	return Invalid, fmt.Sprintf("no method judges trial %s", tr.Name)
}

// runInvalid is why no fact of run o counts, or "": the guest could not run the trial, or the
// launcher is not a clean build of the image's commit.
func runInvalid(o Outcome, launcher, image string) string {
	switch {
	case o.Invalid != "":
		return o.Invalid
	case launcher != image || !buildinfo.IsCommitID(launcher):
		return fmt.Sprintf("launcher is not a clean build of the image commit %s", image)
	}
	return ""
}

// judgeFailure: the host's marks, the closed facts of each boot, the target kernel and, after a
// reset, ext4 with a journal that still needed recovery are required, else INVALID. Every number up
// to H, the end of the contiguous numbers handed over 900 ms before the failure, must be stored,
// else MISS.
func judgeFailure(tr rangejob.Trial, o Outcome) (string, string) {
	last := []string{FactTrial, FactPhase, FactKernel, FactStoredPrefix, FactStoredCount}
	if tr.Failure == FailReset {
		first, err := closedFacts(o.FirstBoot, []string{FactTrial, FactPhase, FactKernel, FactResetArmed})
		if err != nil {
			return Invalid, "first boot: " + err.Error()
		}
		if first[FactKernel] != TargetKernel {
			return Invalid, "first boot ran another kernel"
		}
		last = append(last, FactScratchJournal, FactScratchRecovery)
	}
	f, err := closedFacts(o.Facts, last)
	if err != nil {
		return Invalid, err.Error()
	}
	prefix, errP := plainNumber(f[FactStoredPrefix])
	count, errC := plainNumber(f[FactStoredCount])
	switch {
	case f[FactKernel] != TargetKernel:
		return Invalid, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	case errP != nil || errC != nil || count < prefix:
		return Invalid, "stored counts are not plain numbers that add up"
	case tr.Failure == FailReset && (f[FactScratchJournal] != "yes" || f[FactScratchRecovery] != "yes"):
		return Invalid, "the reset did not leave ext4 with a journal that needs recovery"
	case o.Marks.H == 0:
		return Invalid, "nothing was handed over in time to have to survive"
	case tr.Expect == Pass && o.Marks.Synced < o.Marks.H && prefix >= o.Marks.Synced:
		// The control's premise is a writer synced through H; a host that stalled its storage
		// broke the premise, not the file system. A number up to S lost is a real loss (ADR 0019).
		return Invalid, fmt.Sprintf("the writer had synced only through %d of H=%d", o.Marks.Synced, o.Marks.H)
	case prefix < max(o.Marks.H, o.Marks.Synced):
		// Everything handed over in time, and everything an fsync had returned for, must survive.
		return Miss, fmt.Sprintf("numbers up to %d (H=%d, synced %d) had to survive the %s; stored through %d",
			max(o.Marks.H, o.Marks.Synced), o.Marks.H, o.Marks.Synced, tr.Failure, prefix)
	}
	return Pass, fmt.Sprintf("every number up to %d (H=%d, synced %d) survived the %s (stored through %d)",
		max(o.Marks.H, o.Marks.Synced), o.Marks.H, o.Marks.Synced, tr.Failure, prefix)
}

// closedFacts maps facts that must be exactly names, each once.
func closedFacts(facts []Record, names []string) (map[string]string, error) {
	f, missing, err := namedFacts(facts, names)
	if err == nil && len(missing) > 0 {
		err = fmt.Errorf("report has %d of %d facts", len(f), len(names))
	}
	return f, err
}

// namedFacts maps facts that must each be one of names, reported once, and lists the names missing.
func namedFacts(facts []Record, names []string) (map[string]string, []string, error) {
	f := map[string]string{}
	for _, r := range facts {
		if !slices.Contains(names, r.Name) {
			return nil, nil, fmt.Errorf("unexpected fact \"%s\"", Printable(r.Name, 64))
		}
		if _, dup := f[r.Name]; dup {
			return nil, nil, fmt.Errorf("fact %s reported twice", r.Name)
		}
		f[r.Name] = r.Value
	}
	var missing []string
	for _, name := range names {
		if _, ok := f[name]; !ok {
			missing = append(missing, name)
		}
	}
	return f, missing, nil
}

// plainNumber is a canonical decimal.
func plainNumber(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != s {
		return 0, errors.New("not a plain number")
	}
	return v, nil
}
