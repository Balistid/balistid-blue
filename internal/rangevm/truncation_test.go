package rangevm

import (
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/watch"
)

// truncRun is a sound truncation run of name: the watcher's start at 60 s, the first oversized exec at 100 s,
// one every 5 s, the sink read 80 s after the last; truncation-11's alert 10 s after its last exec.
func truncRun(name string, change ...string) Outcome {
	base := map[string]string{FactTruncExecs: "11", FactTruncFirstMS: "100000", FactTruncLastMS: "150000", FactTruncEndMS: "230000",
		FactTruncBefore: "0", FactTruncEntries: "11", FactOtherLoss: "0", FactPosts: "60000:start,160000:truncated", FactRefused: "0",
		FactPiActive: "active", FactRestartsPre: "0", FactRestartsPost: "0", FactPiVerified: "yes", FactLostBefore: "0",
		FactLostAfter: "0", FactOverflowBefore: "no", FactOverflowAfter: "no"}
	if name == "truncation-10" {
		base[FactTruncExecs], base[FactTruncLastMS], base[FactTruncEndMS], base[FactTruncEntries] = "10", "145000", "225000", "10"
		base[FactPosts] = "60000:start"
	}
	return probeRun(name, truncationFacts, base, change...)
}

// The judge's verdict on each change: every way to PASS with a false fact gives MISS or INVALID.
func judgeTruncationCases(t *testing.T, name string, cases map[string][]string) {
	t.Helper()
	tr := trial(t, name)
	for want, changes := range cases {
		for _, c := range changes {
			var change []string
			if c != "" {
				change = strings.Split(c, ";")
			}
			if v, r := JudgeTrial(tr, truncRun(name, change...), cleanBuild, cleanBuild); v != want {
				t.Errorf("%s %q: %s (%s), want %s", name, c, v, r, want)
			}
		}
	}
}

// Eleven truncated records pass only with one truncated alert after the 11th exec began and within 65 s of it
// (ADR 0069, points 3 and 4).
func TestJudgeTruncationOverTheLimit(t *testing.T) {
	judgeTruncationCases(t, "truncation-11", map[string][]string{
		Pass: {"", FactPosts + "=60000:start,215000:truncated", FactPosts + "=60000:start,160000:truncated,170000:unknown"},
		Miss: {
			FactPosts + "=60000:start",                                   // no alert
			FactPosts + "=60000:start,215001:truncated",                  // late
			FactPosts + "=60000:start,150000:truncated",                  // at the 11th exec's start, before its record
			FactPosts + "=60000:start,145000:truncated",                  // at the 10th: the limit is off by one
			FactPosts + "=60000:start,90000:truncated",                   // before any exec
			FactPosts + "=60000:start,160000:truncated,170000:truncated", // a second alert
			FactPosts + "=60000:start,160000:unknown",                    // another tag
			FactRefused + "=1",                                           // a refused push may be the alert
			FactPosts + "=none;" + FactRefused + "=2",
			FactPiActive + "=failed",
			FactRestartsPost + "=1",
		},
		Invalid: truncationInvalid("12", "10"),
	})
}

// Ten truncated records pass only without any truncated alert in the whole window (ADR 0069, points 3 and 4).
func TestJudgeTruncationAtTheLimit(t *testing.T) {
	judgeTruncationCases(t, "truncation-10", map[string][]string{
		Pass: {"", FactPosts + "=60000:start,200000:unknown"},
		Miss: {
			FactPosts + "=60000:start,200000:truncated", // an alert at the limit
			FactPosts + "=60000:start,90000:truncated",  // before the first exec
			FactPosts + "=60000:start,224999:truncated", // late in the window
			FactRefused + "=1",                          // the refused push may be the alert
			FactPiActive + "=inactive",                  // a watcher gone says nothing
			FactRestartsPost + "=2",                     // a restart forgets the hour's count
		},
		Invalid: truncationInvalid("11", "9"),
	})
}

// truncationInvalid are the changes that leave a truncation run unproven either way; more and fewer are execs or
// entries off the trial's count.
func truncationInvalid(more, fewer string) []string {
	out := []string{
		FactTruncExecs + "=" + more, FactTruncExecs + "=" + fewer, FactTruncEntries + "=" + more, FactTruncEntries + "=" + fewer,
		FactTruncBefore + "=1",                                      // a truncated record before the run counts in the watcher's hour
		FactOtherLoss + "=1",                                        // another loss, collector or kernel stage
		FactLostAfter + "=4",                                        // the kernel lost records
		FactOverflowAfter + "=yes",                                  // the dispatcher overflowed
		FactOverflowBefore + "=stale",                               // its state unread
		FactTruncEndMS + "=144000",                                  // the sink read before the last exec
		FactTruncFirstMS + "=999999",                                // the last exec before the first
		FactPosts + "=160000:truncated",                             // no start
		FactPosts + "=110000:start,160000:truncated",                // the watcher started after the first exec
		FactPosts + "=60000:start,160000:Truncated",                 // not a tag
		FactPiVerified + "=error: the Pi verified 40 of 52 entries", // its verification not shown
		FactPiActive + "=missing",
		FactRestartsPre + "=missing",
		FactTrial + "=truncation-1",
		FactKernel + "=6.1.0",
		"pi_alerts=1", // unknown
	}
	return append(out, truncationFacts...) // each missing
}

// The sink read must come TruncationWait after the last exec, so the window covers the 65 s and its margin; a fact
// reported twice proves nothing.
func TestTruncationWindowAndRepeatedFacts(t *testing.T) {
	tr := trial(t, "truncation-11")
	if v, r := JudgeTrial(tr, truncRun(tr.Name, FactTruncEndMS+"=229999"), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("sink read a millisecond early: %s (%s)", v, r)
	}
	o := truncRun(tr.Name)
	o.Facts = append(o.Facts, Record{Name: FactPosts, Value: "60000:start,160000:truncated"})
	if v, r := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("posts reported twice: %s (%s)", v, r)
	}
	if TruncationWait <= lossAlarm {
		t.Errorf("TruncationWait %s leaves no margin over %s", TruncationWait, lossAlarm)
	}
}

// The judge's key and limit are the Pi's (internal/watch) and the table's counts sit on either side of the limit.
func TestTruncationIsThePis(t *testing.T) {
	if TruncatedTag != string(watch.KeyTruncated) || truncationLimit != watch.DefaultLimits.Truncated {
		t.Errorf("tag %q, limit %d; the Pi alerts %q above %d", TruncatedTag, truncationLimit, watch.KeyTruncated, watch.DefaultLimits.Truncated)
	}
	if rangejob.TruncatedExecs(rangejob.InjectTruncated11) != truncationLimit+1 || rangejob.TruncatedExecs(rangejob.InjectTruncated10) != truncationLimit {
		t.Error("the truncation trials do not sit on either side of the limit")
	}
}
