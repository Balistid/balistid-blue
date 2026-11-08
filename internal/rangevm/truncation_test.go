package rangevm

import (
	"strconv"
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

// truncCase is a change to a sound run, ";"-separated, and the verdict and the words of the reason it must give.
type truncCase struct{ change, want, reason string }

// judgeTruncationCases checks each case's verdict and reason: every way to PASS with a false fact gives MISS or
// INVALID, each for its own reason.
func judgeTruncationCases(t *testing.T, name string, cases []truncCase) {
	t.Helper()
	tr := trial(t, name)
	for _, c := range cases {
		var change []string
		if c.change != "" {
			change = strings.Split(c.change, ";")
		}
		if v, r := JudgeTrial(tr, truncRun(name, change...), cleanBuild, cleanBuild); v != c.want || !strings.Contains(r, c.reason) {
			t.Errorf("%s %q: %s (%s), want %s (%s)", name, c.change, v, r, c.want, c.reason)
		}
	}
}

// Eleven truncated records pass only with one truncated alert after the 11th exec began and within 65 s of it
// (ADR 0069, points 3 and 4).
func TestJudgeTruncationOverTheLimit(t *testing.T) {
	posts := FactPosts + "=60000:start,"
	judgeTruncationCases(t, "truncation-11", append([]truncCase{
		{"", Pass, "one truncated alert 10s after the last exec"},
		{posts + "215000:truncated", Pass, "one truncated alert 1m5s after the last exec"},
		{posts + "160000:truncated,170000:unknown", Pass, "one truncated alert 10s after"},
		{FactTruncFirstMS + "=150000", Pass, "one truncated alert 10s after"},                 // the stamps of first and last may agree
		{FactPosts + "=100000:start,160000:truncated", Pass, "one truncated alert 10s after"}, // the start in the first exec's ms
		{FactPosts + "=0:start,160000:truncated", Pass, "one truncated alert 10s after"},      // a start at the clock's zero
		{FactPosts + "=60000:start", Miss, "no truncated alert reached the sink"},
		{posts + "215001:truncated", Miss, "the truncated alert 1m5.001s after the last exec, over 1m5s"},
		{posts + "150000:truncated", Miss, "a truncated alert at 150000 ms, before the last exec at 150000"}, // before its record
		{posts + "145000:truncated", Miss, "a truncated alert at 145000 ms, before the last exec"},           // at the 10th
		{posts + "90000:truncated", Miss, "a truncated alert at 90000 ms, before the last exec"},             // before any exec
		{posts + "160000:truncated,170000:truncated", Miss, "2 truncated alerts, the second at 170000 ms"},
		{posts + "160000:unknown", Miss, "no truncated alert reached the sink"},  // another tag
		{FactRefused + "=1", Miss, "the sink refused 1 of the watcher's pushes"}, // a refused push may be the alert
		{FactPosts + "=none;" + FactRefused + "=2", Miss, "the sink refused 2 of the watcher's pushes"},
		{FactPiActive + "=failed", Miss, "the watcher is failed at the end, restarts 0 to 0"},
		{FactRestartsPost + "=1", Miss, "the watcher is active at the end, restarts 0 to 1"},
		{FactPiActive + "=" + strings.Repeat("a", 80), Miss, "the watcher is " + strings.Repeat("a", 64) + " at the end"}, // quoted to 64
	}, truncationInvalid("11", "12", "10", 150000)...))
}

// Ten truncated records pass only without any truncated alert in the whole window (ADR 0069, points 3 and 4).
func TestJudgeTruncationAtTheLimit(t *testing.T) {
	posts := FactPosts + "=60000:start,"
	judgeTruncationCases(t, "truncation-10", append([]truncCase{
		{"", Pass, "no truncated alert for 10 truncated records"},
		{posts + "200000:unknown", Pass, "no truncated alert for 10 truncated records"},
		{posts + "200000:truncated", Miss, "a truncated alert at 200000 ms for 10 truncated records"},
		{posts + "90000:truncated", Miss, "a truncated alert at 90000 ms for 10"}, // before the first exec
		{posts + "224999:truncated", Miss, "a truncated alert at 224999 ms for 10"},
		{FactRefused + "=1", Miss, "the sink refused 1 of"},                      // the refused push may be the alert
		{FactPiActive + "=inactive", Miss, "the watcher is inactive at the end"}, // a watcher gone says nothing
		{FactRestartsPost + "=2", Miss, "restarts 0 to 2"},                       // a restart forgets the hour's count
	}, truncationInvalid("10", "11", "9", 145000)...))
}

// truncationInvalid are the changes that leave a run of want execs, the last at last ms, unproven either way; more
// and fewer are execs or entries off its count.
func truncationInvalid(want, more, fewer string, last int) []truncCase {
	out := []truncCase{
		{FactTruncExecs + "=" + more, Invalid, more + " oversized execs ran, the trial runs " + want},
		{FactTruncExecs + "=" + fewer, Invalid, fewer + " oversized execs ran, the trial runs " + want},
		{FactTruncEntries + "=" + more, Invalid, "holds 0 truncated entries before the execs and " + more + " after, want 0 and " + want},
		{FactTruncEntries + "=" + fewer, Invalid, "and " + fewer + " after, want 0 and " + want},
		{FactTruncBefore + "=1", Invalid, "holds 1 truncated entries before the execs and " + want + " after"}, // counts in the hour
		{FactOtherLoss + "=1", Invalid, "records lost besides the truncated: 1 loss entries, kernel lost 0 to 0, overflow no to no"},
		{FactLostAfter + "=4", Invalid, "kernel lost 0 to 4"},
		{FactOverflowAfter + "=yes", Invalid, "overflow no to yes"},
		{FactOverflowBefore + "=stale", Invalid, "overflow stale to no"},
		{FactOverflowBefore + "=" + strings.Repeat("y", 40), Invalid, "overflow " + strings.Repeat("y", 16) + " to no"}, // quoted to 16
		{FactOverflowAfter + "=" + strings.Repeat("z", 40), Invalid, "overflow no to " + strings.Repeat("z", 16)},
		{FactTruncEndMS + "=" + strconv.Itoa(last-1000), Invalid, "the sink was read 0 ms after the last exec, before 1m20s"},
		{FactTruncEndMS + "=" + strconv.Itoa(last+79999), Invalid, "the sink was read 79999 ms after the last exec, before 1m20s"},
		{FactTruncFirstMS + "=999999", Invalid, "the last exec starts before the first"},
		{FactPosts + "=160000:truncated", Invalid, "the sink saw no start of the watcher before the first exec"},
		{FactPosts + "=110000:start,160000:truncated", Invalid, "the sink saw no start"}, // started after the first exec
		{FactPosts + "=60000:start,160000:Truncated", Invalid, `post "160000:Truncated" is not ms:tag`},
		{FactPiVerified + "=error: the Pi verified 40 of 52 entries", Invalid,
			`not shown to have verified the truncated entries: "error: the Pi verified 40 of 52 entries"`},
		{FactPiVerified + "=" + strings.Repeat("e", 300), Invalid, `entries: "` + strings.Repeat("e", 256) + `"`}, // quoted to 256
		{FactPiActive + "=missing", Invalid, "the watcher's state could not be read"},
		{FactRestartsPre + "=missing", Invalid, "fact pi_restarts_before is not a plain number"},
		{FactTrial + "=truncation-1", Invalid, "the guest ran another trial"},
		{FactKernel + "=6.1.0", Invalid, `guest kernel "6.1.0" is not the target`},
		{"pi_alerts=1", Invalid, `unexpected fact "pi_alerts"`},
		{FactTrial, Invalid, "the guest ran another trial"},
		{FactKernel, Invalid, `guest kernel "" is not the target`},
	}
	for _, name := range truncationFacts {
		if name != FactTrial && name != FactKernel {
			out = append(out, truncCase{name, Invalid, "report has 19 of 20 facts, not " + name}) // each missing
		}
	}
	return out
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
	_, r := JudgeTrial(tr, truncRun(tr.Name, FactOverflowAfter+"="+strings.Repeat("z", 40)), cleanBuild, cleanBuild)
	if !strings.HasSuffix(r, " to "+strings.Repeat("z", 16)) {
		t.Errorf("an overflow value must end the reason quoted to 16 bytes: %q", r)
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

// A trial whose injection runs no oversized exec is no truncation run, whatever its facts: it never passes.
func TestJudgeTruncationNeedsItsExecs(t *testing.T) {
	tr := trial(t, "truncation-10")
	tr.Inject = rangejob.InjectNone
	o := truncRun(tr.Name, FactTruncExecs+"=0", FactTruncEntries+"=0")
	if v, r := judgeTruncation(tr, o); v != Invalid || !strings.Contains(r, "0 oversized execs ran, the trial runs 0") {
		t.Errorf("no execs: %s (%s)", v, r)
	}
}
