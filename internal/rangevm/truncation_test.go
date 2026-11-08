package rangevm

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/watch"
)

// truncRun is a sound truncation run of name: the watcher's start at 60 s, the first oversized exec at 100 s, the
// others but the last one every 5 s, the last 80 s after the one before, the sink read 80 s after the last;
// truncation-11's alert 10 s after its last exec.
func truncRun(name string, change ...string) Outcome {
	base := map[string]string{FactTruncStartsMS: startsValue(soundStarts(11)), FactTruncEndMS: "305000", FactTruncBefore: "0",
		FactTruncEntries: "11", FactOtherLoss: "0", FactPosts: "60000:start,235000:truncated", FactRefused: "0", FactPiActive: "active",
		FactRestartsPre: "0", FactRestartsVerify: "0", FactRestartsPost: "0", FactPiVerified: "yes", FactLostBefore: "0",
		FactLostAfter: "0", FactOverflowBefore: "no", FactOverflowAfter: "no"}
	if name == "truncation-10" {
		base[FactTruncStartsMS], base[FactTruncEntries], base[FactPosts] = startsValue(soundStarts(10)), "10", "60000:start"
		base[FactTruncEndMS] = "300000"
	}
	return probeRun(name, truncationFacts, base, change...)
}

// soundStarts are the starts in ms of a sound run of n execs: from 100 s one every 5 s, the last 80 s after the one
// before.
func soundStarts(n int) []int {
	s := make([]int, n)
	for i := range n - 1 {
		s[i] = 100000 + i*5000
	}
	s[n-1] = s[n-2] + 80000
	return s
}

// startsFact is the starts fact of s, each at its place set to the value after it in set.
func startsFact(s []int, set ...int) string {
	s = append([]int(nil), s...)
	for i := 0; i+1 < len(set); i += 2 {
		s[set[i]] = set[i+1]
	}
	each := make([]string, len(s))
	for i, v := range s {
		each[i] = strconv.Itoa(v)
	}
	return FactTruncStartsMS + "=" + strings.Join(each, ",")
}

// startsValue is the value of the starts fact of s.
func startsValue(s []int) string {
	_, v, _ := strings.Cut(startsFact(s), "=")
	return v
}

// truncCase is a change to a sound run, ";"-separated, and the verdict and the words of the reason it must give.
type truncCase struct{ change, want, reason string }

// hasReason: want is in r, and a number at either end of want is not part of a longer one in r.
func hasReason(r, want string) bool {
	digit := func(b byte) bool { return b >= '0' && b <= '9' }
	for i := strings.Index(r, want); i >= 0 && want != ""; {
		end := i + len(want)
		if (i == 0 || !digit(r[i-1]) || !digit(want[0])) && (end == len(r) || !digit(r[end]) || !digit(want[len(want)-1])) {
			return true
		}
		next := strings.Index(r[i+1:], want)
		if next < 0 {
			return false
		}
		i += 1 + next
	}
	return false
}

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
		if v, r := JudgeTrial(tr, truncRun(name, change...), cleanBuild, cleanBuild); v != c.want || !hasReason(r, c.reason) {
			t.Errorf("%s %q: %s (%s), want %s (%s)", name, c.change, v, r, c.want, c.reason)
		}
	}
}

// Eleven truncated records pass only with one truncated alert after the 11th exec began and within 65 s of it
// (ADR 0069, points 3 and 4).
func TestJudgeTruncationOverTheLimit(t *testing.T) {
	posts := FactPosts + "=60000:start,"
	sound := "one truncated alert 10s after the last exec"
	judgeTruncationCases(t, "truncation-11", append([]truncCase{
		{"", Pass, sound},
		{posts + "290000:truncated", Pass, "one truncated alert 1m5s after the last exec"},
		{posts + "235000:truncated,245000:unknown", Pass, sound},
		{FactPosts + "=100000:start,235000:truncated", Pass, sound}, // the start in the first exec's ms
		{FactPosts + "=0:start,235000:truncated", Pass, sound},      // a start at the clock's zero
		{FactPosts + "=60000:start", Miss, "no truncated alert reached the sink"},
		{posts + "290001:truncated", Miss, "the truncated alert 1m5.001s after the last exec, over 1m5s"},
		{posts + "225000:truncated", Miss, "a truncated alert at 225000 ms, before the last exec at 225000"}, // before its record
		{posts + "150200:truncated", Miss, "a truncated alert at 150200 ms, before the last exec at 225000"}, // the 10th's, late
		{posts + "145000:truncated", Miss, "a truncated alert at 145000 ms, before the last exec at 225000"}, // at the 10th
		{posts + "90000:truncated", Miss, "a truncated alert at 90000 ms, before the last exec at 225000"},   // before any exec
		{posts + "235000:truncated,245000:truncated", Miss, "2 truncated alerts, the second at 245000 ms"},
		{posts + "235000:unknown", Miss, "no truncated alert reached the sink"},  // another tag
		{FactRefused + "=1", Miss, "the sink refused 1 of the watcher's pushes"}, // a refused push may be the alert
		{FactPosts + "=none;" + FactRefused + "=2", Miss, "the sink refused 2 of the watcher's pushes"},
		{FactPiActive + "=failed", Miss, "the watcher is failed at the end, restarts 0 to 0"},
		{FactRestartsPost + "=1", Miss, "the watcher is active at the end, restarts 0 to 1"},
		{FactPiActive + "=" + strings.Repeat("a", 80), Miss, "the watcher is " + strings.Repeat("a", 64) + " at the end"}, // quoted to 64
	}, append(append(truncationSchedule(11, sound, "one truncated alert 9s after the last exec"), truncationRestarts(sound)...), truncationInvalid("11", "12", "10")...)...))
}

// Ten truncated records pass only without any truncated alert in the whole window (ADR 0069, points 3 and 4).
func TestJudgeTruncationAtTheLimit(t *testing.T) {
	posts := FactPosts + "=60000:start,"
	sound := "no truncated alert for 10 truncated records"
	judgeTruncationCases(t, "truncation-10", append([]truncCase{
		{"", Pass, sound},
		{posts + "200000:unknown", Pass, sound},
		{posts + "200000:truncated", Miss, "a truncated alert at 200000 ms for 10 truncated records"},
		{posts + "90000:truncated", Miss, "a truncated alert at 90000 ms for 10"}, // before the first exec
		{posts + "299999:truncated", Miss, "a truncated alert at 299999 ms for 10"},
		{FactRefused + "=1", Miss, "the sink refused 1 of"},                      // the refused push may be the alert
		{FactPiActive + "=inactive", Miss, "the watcher is inactive at the end"}, // a watcher gone says nothing
		{FactRestartsPost + "=2", Miss, "restarts 0 to 2"},                       // a restart forgets the hour's count
	}, append(append(truncationSchedule(10, sound, sound), truncationRestarts(sound)...), truncationInvalid("10", "11", "9")...)...))
}

// truncationSchedule are the changes to the starts of a sound run of n execs at and past each bound of the schedule:
// all but the last from the first every 5 s, the last 80 s after the one before, each up to a second late and never
// early, every one in order, and the sink read 80 s after the last and within the hour; lateSound is the PASS of a
// last exec a second late.
func truncationSchedule(n int, sound, lateSound string) []truncCase {
	s := soundStarts(n)
	first, prev, last := s[0], s[n-2], s[n-1]
	late := func(exec, ms, ref, due int) string {
		return fmt.Sprintf("exec %d starts %d ms after exec %d, the trial %d to %d", exec, ms, ref, due, due+1000)
	}
	order := func(exec, ms int) string {
		return fmt.Sprintf("exec %d starts at %d ms, not after exec %d at %d", exec, ms, exec-1, s[exec-2])
	}
	burst := []int{1, 120000} // 20 s late, then the rest at once
	for i := 2; i < n; i++ {
		burst = append(burst, i, 120000+i)
	}
	end81 := ";" + FactTruncEndMS + "=" + strconv.Itoa(prev+161000) // the sink read 80 s after a last exec a second late
	middle := []int{5, prev - 4000}                                 // late in the middle, then at once until the one before the last is due
	for i := 6; i < n-2; i++ {
		middle = append(middle, i, prev-4000+i-5)
	}
	return []truncCase{
		{startsFact(s, 3, s[3]+1000), Pass, sound},
		{startsFact(s, 3, s[3]+1000, 4, s[4]+1000), Pass, sound},
		{startsFact(s, n-1, prev+81000) + end81, Pass, lateSound},
		{startsFact(s, n-2, prev+1000, n-1, prev+81000) + end81, Pass, lateSound},
		{startsFact(s, 3, s[3]+1001), Invalid, late(4, 16001, 1, 15000)},
		{startsFact(s, 3, s[3]-1), Invalid, late(4, 14999, 1, 15000)},
		{startsFact(s, 1, s[1]-1), Invalid, late(2, 4999, 1, 5000)},
		{startsFact(s, n-2, prev+1001), Invalid, late(n-1, (n-2)*5000+1001, 1, (n-2)*5000)},
		{startsFact(s, n-1, prev+81001), Invalid, late(n, 81001, n-1, 80000)},
		{startsFact(s, n-1, prev+79999), Invalid, late(n, 79999, n-1, 80000)},
		{startsFact(s, burst...), Invalid, late(2, 20000, 1, 5000)},
		{startsFact(s, 3, s[3]+1000, 4, s[3]+1001), Invalid, late(5, 16001, 1, 20000)},
		{startsFact(s, middle...), Invalid, late(6, prev-4000-first, 1, 25000)},
		{startsFact(s, 1, first), Invalid, order(2, first)},
		{startsFact(s, 3, s[2]), Invalid, order(4, s[2])},
		{startsFact(s, 3, s[2]-1), Invalid, order(4, s[2]-1)},
		{startsFact(s, n-1, prev), Invalid, order(n, prev)},
		{startsFact(s, 2, s[3], 3, s[2]), Invalid, late(3, 15000, 1, 10000)},
		{startsFact(s[:n-1]), Invalid, fmt.Sprintf("%d oversized execs ran, the trial runs %d", n-1, n)},
		{startsFact(append(s, last+5000)), Invalid, fmt.Sprintf("%d oversized execs ran, the trial runs %d", n+1, n)},
		{startsFact(s) + ",", Invalid, fmt.Sprintf("%d oversized execs ran, the trial runs %d", n+1, n)},
		{FactTruncStartsMS + "=", Invalid, fmt.Sprintf("1 oversized execs ran, the trial runs %d", n)},
		{strings.Replace(startsFact(s), ",115000,", ",115e3,", 1), Invalid, fmt.Sprintf("fact trunc_starts_ms is not %d plain numbers", n)},
		{strings.Replace(startsFact(s), ",115000,", ",-1,", 1), Invalid, fmt.Sprintf("fact trunc_starts_ms is not %d plain numbers", n)},
		{strings.Replace(startsFact(s), ",115000,", ", 115000,", 1), Invalid, fmt.Sprintf("fact trunc_starts_ms is not %d plain numbers", n)},
		{strings.Replace(startsFact(s), ",115000,", ",0115000,", 1), Invalid, fmt.Sprintf("fact trunc_starts_ms is not %d plain numbers", n)},
		{FactTruncEndMS + "=" + strconv.Itoa(first+3600000), Pass, sound},
		{FactTruncEndMS + "=" + strconv.Itoa(first+3600001), Invalid, "the sink was read 3600001 ms after the first exec, over 3600000"},
		{FactTruncEndMS + "=" + strconv.Itoa(last-1000), Invalid, "the sink was read 0 ms after the last exec, before 1m20s"},
		{FactTruncEndMS + "=" + strconv.Itoa(last+79999), Invalid, "the sink was read 79999 ms after the last exec, before 1m20s"},
	}
}

// truncationRestarts are the watcher's restarts before the run, as its verification began and after it: one before
// the verification is a MISS even when the verification's start of the watcher reset the count, and a count that
// fell without such a restart is no count.
func truncationRestarts(sound string) []truncCase {
	at := func(pre, verify, post int) string {
		return fmt.Sprintf("%s=%d;%s=%d;%s=%d", FactRestartsPre, pre, FactRestartsVerify, verify, FactRestartsPost, post)
	}
	return []truncCase{
		{at(1, 1, 1), Pass, sound},
		{at(0, 1, 0), Miss, "the watcher restarted before its verification, restarts 0 to 1"},
		{at(0, 1, 1), Miss, "the watcher restarted before its verification, restarts 0 to 1"},
		{at(2, 1, 1), Miss, "the watcher restarted before its verification, restarts 2 to 1"},
		{at(1, 1, 0), Invalid, "the watcher's restarts fell from 1 to 0 over its verification"},
		{at(3, 3, 2), Invalid, "the watcher's restarts fell from 3 to 2 over its verification"},
		{at(1, 1, 2), Miss, "the watcher is active at the end, restarts 1 to 2"},
		{FactRestartsVerify + "=missing", Invalid, "fact pi_restarts_verify is not a plain number"},
	}
}

// truncationInvalid are the changes that leave a run of want execs unproven either way; more and fewer are entries
// off its count.
func truncationInvalid(want, more, fewer string) []truncCase {
	out := []truncCase{
		{FactTruncEntries + "=" + more, Invalid, "holds 0 truncated entries before the execs and " + more + " after, want 0 and " + want},
		{FactTruncEntries + "=" + fewer, Invalid, "and " + fewer + " after, want 0 and " + want},
		{FactTruncBefore + "=1", Invalid, "holds 1 truncated entries before the execs and " + want + " after"}, // counts in the hour
		{FactOtherLoss + "=1", Invalid, "records lost besides the truncated: 1 loss entries, kernel lost 0 to 0, overflow no to no"},
		{FactLostAfter + "=4", Invalid, "kernel lost 0 to 4"},
		{FactOverflowAfter + "=yes", Invalid, "overflow no to yes"},
		{FactOverflowBefore + "=stale", Invalid, "overflow stale to no"},
		{FactOverflowBefore + "=" + strings.Repeat("y", 40), Invalid, "overflow " + strings.Repeat("y", 16) + " to no"}, // quoted to 16
		{FactOverflowAfter + "=" + strings.Repeat("z", 40), Invalid, "overflow no to " + strings.Repeat("z", 16)},
		{FactPosts + "=235000:truncated", Invalid, "the sink saw no start of the watcher before the first exec"},
		{FactPosts + "=110000:start,235000:truncated", Invalid, "the sink saw no start"}, // started after the first exec
		{FactPosts + "=60000:start,235000:Truncated", Invalid, `post "235000:Truncated" is not ms:tag`},
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
			out = append(out, truncCase{name, Invalid, fmt.Sprintf("report has %d of %d facts, not %s", len(truncationFacts)-1,
				len(truncationFacts), name)}) // each missing
		}
	}
	return out
}

// The sink read must come TruncationWait after the last exec, so the window covers the 65 s and its margin; a fact
// reported twice proves nothing.
func TestTruncationWindowAndRepeatedFacts(t *testing.T) {
	tr := trial(t, "truncation-11")
	if v, r := JudgeTrial(tr, truncRun(tr.Name, FactTruncEndMS+"=304999"), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("sink read a millisecond early: %s (%s)", v, r)
	}
	for _, again := range []Record{{Name: FactPosts, Value: "60000:start,235000:truncated"},
		{Name: FactTruncStartsMS, Value: startsValue(soundStarts(11))}} {
		o := truncRun(tr.Name)
		o.Facts = append(o.Facts, again)
		if v, r := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != Invalid || !hasReason(r, "fact "+again.Name+" reported twice") {
			t.Errorf("%s reported twice: %s (%s)", again.Name, v, r)
		}
	}
	if TruncationWait <= lossAlarm {
		t.Errorf("TruncationWait %s leaves no margin over %s", TruncationWait, lossAlarm)
	}
	_, r := JudgeTrial(tr, truncRun(tr.Name, FactOverflowAfter+"="+strings.Repeat("z", 40)), cleanBuild, cleanBuild)
	if !strings.HasSuffix(r, " to "+strings.Repeat("z", 16)) {
		t.Errorf("an overflow value must end the reason quoted to 16 bytes: %q", r)
	}
	for _, c := range []struct {
		r, want string
		ok      bool
	}{{"over 3600000", "over 3600000", true}, {"over 36000001", "over 3600000", false}, {"at 15 ms", "5 ms", false},
		{"at 15 ms, 5 ms", "5 ms", true}, {"x", "", false}} {
		if hasReason(c.r, c.want) != c.ok {
			t.Errorf("hasReason(%q, %q) is %v", c.r, c.want, !c.ok)
		}
	}
}

// The judge's key and limit are the Pi's (internal/watch) and acceptance truncation_alarm_per_hour's, and the table's
// counts sit on either side of the limit.
func TestTruncationIsThePis(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^id = "truncation_alarm_per_hour"\nmax = (\d+)\n`).FindSubmatch(data)
	if m == nil || string(m[1]) != strconv.Itoa(truncationLimit) {
		t.Errorf("acceptance truncation_alarm_per_hour %q, the judge's limit %d", m, truncationLimit)
	}
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
	o := truncRun(tr.Name, FactTruncEntries+"=0")
	if v, r := judgeTruncation(tr, o); v != Invalid || !strings.Contains(r, "10 oversized execs ran, the trial runs 0") {
		t.Errorf("no execs: %s (%s)", v, r)
	}
}
