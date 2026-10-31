package rangevm

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// alarmRun is a sound run of trial name: the start pushed at 60 s, the last growth at 100 s, the injection at
// 101 s and the silence alert after alertAfter, counted from the growth for silence, the injection for quiet.
func alarmRun(name string, alertAfter time.Duration, change map[string]string) Outcome {
	from, end := uint64(100_000), "101000"
	again := "none"
	if name == "quiet-off" || name == "quiet-masked" || name == "quiet-again" {
		from, end = 101_000, "106000" // the announcement's proof took 5 s
	}
	if name == "quiet-again" {
		again = "301000"
	}
	alert := uint64(alertAfter / time.Millisecond) //nolint:gosec // positive test durations
	base := map[string]string{
		FactInject: "ok", FactInjectMS: "101000", FactInjectEndMS: end, FactCosignedMS: "100000", FactGrownAfter: "no",
		FactPosts:   "60000:start," + strconv.FormatUint(from+alert, 10) + ":silence",
		FactRefused: "0", FactRestartsPre: "0", FactRestartsPost: "0", FactAgainMS: again, FactCosignGapMS: "5200",
		FactPiActive: "active",
	}
	var changes []string
	for k, v := range change {
		if k == "-" {
			changes = append(changes, v) // no "=": probeRun leaves the fact out
		} else {
			changes = append(changes, k+"="+v)
		}
	}
	return probeRun(name, alarmFacts, base, changes...)
}

func TestJudgeSilenceWindow(t *testing.T) {
	for _, name := range []string{"silence-wireguard", "silence-ledger", "silence-hard-stop"} {
		tr := trial(t, name)
		for _, c := range []struct {
			after time.Duration
			want  string
		}{
			{840 * time.Second, Pass}, {825 * time.Second, Pass}, {845 * time.Second, Pass},
			{824 * time.Second, Miss}, {846 * time.Second, Miss}, {900 * time.Second, Miss}, {20 * time.Minute, Miss},
		} {
			if v, r := JudgeTrial(tr, alarmRun(name, c.after, nil), cleanBuild, cleanBuild); v != c.want {
				t.Errorf("%s alert after %s: %s (%s), want %s", name, c.after, v, r, c.want)
			}
		}
	}
}

// A cap restarted by the second announcement, about 3 min after the first, alerts about 23 min after it.
func TestJudgeQuietCapNotRestarted(t *testing.T) {
	for _, name := range []string{"quiet-off", "quiet-masked", "quiet-again"} {
		tr := trial(t, name)
		for _, c := range []struct {
			after time.Duration
			want  string
		}{
			// counted from the stop (101 s); the proof ended 5 s later, at 106 s
			{RangeQuiet, Pass}, {RangeQuiet + time.Minute, Pass},
			{RangeQuiet - time.Millisecond, Miss},               // 19:54.999 after the proof's end
			{RangeQuiet + time.Minute + time.Millisecond, Miss}, // 21:00.001 after the stop
			{RangeQuiet - 5*time.Second, Miss}, {14 * time.Minute, Miss}, {23 * time.Minute, Miss},
		} {
			if v, r := JudgeTrial(tr, alarmRun(name, c.after, nil), cleanBuild, cleanBuild); v != c.want {
				t.Errorf("%s alert after %s: %s (%s), want %s", name, c.after, v, r, c.want)
			}
		}
	}
	tr := trial(t, "quiet-again")
	for _, again := range []string{"none", "101000", "220999", "x"} {
		if v, _ := JudgeTrial(tr, alarmRun("quiet-again", RangeQuiet, map[string]string{FactAgainMS: again}), cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("quiet-again with a second announcement at %q: %s", again, v)
		}
	}
	// quiet-again's log grows again between its announcements, after the first one: still sound.
	if v, r := JudgeTrial(tr, alarmRun("quiet-again", RangeQuiet, map[string]string{FactCosignedMS: "280000"}), cleanBuild, cleanBuild); v != Pass {
		t.Errorf("quiet-again with growth between its announcements: %s (%s)", v, r)
	}
	// a proof longer than proofMax cannot time the cap
	if v, _ := JudgeTrial(trial(t, "quiet-off"), alarmRun("quiet-off", RangeQuiet, map[string]string{FactInjectEndMS: "166001"}), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("quiet-off with a 65.001 s proof: %s", v)
	}
	if v, _ := JudgeTrial(trial(t, "quiet-off"), alarmRun("quiet-off", RangeQuiet, map[string]string{FactAgainMS: "301000"}), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("quiet-off with a second announcement: %s", v)
	}
}

func TestAlarmInvalidAndMissCases(t *testing.T) {
	tr := trial(t, "silence-ledger")
	ok := 840 * time.Second
	for want, changes := range map[string][]map[string]string{
		Invalid: {
			{FactInject: "error: systemctl stop balistid-ledger.service: exit status 1"},
			{FactGrownAfter: "yes"}, {FactGrownAfter: ""},
			{FactInjectEndMS: "101001"}, {FactInjectEndMS: "100999"}, {FactPiActive: "missing"},
			{FactPosts: "940000:silence"},                           // no start: the sink path is not shown
			{FactPosts: "60000:start,90000:silence,940000:silence"}, // silence before the injection
			{FactPosts: "60000:start,940000:Silence"}, {FactPosts: "60000:start;940000:silence"},
			{FactPosts: "940000:silence,60000:start"},
			{FactInjectMS: "-1"}, {FactRefused: "x"}, {FactKernel: "6.0.0"}, {FactTrial: "silence-wireguard"},
			{"-": FactPosts}, {"extra": "1"},
		},
		Miss: {
			// a watcher that is not running at the end, or restarted, broke the alarm's path (ADR 0021)
			{FactPiActive: "inactive"}, {FactPiActive: "failed"}, {FactPiActive: "activating"},
			{FactPiActive: "inactive", FactPosts: "60000:start"},
			{FactPosts: "60000:start", FactRestartsPost: "1"},
			{FactPosts: "60000:start"},
			{FactPosts: "60000:start,940000:loss"},
			{FactRestartsPost: "1"},
			{FactPosts: "none", FactRefused: "3"}, // the watcher's token refused: broken plumbing, not a pass
			{FactPosts: "940000:silence", FactRefused: "1"},
		},
	} {
		for _, c := range changes {
			if v, r := JudgeTrial(tr, alarmRun("silence-ledger", ok, c), cleanBuild, cleanBuild); v != want {
				t.Errorf("silence-ledger with %v: %s (%s), want %s", c, v, r, want)
			}
		}
	}
}

func TestAlarmMeasures(t *testing.T) {
	m := Measures(trial(t, "silence-wireguard"), alarmRun("silence-wireguard", 841*time.Second, nil))
	if m[MeasureAlarmMS] != 841_000 || m[FactCosignGapMS] != 5200 {
		t.Errorf("measures %v", m)
	}
	m = Measures(trial(t, "quiet-again"), alarmRun("quiet-again", RangeQuiet, nil))
	if m[MeasureAlarmMS] != uint64((RangeQuiet-5*time.Second)/time.Millisecond) { // from the proof's end, 5 s after the stop
		t.Errorf("quiet measures %v", m)
	}
}

// The judge's quiet window is the cap the range's drop-in gives the watcher.
func TestRangeQuietMatchesTheDropIn(t *testing.T) {
	data, err := os.ReadFile("../../range/balistid-pi-range.conf")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^ExecStart=/\S+ .* -quiet (\S+)$`).FindSubmatch(data)
	if m == nil {
		t.Fatal("no -quiet in the drop-in's ExecStart")
	}
	d, err := time.ParseDuration(string(m[1]))
	if err != nil || d != RangeQuiet {
		t.Errorf("drop-in -quiet %q, judge %s", m[1], RangeQuiet)
	}
}
