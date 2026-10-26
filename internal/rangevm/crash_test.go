package rangevm

import (
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// crashRun is a sound run of collector failure trial tr: H=1000 numbers execed in time, S=5000
// acknowledged, all stored, and the next run starting right after the durable seq 5200; change sets
// name=value of the last boot, first:name=value of a reset's first boot, a name without a value
// removes it, and marks:h= or marks:s= sets a mark.
func crashRun(tr rangejob.Trial, change ...string) Outcome {
	first := map[string]string{FactTrial: tr.Name, FactPhase: "1", FactKernel: TargetKernel, FactResetArmed: "yes"}
	last := map[string]string{FactTrial: tr.Name, FactPhase: "1", FactKernel: TargetKernel, FactStoredPrefix: "1200",
		FactStoredCount: "1300", FactRecovered: "1", FactRecoveredLast: "5200", FactRecoveredSeq: "5201"}
	order := []string{FactTrial, FactPhase, FactKernel, FactStoredPrefix, FactStoredCount, FactRecovered, FactRecoveredLast, FactRecoveredSeq}
	if tr.Failure == FailReset {
		last[FactPhase], last[FactScratchJournal], last[FactScratchRecovery] = "2", "yes", "yes"
		order = append(order, FactScratchJournal, FactScratchRecovery)
	}
	o := Outcome{Marks: Marks{H: 1000, Synced: 5000}}
	for _, c := range change {
		name, value, set := strings.Cut(c, "=")
		if _, known := last[name]; set && !known && !strings.Contains(name, ":") {
			order = append(order, name) // a fact the trial does not have
		}
		switch {
		case name == "marks:h":
			o.Marks.H, _ = plainNumber(value)
		case name == "marks:s":
			o.Marks.Synced, _ = plainNumber(value)
		case strings.HasPrefix(name, "first:") && set:
			first[strings.TrimPrefix(name, "first:")] = value
		case strings.HasPrefix(name, "first:"):
			delete(first, strings.TrimPrefix(name, "first:"))
		case set:
			last[name] = value
		default:
			delete(last, name)
		}
	}
	for _, n := range order {
		if v, ok := last[n]; ok {
			o.Facts = append(o.Facts, Record{Name: n, Value: v})
		}
	}
	if tr.Failure == FailReset {
		for _, n := range []string{FactTrial, FactPhase, FactKernel, FactResetArmed} {
			if v, ok := first[n]; ok {
				o.FirstBoot = append(o.FirstBoot, Record{Name: n, Value: v})
			}
		}
	}
	return o
}

// Every number execed up to H and every seq acknowledged up to S must survive; a run that cannot show
// either, or contradicts itself, is INVALID.
func TestJudgeCrash(t *testing.T) {
	for _, name := range []string{"kill-collector-1", "reset-collector-7"} {
		tr := trial(t, name)
		if v, r := JudgeTrial(tr, crashRun(tr), cleanBuild, cleanBuild); v != Pass {
			t.Fatalf("%s sound run: %s (%s)", name, v, r)
		}
		cases := map[string][]string{
			Miss: {
				"stored_prefix=999",                      // a number execed in time is gone
				"recovered_last=4999,recovered_seq=5000", // Open reused an acknowledged seq
				"marks:s=1005200",                        // an overclaimed S: no run can show it survived
				"stored_prefix=0,stored_count=0",
			},
			Pass: {
				"stored_prefix=1000",                     // exactly H
				"recovered_last=5000,recovered_seq=5001", // exactly S
			},
			Invalid: {
				"marks:h=0", "marks:s=0", "recovered=0", "recovered=2", "recovered_seq=5200", "recovered_seq=5202",
				"stored_count=1199", "stored_prefix=-1", "recovered_last=", "kernel=6.0.0", "canary=seen",
				"recovered", "stored_count", "recovered_last=01,recovered_seq=2", "trial=kill-collector-2",
			},
		}
		for want, changes := range cases {
			for _, c := range changes {
				if v, r := JudgeTrial(tr, crashRun(tr, strings.Split(c, ",")...), cleanBuild, cleanBuild); v != want {
					t.Errorf("%s with %s: %s (%s); want %s", name, c, v, r, want)
				}
			}
		}
	}
	reset := trial(t, "reset-collector-1")
	for _, c := range []string{"scratch_recovery=no", "scratch_journal=no", "first:reset_armed", "first:kernel=6.0.0", "scratch_journal"} {
		if v, r := JudgeTrial(reset, crashRun(reset, c), cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("reset with %s: %s (%s); want INVALID", c, v, r)
		}
	}
	kill := trial(t, "kill-collector-1")
	if v, _ := JudgeTrial(kill, crashRun(kill, "scratch_journal=yes"), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("a kill reporting a superblock: %s; want INVALID", v)
	}
}

// crash_loss_ms is decided by 20 kills and 20 resets of the collector at sustained_rate besides the
// writer controls, in rows a batch can run.
func TestCrashTrialsOfTheCollector(t *testing.T) {
	runs := map[string]int{}
	for _, tr := range rangejob.Trials() {
		if tr.Method() != rangejob.MethodCollectorFailure {
			continue
		}
		if tr.Metric != rangejob.MetricCrashLoss || tr.Expect != "" || tr.Load != (rangejob.Load{Kind: rangejob.LoadExec, Rate: 2000, Seconds: 20}) {
			t.Errorf("%s: %+v", tr.Name, tr)
		}
		runs[tr.Failure] += tr.Count
	}
	if runs[FailKill] < 20 || runs[FailReset] < 20 {
		t.Errorf("runs per failure %v; acceptance asks 20 of each", runs)
	}
}
