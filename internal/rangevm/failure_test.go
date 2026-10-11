package rangevm

import (
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

func TestVerdictNamesMatchTheTable(t *testing.T) {
	if Pass != rangejob.ExpectPass || Miss != rangejob.ExpectMiss {
		t.Fatal("rangejob's expected verdicts are not rangevm's")
	}
	for name, want := range map[string]string{
		"rate-sustained": Pass, "rate-control-drop": Miss, "reset-control-sync250": Pass,
		"reset-control-lastsync1500": Miss, "kill-control-buffer2s": Miss,
	} {
		if got := ExpectedVerdict(trial(t, name)); got != want {
			t.Errorf("%s must give %s, table says %s", name, want, got)
		}
	}
}

// failureRun is a sound run of tr with H 1000 and everything through 1200 stored, changed by
// name=value pairs ("first:" before a name changes the first boot).
func failureRun(tr rangejob.Trial, change ...string) Outcome {
	first := map[string]string{FactTrial: tr.Name, FactPhase: "1", FactKernel: TargetKernel, FactResetArmed: "yes"}
	last := map[string]string{FactTrial: tr.Name, FactPhase: "1", FactKernel: TargetKernel, FactStoredPrefix: "1200", FactStoredCount: "1300"}
	order := []string{FactTrial, FactPhase, FactKernel, FactStoredPrefix, FactStoredCount}
	if tr.Failure == FailReset {
		last[FactPhase], last[FactScratchJournal], last[FactScratchRecovery] = "2", "yes", "yes"
		order = append(order, FactScratchJournal, FactScratchRecovery)
	}
	for _, c := range change {
		name, value, _ := strings.Cut(c, "=")
		if n, ok := strings.CutPrefix(name, "first:"); ok {
			first[n] = value
		} else {
			last[name] = value
		}
	}
	o := Outcome{Marks: Marks{H: 1000, Synced: 1100}}
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
		if v, ok := first["canary"]; ok {
			o.FirstBoot = append(o.FirstBoot, Record{Name: "canary", Value: v})
		}
	}
	return o
}

func TestJudgeFailure(t *testing.T) {
	for _, name := range []string{"reset-control-sync250", "kill-control-buffer2s"} {
		tr := trial(t, name)
		if v, r := JudgeTrial(tr, failureRun(tr), cleanBuild, cleanBuild); v != Pass {
			t.Errorf("%s sound run: %s (%s)", name, v, r)
		}
		cases := map[string]string{
			"stored_prefix=999":  Miss,
			"stored_prefix=1000": Pass,
			"stored_prefix=0999": Invalid,
			"stored_count=1100":  Invalid,
			"kernel=6.1":         Invalid,
			"canary=seen":        Invalid,
			"stored_prefix=":     Invalid,
		}
		for c, want := range cases {
			o := failureRun(tr, c)
			if c == "canary=seen" {
				o.Facts = append(o.Facts, Record{Name: "canary", Value: "seen"})
			}
			if v, r := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != want {
				t.Errorf("%s %s: %s (%s); want %s", name, c, v, r, want)
			}
		}
		noPhase := failureRun(tr)
		noPhase.Facts = append(noPhase.Facts[:1:1], noPhase.Facts[2:]...)
		if v, _ := JudgeTrial(tr, noPhase, cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("%s without its phase: %s", name, v)
		}
		o := failureRun(tr)
		o.Marks.H = 0
		if v, _ := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("%s with H 0: %s, want INVALID", name, v)
		}
		o.Invalid = "no fail mark"
		if v, _ := JudgeTrial(tr, o, cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("%s with an invalid boot: %s", name, v)
		}
		dup := failureRun(tr)
		dup.Facts = append(dup.Facts, dup.Facts[3])
		if v, _ := JudgeTrial(tr, dup, cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("%s with a repeated fact: %s", name, v)
		}
		if v, _ := JudgeTrial(tr, failureRun(tr), cleanBuild, strings.Repeat("f", 40)); v != Invalid {
			t.Errorf("%s judged by another build: %s", name, v)
		}
		if v, _ := JudgeTrial(tr, failureRun(tr), "dev", "dev"); v != Invalid {
			t.Errorf("%s from a dev launcher: %s", name, v)
		}
	}
	kill := trial(t, "kill-control-buffer2s")
	o := failureRun(kill)
	o.Facts = append(o.Facts[:3], Record{Name: FactTrialError, Value: "mkfs failed"})
	if v, r := JudgeTrial(kill, o, cleanBuild, cleanBuild); v != Invalid || !strings.Contains(r, "mkfs failed") {
		t.Errorf("guest error: %s (%s)", v, r)
	}
	// sync250's premise is a writer synced through H; without it the run is INVALID, not a MISS.
	sync250 := trial(t, "reset-control-sync250")
	stalled := failureRun(sync250, "stored_prefix=999")
	stalled.Marks.Synced = 999
	if v, r := JudgeTrial(sync250, stalled, cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("sync250 synced short of H: %s (%s); want INVALID", v, r)
	}
	lastsync := trial(t, "reset-control-lastsync1500")
	short := failureRun(lastsync, "stored_prefix=999")
	short.Marks.Synced = 900
	if v, r := JudgeTrial(lastsync, short, cleanBuild, cleanBuild); v != Miss {
		t.Errorf("lastsync1500 synced short of H by design: %s (%s); want MISS", v, r)
	}
	reset := trial(t, "reset-control-sync250")
	for _, c := range []string{"scratch_journal=no", "scratch_recovery=no", "first:kernel=6.1", "first:canary=x"} {
		if v, r := JudgeTrial(reset, failureRun(reset, c), cleanBuild, cleanBuild); v != Invalid {
			t.Errorf("reset %s: %s (%s); want INVALID", c, v, r)
		}
	}
}
