package rangevm

import (
	"testing"
)

// lossRun is a sound collector-loss run: start at 60 s, the injection from 100 s to 106 s, the ledger's entry of
// it and a loss alert at 120 s.
func lossRun(name string, change map[string]string) Outcome {
	base := map[string]string{
		FactInject: "ok", FactInjectMS: "100000", FactInjectEndMS: "106000", FactLossEntry: "yes",
		FactPosts: "60000:start,120000:loss", FactRefused: "0", FactPiActive: "active",
		FactLostBefore: "0", FactLostAfter: "0", FactOverflowAfter: "no", FactCollectorRestarts: "0 0",
	}
	var changes []string
	for k, v := range change {
		if k == "-" {
			changes = append(changes, v)
		} else {
			changes = append(changes, k+"="+v)
		}
	}
	return probeRun(name, lossFacts, base, changes...)
}

func TestJudgeLoss(t *testing.T) {
	for _, name := range []string{"loss-queue-1", "loss-full-fs-2", "loss-store-1"} {
		tr := trial(t, name)
		for want, changes := range map[string][]map[string]string{
			Pass: {nil, {FactPosts: "60000:start,165000:loss"}}, // 65 s after the injection's start
			Miss: {
				{FactPosts: "60000:start,171001:loss"}, // over 65 s even after its end
				{FactPosts: "60000:start"},
				{FactPosts: "60000:start,90000:loss"}, // before the injection
				{FactLossEntry: "no new entry of the cause"},
				{FactPiActive: "failed"},
				{FactPosts: "none", FactRefused: "2"},
			},
			Invalid: {
				{FactInject: "error: fsfreeze --freeze: exit status 1"},
				{FactInjectEndMS: "99999"},
				{FactPiActive: "missing"},
				{FactLostAfter: "3"}, {FactOverflowAfter: "yes"}, {FactOverflowAfter: "missing"},
				{FactLossEntry: "error: checkpoint: no such file"},
				{FactPosts: "120000:loss"},
				// within 65 s of the end, not of the start: the loss may have come at the start
				{FactPosts: "60000:start,171000:loss"},
				{FactInjectEndMS: "200000", FactPosts: "60000:start,200001:loss"},
				{FactKernel: "6.0.0"}, {"-": FactLossEntry}, {"extra": "1"},
			},
		} {
			for _, c := range changes {
				if v, r := JudgeTrial(tr, lossRun(name, c), cleanBuild, cleanBuild); v != want {
					t.Errorf("%s with %v: %s (%s), want %s", name, c, v, r, want)
				}
			}
		}
	}
	// A restarted collector spoils the queue's case only; a store may restart it as it fails.
	if v, _ := JudgeTrial(trial(t, "loss-queue-1"), lossRun("loss-queue-1", map[string]string{FactCollectorRestarts: "0 1"}), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("loss-queue with a collector restart: %s", v)
	}
	if v, r := JudgeTrial(trial(t, "loss-store-1"), lossRun("loss-store-1", map[string]string{FactCollectorRestarts: "0 1"}), cleanBuild, cleanBuild); v != Pass {
		t.Errorf("loss-store with a collector restart: %s (%s)", v, r)
	}
	// A full filesystem's store gone down is the store's race: INVALID with its alert in time, never PASS, and a
	// MISS without it; any other case without its entry still MISSes.
	down := LossStoreDown + "; loss -1 s0 r0; unstored health 14 s2 r2 u4"
	for _, c := range []struct{ name, posts, want string }{
		{"loss-full-fs-1", "60000:start,120000:loss", Invalid},
		{"loss-full-fs-1", "60000:start,165000:loss", Invalid},
		{"loss-full-fs-1", "60000:start", Miss},
		{"loss-full-fs-1", "60000:start,120000:unknown", Miss},
		{"loss-full-fs-1", "60000:start,171001:loss", Miss},
		{"loss-store-1", "60000:start,120000:loss", Miss},
		{"loss-queue-1", "60000:start,120000:loss", Miss},
	} {
		run := lossRun(c.name, map[string]string{FactLossEntry: down, FactPosts: c.posts})
		if v, r := JudgeTrial(trial(t, c.name), run, cleanBuild, cleanBuild); v != c.want {
			t.Errorf("%s with its store down and %s: %s (%s), want %s", c.name, c.posts, v, r, c.want)
		}
	}
	// The store's loss may come as its UNKNOWN; the queue's may not.
	if v, r := JudgeTrial(trial(t, "loss-store-2"), lossRun("loss-store-2", map[string]string{FactPosts: "60000:start,120000:unknown"}),
		cleanBuild, cleanBuild); v != Pass {
		t.Errorf("loss-store with an unknown alert: %s (%s)", v, r)
	}
	if v, _ := JudgeTrial(trial(t, "loss-queue-2"), lossRun("loss-queue-2", map[string]string{FactPosts: "60000:start,120000:unknown"}),
		cleanBuild, cleanBuild); v != Miss {
		t.Errorf("loss-queue with only an unknown alert: %s", v)
	}
}

// Kernel and dispatcher loss have no detector until balistid-auditstat: INVALID however they ran.
func TestKernelCasesInvalidWithoutDetector(t *testing.T) {
	for _, name := range []string{"loss-kernel", "loss-dispatcher"} {
		for _, c := range []map[string]string{nil, {FactLostAfter: "7"}, {FactPosts: "60000:start"}} {
			if v, _ := JudgeTrial(trial(t, name), lossRun(name, c), cleanBuild, cleanBuild); v != Invalid {
				t.Errorf("%s with %v: %s", name, c, v)
			}
		}
	}
}

// The control has no loss: any loss or unknown alert after the watcher's start is a MISS, also one before the
// control's moment of injection, none a PASS.
func TestLossControl(t *testing.T) {
	tr := trial(t, "loss-control-none")
	for posts, want := range map[string]string{
		"60000:start":                Pass,
		"60000:start,120000:loss":    Miss,
		"60000:start,120000:unknown": Miss,
		"60000:start,90000:loss":     Miss,
		"60000:start,95000:unknown":  Miss,
		"60000:start,120000:daily":   Pass,
	} {
		run := lossRun("loss-control-none", map[string]string{FactPosts: posts, FactLossEntry: "no new entry of the cause"})
		if v, r := JudgeTrial(tr, run, cleanBuild, cleanBuild); v != want {
			t.Errorf("control with %s: %s (%s), want %s", posts, v, r, want)
		}
	}
	m := Measures(trial(t, "loss-queue-1"), lossRun("loss-queue-1", nil))
	if m[MeasureAlarmMS] != 20000 { // from the injection's start, the bound a PASS proves
		t.Errorf("measures %v", m)
	}
}
