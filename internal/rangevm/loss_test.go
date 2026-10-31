package rangevm

import (
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/watch"
)

// lossTag is the key a loss case's alert carries, spelled out here so a change of LossTag fails these tests.
func lossTag(name string) string {
	for prefix, tag := range map[string]string{"loss-queue": "lossqueue", "loss-full-fs": "losscap", "loss-store": "lossstore"} {
		if strings.HasPrefix(name, prefix) {
			return tag
		}
	}
	return "loss"
}

// lossRun is a sound collector-loss run: start at 60 s, the injection from 100 s to 106 s, the ledger's entry of
// it and its stage's alert at 120 s; ":loss" in a change's posts is that stage's key.
func lossRun(name string, change map[string]string) Outcome {
	base := map[string]string{FactFirstUnknown: "none",
		FactInject: "ok", FactInjectMS: "100000", FactInjectEndMS: "106000", FactLossEntry: "yes",
		FactPosts: "60000:start,120000:loss", FactRefused: "0", FactPiActive: "active",
		FactLostBefore: "0", FactLostAfter: "0", FactOverflowAfter: "no", FactCollectorRestarts: "0 0",
	}
	base[FactPosts] = strings.ReplaceAll(base[FactPosts], ":loss", ":"+lossTag(name))
	var changes []string
	for k, v := range change {
		if k == FactPosts {
			v = strings.ReplaceAll(v, ":loss", ":"+lossTag(name))
		}
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
				{FactLossEntry: "error: checkpoint: no such file"}, {FactFirstUnknown: "error: checkpoint: no such file"},
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
	// The store's loss may come as its UNKNOWN when the ledger's first UNKNOWN is the store's; the queue's may not.
	unknown := map[string]string{FactPosts: "60000:start,120000:unknown", FactFirstUnknown: "2"}
	if v, r := JudgeTrial(trial(t, "loss-store-2"), lossRun("loss-store-2", unknown), cleanBuild, cleanBuild); v != Pass {
		t.Errorf("loss-store with an unknown alert: %s (%s)", v, r)
	}
	for _, first := range []string{"none", "8", "3"} {
		other := map[string]string{FactPosts: "60000:start,120000:unknown", FactFirstUnknown: first}
		if v, r := JudgeTrial(trial(t, "loss-store-2"), lossRun("loss-store-2", other), cleanBuild, cleanBuild); v != Miss {
			t.Errorf("loss-store with an unknown alert and first UNKNOWN %s: %s (%s)", first, v, r)
		}
	}
	// An UNKNOWN the ledger logged before the injection leaves the store's unknown alert unattributed: INVALID; the
	// queue's trial does not depend on it.
	before := map[string]string{FactPosts: "60000:start,120000:unknown", FactFirstUnknown: "before 2"}
	if v, r := JudgeTrial(trial(t, "loss-store-2"), lossRun("loss-store-2", before), cleanBuild, cleanBuild); v != Invalid {
		t.Errorf("loss-store with an UNKNOWN before the injection: %s (%s)", v, r)
	}
	if v, r := JudgeTrial(trial(t, "loss-queue-1"), lossRun("loss-queue-1", map[string]string{FactFirstUnknown: "before 3"}),
		cleanBuild, cleanBuild); v != Pass {
		t.Errorf("loss-queue with an UNKNOWN before the injection: %s (%s)", v, r)
	}
	// Another stage's alert is not the cause's (ADR 0039, point 3).
	for name, post := range map[string]string{"loss-queue-1": "lossstore", "loss-full-fs-1": "lossqueue", "loss-store-1": "losscap"} {
		run := probeRun(name, lossFacts, map[string]string{
			FactInject: "ok", FactInjectMS: "100000", FactInjectEndMS: "106000", FactLossEntry: "yes", FactFirstUnknown: "none",
			FactPosts: "60000:start,120000:" + post + ",121000:lossunstored", FactRefused: "0", FactPiActive: "active",
			FactLostBefore: "0", FactLostAfter: "0", FactOverflowAfter: "no", FactCollectorRestarts: "0 0",
		})
		if v, r := JudgeTrial(trial(t, name), run, cleanBuild, cleanBuild); v != Miss {
			t.Errorf("%s with a %s alert: %s (%s)", name, post, v, r)
		}
	}
	// A full filesystem's store gone down instead of to its cap is a MISS, even with its alert in time.
	down := map[string]string{FactLossEntry: "store down; loss -1 s0 r0; unstored health 14 s2 r2 u4"}
	if v, r := JudgeTrial(trial(t, "loss-full-fs-1"), lossRun("loss-full-fs-1", down), cleanBuild, cleanBuild); v != Miss {
		t.Errorf("loss-full-fs with its store down and a timely alert: %s (%s)", v, r)
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
		"60000:start":                     Pass,
		"60000:start,120000:loss":         Miss,
		"60000:start,120000:unknown":      Miss,
		"60000:start,90000:loss":          Miss,
		"60000:start,95000:unknown":       Miss,
		"60000:start,120000:daily":        Pass,
		"60000:start,120000:lossunstored": Miss,
		"60000:start,120000:losskernel":   Miss,
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

// The judges' keys are the Pi's (ADR 0039, point 1).
func TestLossTagsAreThePis(t *testing.T) {
	for inject, key := range map[string]watch.Key{
		rangejob.InjectQueue: watch.KeyLossQueue, rangejob.InjectFullFS: watch.KeyLossCap, rangejob.InjectStore: watch.KeyLossStore,
	} {
		if LossTag(inject) != string(key) {
			t.Errorf("%s: tag %q, the Pi's key %q", inject, LossTag(inject), key)
		}
	}
	if LossTag(rangejob.InjectKernel) != "" || LossTag(rangejob.InjectNone) != "" {
		t.Error("a case without a detector or a cause has a tag")
	}
}
