package watch

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
)

func TestAdvanceVerifiesAcrossBundles(t *testing.T) {
	ctx := context.Background()
	log := enc(t, batches(600)...)
	l, f, err := Advance(ctx, Log{}, headOf(log[:300]), fetchFrom(log))
	if err != nil || l.Size != 300 || len(l.Partial) != 44 || f.Entries != 300 || f.Broken != 0 || l.check() != nil {
		t.Fatalf("to 300: size %d, partial %d, %+v, %v", l.Size, len(l.Partial), f, err)
	}
	l, f, err = Advance(ctx, l, headOf(log), fetchFrom(log))
	if err != nil || l.Size != 600 || f.Entries != 300 || f.Broken != 0 || l.Root != mth(log) || l.check() != nil {
		t.Fatalf("to 600: size %d, %+v, %v", l.Size, f, err)
	}
}

// The relay's copy of entries the Pi verified is never read: a changed prefix of a partial bundle neither
// breaks verification nor reaches the kept bundle.
func TestAdvanceIgnoresHostCopyOfVerifiedEntries(t *testing.T) {
	ctx := context.Background()
	log := enc(t, batches(300)...)
	l := verified(t, log[:260])
	served := append([][]byte(nil), log...)
	served[256] = enc(t, entry.Announce{Kind: entry.AnnounceShutdown})[0]
	l, _, err := Advance(ctx, l, headOf(log), fetchFrom(served))
	if err != nil || l.Size != 300 || !bytes.Equal(l.Partial[0], log[256]) {
		t.Fatalf("size %d, err %v", l.Size, err)
	}
}

func TestForkRefusedAgainstCosigned(t *testing.T) {
	ctx := context.Background()
	log := enc(t, batches(300)...)
	start := verified(t, log[:100])
	changed := append([][]byte(nil), log...)
	changed[150] = append([]byte(nil), log[150]...)
	changed[150][len(changed[150])-1] ^= 1
	swapped := append([][]byte(nil), log...)
	swapped[200], swapped[201] = swapped[201], swapped[200]
	for name, served := range map[string][][]byte{"a changed byte": changed, "two entries swapped": swapped} {
		l, f, err := Advance(ctx, start, headOf(log), fetchFrom(served))
		if !errors.Is(err, ErrMismatch) || l.Size != 100 || f.Entries != 0 {
			t.Errorf("%s: size %d, err %v, want ErrMismatch at 100", name, l.Size, err)
		}
	}
	// the legitimate log still verifies from the same state
	if l, _, err := Advance(ctx, start, headOf(log), fetchFrom(log)); err != nil || l.Size != 300 {
		t.Fatalf("genuine log: size %d, err %v", l.Size, err)
	}
}

func TestWitnessBehindPiAlarms(t *testing.T) {
	ctx := context.Background()
	log := enc(t, batches(50)...)
	l := verified(t, log)
	other := headOf(log)
	other.Root[0] ^= 1
	for name, h := range map[string]Head{"behind": headOf(log[:49]), "another root": other} {
		if got, _, err := Advance(ctx, l, h, fetchFrom(log)); !errors.Is(err, ErrFork) || got.Size != 50 {
			t.Errorf("%s: size %d, err %v, want ErrFork", name, got.Size, err)
		}
	}
	if _, f, err := Advance(ctx, l, headOf(log), fetchFrom(log)); err != nil || f.Entries != 0 {
		t.Fatalf("same head: %+v %v", f, err)
	}
}

func TestEmptyHeadMustBeTheEmptyRoot(t *testing.T) {
	ctx := context.Background()
	if _, _, err := Advance(ctx, Log{}, Head{Size: 0, Root: mth(nil)}, fetchFrom(nil)); err != nil {
		t.Fatalf("the empty log: %v", err)
	}
	if _, _, err := Advance(ctx, Log{}, Head{Size: 0, Root: [32]byte{1}}, fetchFrom(nil)); !errors.Is(err, ErrFork) {
		t.Fatalf("another root at 0 entries: %v", err)
	}
}

func TestLogRules(t *testing.T) {
	b := func(first, last uint64) entry.Body { return entry.Batch{First: first, Last: last, Root: [32]byte{1}} }
	s := func(first, last uint64) entry.Body { return entry.Seal{First: first, Last: last, SHA256: [32]byte{2}} }
	cases := []struct {
		name   string
		bodies []entry.Body
		broken int
	}{
		{"a log as the ledger writes it", []entry.Body{entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStarting},
			b(5, 9), entry.Loss{Seq: 10, Stage: entry.StageTruncated, Records: 1}, b(10, 12), s(1, 12),
			entry.Health{State: entry.StateOK}, b(13, 20), s(13, 20), entry.Announce{Kind: entry.AnnounceSuspend}, b(21, 22),
			entry.Final{NextOrigin: "next/log"}}, 0},
		{"a gap between batches", []entry.Body{b(1, 5), b(7, 9)}, 1},
		{"batches that overlap", []entry.Body{b(1, 5), b(5, 9)}, 1},
		{"a seal before its batch", []entry.Body{b(1, 5), s(1, 9), b(6, 9)}, 1},
		{"a seal with no batch", []entry.Body{s(1, 5)}, 1},
		{"two seals after one batch", []entry.Body{b(1, 5), s(1, 5), s(1, 5)}, 1},
		{"seals that do not tile", []entry.Body{b(1, 5), s(1, 5), b(6, 9), s(7, 9)}, 1},
		{"a loss of a batched record", []entry.Body{b(1, 5), entry.Loss{Seq: 5, Stage: entry.StageQueue, Records: 3}}, 1},
		{"an entry after final", []entry.Body{b(1, 5), entry.Final{NextOrigin: "next/log"}, b(6, 9)}, 1},
		{"a loss the next batch does not cover", []entry.Body{b(1, 5), entry.Loss{Seq: 100, Stage: entry.StageQueue,
			Records: 1}, b(6, 10)}, 1},
		{"a loss left uncovered by final at the cap", []entry.Body{b(1, 5), entry.Loss{Seq: 6, Stage: entry.StageCap,
			Records: 1}, entry.Final{NextOrigin: "next/log"}}, 0},
	}
	for _, c := range cases {
		log := enc(t, c.bodies...)
		_, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
		if err != nil || f.Broken != c.broken || (c.broken > 0) != (f.Problem != "") {
			t.Errorf("%s: broken %d (%q), err %v, want %d", c.name, f.Broken, f.Problem, err, c.broken)
		}
	}
}

func TestUndecodableEntryIsCountedAndPassed(t *testing.T) {
	log := append(enc(t, batches(3)...), []byte("not an entry"))
	log = append(log, enc(t, entry.Batch{First: 31, Last: 40, Root: [32]byte{1}})...)
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || l.Size != 5 || f.Broken != 1 || f.Problem != "an entry that does not decode" || l.Rules.BatchLast != 40 {
		t.Fatalf("size %d, %+v, rules %+v, err %v", l.Size, f, l.Rules, err)
	}
}

func TestNothingAfterFinal(t *testing.T) {
	log := enc(t, entry.Batch{First: 1, Last: 2, Root: [32]byte{1}}, entry.Final{NextOrigin: "next/log"})
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || !f.Final || f.Broken != 0 || !l.Rules.Final {
		t.Fatalf("%+v %v", f, err)
	}
	if ev := NewWatchdog(DefaultLimits, time.Now(), nil, false).Grew(time.Now(), f, l.Rules); len(ev) != 1 || ev[0].Key != KeyFinal {
		t.Fatalf("events %+v, want one final", ev)
	}
	log = append(log, enc(t, entry.Health{State: entry.StateOK})...)
	if _, f, err := Advance(context.Background(), l, headOf(log), fetchFrom(log)); err != nil || f.Broken != 1 {
		t.Fatalf("after final: %+v %v", f, err)
	}
}

// Each loss stage alarms under its own key and no other, so an alert names where records were lost (ADR 0039,
// point 1); truncated records keep their own condition.
func TestLossAlarmsUnderItsStage(t *testing.T) {
	now := time.Now()
	for stage := entry.StageCap; stage <= entry.StageDispatcher; stage++ {
		if stage == entry.StageTruncated {
			continue
		}
		log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}}, entry.Loss{Seq: 5, Stage: stage, Records: 1},
			entry.Batch{First: 5, Last: 9, Root: [32]byte{1}}, entry.Health{State: entry.StateOK})
		l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
		if err != nil || f.Broken != 0 || f.Lost[stage] != 1 {
			t.Fatalf("stage %d: %+v %v", stage, f, err)
		}
		ev := NewWatchdog(DefaultLimits, now, nil, false).Grew(now, f, l.Rules)
		if len(ev) != 1 || ev[0].Key != lossKeys[stage] || ev[0].Key == "" {
			t.Errorf("stage %d: events %+v, want one %q", stage, ev, lossKeys[stage])
		}
		if _, ok := pushTitle[lossKeys[stage]]; !ok {
			t.Errorf("stage %d: no title for %q", stage, lossKeys[stage])
		}
	}
}

// A health entry with unstored records alarms as lossunstored; an UNKNOWN for a lasting reason, auditstat's and
// auditd's ones included (ADR 0038, point 4), alarms at once.
func TestUnstoredAndUnknownAlarm(t *testing.T) {
	now := time.Now()
	for _, r := range []entry.Reason{entry.ReasonStoreDown, entry.ReasonAuditStale, entry.ReasonAuditd} {
		log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}},
			entry.Health{State: entry.StateUnknown, Reason: r, Unstored: 3})
		l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
		if err != nil || f.Unstored != 1 || f.Unknown != 1 || l.Rules.Overflow {
			t.Fatalf("reason %d: %+v %v", r, f, err)
		}
		ev := NewWatchdog(DefaultLimits, now, nil, false).Grew(now, f, l.Rules)
		if len(ev) != 2 || ev[0].Key != KeyLossUnstored || ev[1].Key != KeyUnknown {
			t.Errorf("reason %d: events %+v, want lossunstored and unknown", r, ev)
		}
	}
}

// auditd's dispatcher overflow is a condition under lossdispatcher while the health says so, not a one-off
// UNKNOWN: it reminds every 6 h like the others, a restart keeps it and the next other health ends it.
func TestDispatcherOverflowIsACondition(t *testing.T) {
	now := time.Now()
	log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}},
		entry.Health{State: entry.StateUnknown, Reason: entry.ReasonDispatcher})
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || f.Unknown != 0 || !l.Rules.Overflow || l.Rules.Pending {
		t.Fatalf("%+v %+v %v", f, l.Rules, err)
	}
	w := NewWatchdog(DefaultLimits, now, nil, false)
	if ev := w.Grew(now, f, l.Rules); len(ev) != 0 {
		t.Fatalf("events %+v: the overflow is a condition, not an event", ev)
	}
	if _, ok := w.Conditions(now, false)[KeyLossDispatcher]; !ok || !slices.Contains(conditions, KeyLossDispatcher) {
		t.Fatalf("no lossdispatcher condition: %v", w.Conditions(now, false))
	}
	re := NewWatchdog(DefaultLimits, now, nil, false)
	re.overflow = l.Rules.Overflow && !l.Rules.Final
	if _, ok := re.Conditions(now.Add(time.Hour), false)[KeyLossDispatcher]; !ok {
		t.Fatal("a restart lost the lossdispatcher condition")
	}
	log = append(log, enc(t, entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLaurelDisconnected})...)
	l2, f2, err := Advance(context.Background(), l, headOf(log), fetchFrom(log))
	if err != nil || l2.Rules.Overflow || f2.Unknown != 1 {
		t.Fatalf("after another reason: %+v %+v %v", f2, l2.Rules, err)
	}
	w.Grew(now, f2, l2.Rules)
	if _, ok := w.Conditions(now, false)[KeyLossDispatcher]; ok {
		t.Fatal("the lossdispatcher condition outlived another health")
	}
}

// The cap's UNKNOWN and final verified in one step still alert the cap, once, as the condition never holds.
func TestLogCapAndFinalInOneStep(t *testing.T) {
	now := time.Now()
	log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}}, entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLogCap},
		entry.Final{NextOrigin: "next/log"})
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || f.LogCap != 1 || !f.Final || f.Broken != 0 {
		t.Fatalf("%+v %v", f, err)
	}
	w := NewWatchdog(DefaultLimits, now, nil, false)
	keys := map[Key]int{}
	for _, e := range w.Grew(now, f, l.Rules) {
		keys[e.Key]++
	}
	if keys[KeyLogCap] != 1 || keys[KeyFinal] != 1 {
		t.Fatalf("events %v; want one logcap and one final", keys)
	}
	if _, held := w.Conditions(now, false)[KeyLogCap]; held {
		t.Fatal("the cap holds after final")
	}
}

// After the cap's UNKNOWN only final may follow: anything else breaks the log's rules (ADR 0036, point 5).
func TestOnlyFinalFollowsTheCap(t *testing.T) {
	log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}}, entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLogCap},
		entry.Batch{First: 5, Last: 6, Root: [32]byte{1}})
	if _, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log)); err != nil || f.Broken != 1 {
		t.Fatalf("a batch after the cap: %+v %v", f, err)
	}
}

// The ledger's log at its cap (ADR 0036, point 5) alarms under its own key, not the collector's UNKNOWN, as a
// condition that a restart keeps and final ends.
func TestLogCapAlarms(t *testing.T) {
	now := time.Now()
	log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}}, entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLogCap})
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || f.LogCap != 1 || f.Unknown != 0 || f.Broken != 0 || l.Rules.Pending {
		t.Fatalf("%+v %v", f, err)
	}
	w := NewWatchdog(DefaultLimits, now, nil, false)
	if ev := w.Grew(now, f, l.Rules); len(ev) != 0 {
		t.Fatalf("events %+v: the cap is a condition, not an event", ev)
	}
	if _, ok := w.Conditions(now, false)[KeyLogCap]; !ok || !l.Rules.Capped {
		t.Fatalf("no logcap condition: %v, capped %v", w.Conditions(now, false), l.Rules.Capped)
	}
	// it holds across a restart from the saved rules, until final
	re := NewWatchdog(DefaultLimits, now, nil, false)
	re.capped = l.Rules.Capped && !l.Rules.Final
	if _, ok := re.Conditions(now.Add(time.Hour), false)[KeyLogCap]; !ok {
		t.Fatal("a restart lost the logcap condition")
	}
	log = append(log, enc(t, entry.Final{NextOrigin: "next/log"})...)
	l2, f2, err := Advance(context.Background(), l, headOf(log), fetchFrom(log))
	if err != nil || f2.Broken != 0 || !l2.Rules.Final {
		t.Fatalf("final after the cap: %+v %v", f2, err)
	}
	w.Grew(now, f2, l2.Rules)
	if _, ok := w.Conditions(now, false)[KeyLogCap]; ok {
		t.Fatal("the logcap condition outlived final")
	}
	if _, ok := pushTitle[KeyLogCap]; !ok {
		t.Fatal("no title for the log cap's alert")
	}
}

// AlertsUnknown names exactly the reasons health counts as an UNKNOWN that alarms at once.
func TestAlertsUnknownIsHealths(t *testing.T) {
	for r := entry.ReasonStarting; r <= entry.ReasonAuditd; r++ {
		var f Findings
		(&Rules{}).health(entry.Health{State: entry.StateUnknown, Reason: r}, &f)
		if got := f.Unknown == 1; got != AlertsUnknown(r) {
			t.Errorf("reason %d: health counts an unknown %t, AlertsUnknown says %t", r, got, AlertsUnknown(r))
		}
	}
}

func TestHealthStartingGrace(t *testing.T) {
	t0 := time.Now()
	starting := entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStarting}
	log := enc(t, starting, entry.Health{State: entry.StateOK})
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || l.Rules.Pending || f.Unknown != 0 {
		t.Fatalf("starting then OK: %+v %+v %v", l.Rules, f, err)
	}
	log = append(log, enc(t, entry.Health{State: entry.StateUnknown, Reason: entry.ReasonCanaryPending})...)
	l, f, err = Advance(context.Background(), l, headOf(log), fetchFrom(log))
	if err != nil || !l.Rules.Pending {
		t.Fatalf("canary pending: %+v %v", l.Rules, err)
	}
	w := NewWatchdog(DefaultLimits, t0, nil, false)
	w.Grew(t0, f, l.Rules)
	if _, ok := w.Conditions(t0.Add(59*time.Second), false)[KeyHealth]; ok {
		t.Fatal("UNKNOWN alarmed within its grace")
	}
	if _, ok := w.Conditions(t0.Add(60*time.Second), false)[KeyHealth]; !ok {
		t.Fatal("UNKNOWN past its grace did not alarm")
	}
	log = append(log, enc(t, entry.Health{State: entry.StateOK})...)
	l, f, err = Advance(context.Background(), l, headOf(log), fetchFrom(log))
	if err != nil {
		t.Fatal(err)
	}
	w.Grew(t0.Add(61*time.Second), f, l.Rules)
	if _, ok := w.Conditions(t0.Add(62*time.Second), false)[KeyHealth]; ok {
		t.Fatal("OK did not end the alarm")
	}
}

func TestAdvanceKeepsStateOnFetchError(t *testing.T) {
	log := enc(t, batches(10)...)
	l := verified(t, log[:5])
	fail := func(context.Context, uint64, uint64) ([][]byte, error) { return nil, errMissing }
	got, f, err := Advance(context.Background(), l, headOf(log), fail)
	if !errors.Is(err, errMissing) || got.Size != 5 || f.Entries != 0 {
		t.Fatalf("size %d, err %v", got.Size, err)
	}
	short := func(context.Context, uint64, uint64) ([][]byte, error) { return log[:3], nil }
	if _, _, err := Advance(context.Background(), l, headOf(log), short); err == nil {
		t.Fatal("a bundle short of its width was taken")
	}
}

// An indicator for verify_s (decided on the Pi, L12): a day of log at sustained_rate is about 110k entries.
func TestVerifyDayIndicator(t *testing.T) {
	if testing.Short() {
		t.Skip("indicator only")
	}
	log := enc(t, batches(110_000)...)
	h := headOf(log)
	start := time.Now()
	l, _, err := Advance(context.Background(), Log{}, h, fetchFrom(log))
	if err != nil || l.Size != h.Size {
		t.Fatal(err)
	}
	t.Logf("verified %d entries in %v", l.Size, time.Since(start))
}

// An overflow that a later health ends in the same step alerts once (the condition never holds), and final ends
// the condition a restart keeps.
func TestDispatcherOverflowWithinOneStep(t *testing.T) {
	now := time.Now()
	log := enc(t, entry.Batch{First: 1, Last: 4, Root: [32]byte{1}},
		entry.Health{State: entry.StateUnknown, Reason: entry.ReasonDispatcher}, entry.Health{State: entry.StateOK})
	l, f, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log))
	if err != nil || f.Overflow != 1 || l.Rules.Overflow {
		t.Fatalf("%+v %+v %v", f, l.Rules, err)
	}
	w := NewWatchdog(DefaultLimits, now, nil, false)
	if ev := w.Grew(now, f, l.Rules); len(ev) != 1 || ev[0].Key != KeyLossDispatcher {
		t.Fatalf("events %+v, want one lossdispatcher", ev)
	}
	w.holds(Rules{Overflow: true, Final: true})
	if _, ok := w.Conditions(now, false)[KeyLossDispatcher]; ok {
		t.Fatal("the lossdispatcher condition outlived final")
	}
}
