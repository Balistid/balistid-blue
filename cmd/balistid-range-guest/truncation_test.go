package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// A truncation trial's argv is stored truncated, needs the large stack to exec at all, and keeps each argument under
// the kernel's 128 KiB per string (ADR 0069, point 3).
func TestTruncatedArgvIsOverTheRecordLimit(t *testing.T) {
	c := argvTruncated
	args := c.args("balistid-truncation0123456789abcdef0123456789abcdef")
	total := 0
	for _, a := range args {
		total += len(a) + 1
		if len(a) >= 128<<10 {
			t.Errorf("argument of %d bytes, over MAX_ARG_STRLEN", len(a))
		}
	}
	if total <= rawrecord.MaxBytes || total <= defaultStack/4 || uint64(total) >= c.stack/4 || c.minBytes > uint64(total) {
		t.Errorf("argv of %d bytes: want over %d and %d, under %d", total, rawrecord.MaxBytes, defaultStack/4, c.stack/4)
	}
}

// Truncated entries count only from the index given and only of their stage; every other stage counts apart.
func TestLedgerLossesFromAnIndex(t *testing.T) {
	seq := uint64(3)
	loss := func(s entry.Stage) func(*anchor.Log) {
		return func(l *anchor.Log) {
			seq++
			if err := l.Record(t.Context(), link.Record{Seq: seq, Leaf: sha256.Sum256([]byte(strconv.FormatUint(seq, 10))),
				Loss: &entry.Loss{Seq: seq, Stage: s, Records: 1}}); err != nil {
				t.Fatal(err)
			}
			if err := l.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	// batch 1-3 (0); truncated, batch (1, 2); queue, batch (3, 4); truncated, batch (5, 6)
	root, v := writeLog(t, 3, loss(entry.StageTruncated), loss(entry.StageQueue), loss(entry.StageTruncated))
	for from, want := range map[uint64]truncLosses{
		0: {truncated: 2, other: 1, last: 5, size: 7},
		2: {truncated: 1, other: 1, last: 5, size: 7},
		6: {size: 7},
	} {
		if got, err := ledgerLossesIn(t.Context(), root, v, from); err != nil || got != want {
			t.Errorf("from %d: %+v, %v; want %+v", from, got, err, want)
		}
	}
	_, other := writeLog(t, 1)
	if _, err := ledgerLossesIn(t.Context(), root, other, 0); err == nil {
		t.Error("a log under another key was read")
	}
}

// The watcher counts as verified only past the last truncated entry, so a cosign up to it proves nothing.
func TestTruncVerifiedNeedsACosignPastTheLastEntry(t *testing.T) {
	yes := func(context.Context) string { return "yes" }
	for _, c := range []struct {
		cosigned uint64
		l        truncLosses
		want     bool
	}{
		{6, truncLosses{truncated: 11, last: 5}, true},
		{100, truncLosses{}, false},                     // nothing truncated to verify
		{5, truncLosses{truncated: 11, last: 5}, false}, // cosigned up to the entry, not past it
		{0, truncLosses{truncated: 1}, false},
	} {
		if got := truncVerified(t.Context(), c.cosigned, c.l, yes); (got == "yes") != c.want {
			t.Errorf("cosigned %d, %+v: %q", c.cosigned, c.l, got)
		}
	}
	if got := truncVerified(t.Context(), 6, truncLosses{truncated: 11, last: 5}, func(context.Context) string { return "error: x" }); got == "yes" {
		t.Error("a failed verification read as verified")
	}
}

// The posts fact keeps the first start and every truncated alert, drops other tags, and is no fact at all past
// ParsePosts' cap, so a second alert can never be cut off.
func TestTruncPostsFact(t *testing.T) {
	posts := []rangevm.Post{{MS: 10, Tag: "start"}, {MS: 20, Tag: "unknown"}, {MS: 30, Tag: "truncated"}, {MS: 40, Tag: "start"},
		{MS: 50, Tag: "truncated"}}
	if got := truncPostsFact(posts); got != "10:start,30:truncated,50:truncated" {
		t.Errorf("posts %q", got)
	}
	if got := truncPostsFact(posts[1:2]); got != "none" {
		t.Errorf("no start or alert: %q", got)
	}
	var many []rangevm.Post
	for i := range 65 {
		many = append(many, rangevm.Post{MS: uint64(i), Tag: "truncated"})
	}
	if _, err := rangevm.ParsePosts(truncPostsFact(many)); err == nil || !strings.Contains(truncPostsFact(many), "over 64") {
		t.Errorf("65 alerts read as %q", truncPostsFact(many))
	}
}

// All but the last oversized exec start one every TruncationEvery from the first, the last TruncationWait after the
// one before it.
func TestTruncScheduleWaitsBeforeTheLastExec(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		starts []time.Duration
		n      int
		want   time.Duration
	}{
		{[]time.Duration{100 * s}, 11, 105 * s},
		{[]time.Duration{100 * s, 106 * s}, 11, 110 * s}, // from the first, so a late exec does not shift the rest
		{[]time.Duration{100 * s, 105 * s, 110 * s, 115 * s, 120 * s, 125 * s, 130 * s, 135 * s, 140 * s}, 11, 145 * s},
		{[]time.Duration{100 * s, 105 * s, 110 * s, 115 * s, 120 * s, 125 * s, 130 * s, 135 * s, 140 * s, 145 * s}, 11, 225 * s},
		{[]time.Duration{100 * s, 105 * s, 110 * s, 115 * s, 120 * s, 125 * s, 130 * s, 135 * s, 140 * s}, 10, 220 * s},
	} {
		if got := truncSchedule(c.starts, c.n); got != c.want {
			t.Errorf("after %d of %d execs: %s, want %s", len(c.starts), c.n, got, c.want)
		}
	}
}

// truncFake is a range whose verification can change the sink, the watcher and the clock, as piVerified does.
type truncFake struct {
	posts             []rangevm.Post
	active, restarts  string
	now               time.Duration
	sinkErr, clockErr error
}

func (f *truncFake) end(verify func(*truncFake)) truncEnd {
	return truncEnd{
		active: func() string { return f.active }, restarts: func() string { return f.restarts },
		verify: func(context.Context) string { verify(f); return "yes" },
		sink:   func() ([]rangevm.Post, int, error) { return f.posts, 0, f.sinkErr },
		clock:  func() (time.Duration, error) { return f.now, f.clockErr },
	}
}

// The end of a run is read after the verification, which stops and may restart the watcher: an alert, a restart or
// time it lets through is judged, and the watcher's state is the one before it stopped it. Its restarts are read
// before it as well, as its start of the watcher resets them.
func TestTruncEndReadsAfterTheVerification(t *testing.T) {
	tr, ok := rangejob.Lookup("truncation-10")
	if !ok {
		t.Fatal("no truncation-10")
	}
	for _, c := range []struct {
		verify          func(*truncFake)
		verdict, reason string
		pre, restarts   string
	}{
		{func(*truncFake) {}, rangevm.Pass, "no truncated alert for 10 truncated records", "0", "0"},
		{func(f *truncFake) { f.active = "inactive" }, rangevm.Pass, "no truncated alert for 10 truncated records", "0", "0"},
		{func(f *truncFake) { f.posts = append(f.posts, rangevm.Post{MS: 250000, Tag: rangevm.TruncatedTag}) }, rangevm.Miss,
			"a truncated alert at 250000 ms for 10 truncated records", "0", "0"},
		{func(f *truncFake) { f.restarts = "1" }, rangevm.Miss, "the watcher is active at the end, restarts 0 to 1", "0", "0"},
		{func(f *truncFake) { f.now = 299999 * time.Millisecond }, rangevm.Invalid,
			"the sink was read 79999 ms after the last exec, before 1m20s", "0", "0"},
		{func(f *truncFake) { f.restarts = "0" }, rangevm.Miss, "the watcher restarted before its verification, restarts 0 to 1", "0", "1"},
		{func(f *truncFake) { f.restarts = "0" }, rangevm.Invalid, "the watcher's restarts fell from 1 to 0 over its verification", "1", "1"},
		{func(*truncFake) {}, rangevm.Pass, "no truncated alert for 10 truncated records", "1", "1"},
	} {
		f := &truncFake{posts: []rangevm.Post{{MS: 60000, Tag: "start"}}, active: "active", restarts: c.restarts, now: 300 * time.Second}
		r := &report{}
		for _, kv := range [][2]string{{rangevm.FactTrial, tr.Name}, {rangevm.FactPhase, "1"}, {rangevm.FactKernel, rangevm.TargetKernel},
			{rangevm.FactTruncStartsMS, "100000,105000,110000,115000,120000,125000,130000,135000,140000,220000"},
			{rangevm.FactTruncBefore, "0"}, {rangevm.FactTruncEntries, "10"}, {rangevm.FactOtherLoss, "0"},
			{rangevm.FactRestartsPre, c.pre}, {rangevm.FactLostBefore, "0"}, {rangevm.FactLostAfter, "0"},
			{rangevm.FactOverflowBefore, "no"}, {rangevm.FactOverflowAfter, "no"}} {
			r.add(kv[0], kv[1])
		}
		if err := f.end(c.verify).add(t.Context(), r, 11, truncLosses{truncated: 10, last: 9}); err != nil {
			t.Fatal(err)
		}
		var o rangevm.Outcome
		for _, x := range r.facts {
			o.Facts = append(o.Facts, rangevm.Record{Name: x.name, Value: x.value})
		}
		build := strings.Repeat("ab", 20)
		if v, why := rangevm.JudgeTrial(tr, o, build, build); v != c.verdict || why != c.reason {
			t.Errorf("%s (%s), want %s (%s)", v, why, c.verdict, c.reason)
		}
	}
	for _, f := range []*truncFake{{sinkErr: errors.New("no posts")}, {clockErr: errors.New("no clock")}} {
		if err := f.end(func(*truncFake) {}).add(t.Context(), &report{}, 11, truncLosses{truncated: 10, last: 9}); err == nil {
			t.Errorf("%+v read as an end", f)
		}
	}
}
