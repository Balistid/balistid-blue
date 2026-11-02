package main

import (
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
)

// The rise is the first record counting lost above base after the first mark, exact when it counts base+1; one
// before the mark is refused, and other records only stamp marks (ADR 0045).
func TestTakeRecordFindsTheFirstLost(t *testing.T) {
	rec := func(at time.Duration, msg string) rangeguest.KmsgRecord {
		return rangeguest.KmsgRecord{At: at, Msg: msg}
	}
	first := &kmsgMark{tag: "before"}
	marks := []*kmsgMark{first}
	if rise, _, err := takeRecord(rec(5*time.Second, "audit: audit_lost=3 audit_rate_limit=0"), marks, 2, first); err == nil {
		t.Fatalf("a lost line before the mark taken as the rise at %s", rise)
	}
	for _, r := range []rangeguest.KmsgRecord{rec(6*time.Second, kmsgMarkPrefix+"before"), rec(7*time.Second, "audit: backlog limit exceeded"),
		rec(8*time.Second, "audit: audit_lost=2 x")} {
		if rise, _, err := takeRecord(r, marks, 2, first); rise != 0 || err != nil {
			t.Fatalf("%q: %s %v", r.Msg, rise, err)
		}
	}
	if !first.seen || first.at != 6*time.Second {
		t.Fatalf("mark %+v", first)
	}
	if rise, exact, err := takeRecord(rec(70*time.Second, "audit: audit_lost=3 x"), marks, 2, first); rise != 70*time.Second || !exact || err != nil {
		t.Errorf("rise %s %v %v", rise, exact, err)
	}
	if rise, exact, err := takeRecord(rec(70*time.Second, "audit: audit_lost=131112 x"), marks, 2, first); rise != 70*time.Second || exact || err != nil {
		t.Errorf("a later count: %s %v %v, want its time, not exact", rise, exact, err)
	}
}

// Each mark bounds the offset between the kernel's clock and uptime by its write; the bracket is the widest
// either allows, and an unread mark or a bracket outside uptime is an error.
func TestKernelBracket(t *testing.T) {
	ms := time.Millisecond
	a := &kmsgMark{tag: "before", before: 1000 * ms, after: 1010 * ms, at: 990 * ms, seen: true}    // offset 10..20 ms
	b := &kmsgMark{tag: "after", before: 70000 * ms, after: 70020 * ms, at: 69995 * ms, seen: true} // offset 5..25 ms
	from, to, err := kernelBracket(60000*ms, a, b)
	if err != nil || from != 60005*ms || to != 60025*ms {
		t.Errorf("bracket %s..%s %v", from, to, err)
	}
	if _, _, err := kernelBracket(60000*ms, a, &kmsgMark{tag: "after"}); err == nil {
		t.Error("an unread mark gave a bracket")
	}
	if _, _, err := kernelBracket(ms, &kmsgMark{tag: "x", before: 0, after: ms, at: 10 * ms, seen: true}); err == nil {
		t.Error("a bracket before boot")
	}
}

// The dispatcher's bracket maps wall-clock mtimes to uptime with the offsets seen during the injection: its start
// with the largest, its end with the least, and a spread over clockSpread fails it.
func TestStateBracketOnlyWidens(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	o := offsets{lo: time.Duration(base.UnixNano()) - 100*time.Second, hi: time.Duration(base.UnixNano()) - 99*time.Second}
	from, to, err := o.bracket(base.Add(5*time.Second), base.Add(10*time.Second))
	if err != nil || from != 104*time.Second || to != 110*time.Second {
		t.Errorf("bracket %s..%s %v", from, to, err)
	}
	o.lo -= time.Millisecond
	if _, _, err := o.bracket(base.Add(5*time.Second), base.Add(10*time.Second)); err == nil {
		t.Error("a clock spread over clockSpread gave a bracket")
	}
	var fresh offsets
	if err := fresh.read(); err != nil || fresh.lo != fresh.hi || fresh.lo <= 0 {
		t.Errorf("first read %+v %v", fresh, err)
	}
}
