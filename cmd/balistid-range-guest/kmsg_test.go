package main

import (
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
)

// The rise is the record counting lost base+1 after the first mark; one before the mark, or a higher count
// first, is refused, and other records only stamp marks (ADR 0045).
func TestTakeRecordFindsTheFirstLost(t *testing.T) {
	rec := func(at time.Duration, msg string) rangeguest.KmsgRecord {
		return rangeguest.KmsgRecord{At: at, Msg: msg}
	}
	first := &kmsgMark{tag: "before"}
	marks := []*kmsgMark{first}
	if rise, err := takeRecord(rec(5*time.Second, "audit: audit_lost=3 audit_rate_limit=0"), marks, 2, first); err == nil {
		t.Fatalf("a lost line before the mark taken as the rise at %s", rise)
	}
	for _, r := range []rangeguest.KmsgRecord{rec(6*time.Second, kmsgMarkPrefix+"before"), rec(7*time.Second, "audit: backlog limit exceeded"),
		rec(8*time.Second, "audit: audit_lost=2 x")} {
		if rise, err := takeRecord(r, marks, 2, first); rise != 0 || err != nil {
			t.Fatalf("%q: %s %v", r.Msg, rise, err)
		}
	}
	if !first.seen || first.at != 6*time.Second {
		t.Fatalf("mark %+v", first)
	}
	if rise, err := takeRecord(rec(70*time.Second, "audit: audit_lost=3 x"), marks, 2, first); rise != 70*time.Second || err != nil {
		t.Errorf("rise %s %v", rise, err)
	}
	if rise, err := takeRecord(rec(70*time.Second, "audit: audit_lost=4 x"), marks, 2, first); err == nil {
		t.Errorf("a skipped count taken as the rise at %s", rise)
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
