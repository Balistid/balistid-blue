package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

// The dispatcher's bracket is the guest's own uptime: a new generation's lower bound is the read before the last
// one that still saw the generation before it, a changing file tells nothing, and the first read sets the start.
func TestStateWatchBracketsByItsOwnReads(t *testing.T) {
	gen := func(sec int64, value string) stateRead { return stateRead{value: value, mtime: time.Unix(sec, 0)} }
	reads := []stateRead{gen(10, "no"), gen(10, "no"), {value: stateChanged}, gen(15, "no"), gen(15, "no"), gen(20, "yes")}
	clock := time.Duration(0)
	w := stateWatch{
		read: func() (stateRead, error) { r := reads[0]; reads = reads[1:]; return r, nil },
		now:  func() (time.Duration, error) { clock += time.Second; return clock, nil },
	}
	type step struct {
		fresh       bool
		prev, after time.Duration
	}
	want := []step{{false, 0, 2 * time.Second}, {false, 0, 4 * time.Second}, {false, 0, 6 * time.Second},
		{true, 3 * time.Second, 8 * time.Second}, {false, 0, 10 * time.Second}, {true, 9 * time.Second, 12 * time.Second}}
	for i, w0 := range want {
		fresh, prev, after, err := w.poll()
		if err != nil || fresh != w0.fresh || (fresh && prev != w0.prev) || after != w0.after {
			t.Fatalf("read %d: fresh %v prev %s after %s %v, want %+v", i, fresh, prev, after, err, w0)
		}
	}
	if w.cur.value != "yes" {
		t.Errorf("current %+v", w.cur)
	}
}

// kmsgPair is a kmsgReader over one end of a SEQPACKET socket pair, which keeps records apart as /dev/kmsg does,
// with record already waiting on it.
func kmsgPair(t *testing.T, record string) *kmsgReader {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })
	if _, err := unix.Write(fds[1], []byte(record)); err != nil {
		t.Fatal(err)
	}
	return &kmsgReader{fd: fds[0], buf: make([]byte, 8192)}
}

// A scan whose context ended reads no record, and awaitMark then fails at once though the mark is waiting.
func TestKmsgReadsStopWithTheirContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	k := kmsgPair(t, "12,7,1000,-;"+kmsgMarkPrefix+"after")
	m := &kmsgMark{tag: "after"}
	k.marks = append(k.marks, m)
	if at, _, err := k.scan(ctx, 0, m); at != 0 || err != nil || m.seen {
		t.Fatalf("a cancelled scan read on: %s %v, mark seen %v", at, err, m.seen)
	}
	start := time.Now()
	if err := k.awaitMark(ctx, m); err == nil || m.seen || time.Since(start) > 100*time.Millisecond {
		t.Errorf("awaitMark with an ended context: %v, seen %v, after %s", err, m.seen, time.Since(start))
	}
	if _, _, err := k.scan(t.Context(), 0, m); err != nil || !m.seen || m.at != time.Millisecond {
		t.Errorf("a live scan: %v, mark %+v", err, m)
	}
}
