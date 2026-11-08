package main

import (
	"context"
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
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
