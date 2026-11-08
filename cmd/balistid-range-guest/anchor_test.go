package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/entry"
)

// Only batch entries count, only those stamped in the window, and the window's ends bound the first and last gap,
// rounded up to the ms: an idle stretch at either end is a gap, never fewer batches (ADR 0069, point 1).
func TestAnchorGapsCountBatchesInTheWindow(t *testing.T) {
	health := func(l *anchor.Log) {
		if err := l.Health(t.Context(), entry.Health{State: entry.StateOK}); err != nil {
			t.Fatal(err)
		}
	}
	before := time.Now().UnixNano()
	root, v := writeLog(t, 6, health, health) // batches 1-3 and 4-6, then two health entries
	after := time.Now().UnixNano()
	gap, batches := anchorGapsIn(t.Context(), root, v, before, after)
	if batches != "2" || gap == "" || strings.HasPrefix(gap, "error") {
		t.Errorf("whole log: gap %q, batches %q; want 2 batches", gap, batches)
	}
	for _, c := range []struct {
		from, to     int64
		gap, batches string
	}{
		{after, after + 5*time.Second.Nanoseconds(), "5000", "0"},  // after the log: one gap, no batch
		{after, after + 1, "1", "0"},                               // a nanosecond is a whole ms
		{before - time.Hour.Nanoseconds(), before, "3600000", "0"}, // before the log
	} {
		if g, b := anchorGapsIn(t.Context(), root, v, c.from, c.to); g != c.gap || b != c.batches {
			t.Errorf("window %d to %d: gap %q, batches %q; want %q, %q", c.from, c.to, g, b, c.gap, c.batches)
		}
	}
	_, other := writeLog(t, 1)
	if g, b := anchorGapsIn(t.Context(), root, other, before, after); !strings.HasPrefix(g, "error") || !strings.HasPrefix(b, "error") {
		t.Errorf("another key: gap %q, batches %q", g, b)
	}
}
