package main

import (
	"testing"
	"time"
)

// TestBrokenRunsInTimeOrder: RFC 3339 drops trailing zeros, so 10:00:00.5Z sorts before 10:00:00Z as text; the
// list is in the order of the times.
func TestBrokenRunsInTimeOrder(t *testing.T) {
	at := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	later := at.Add(time.Second / 2)
	runs := []execRun{
		{Schema: 1, Received: timeText(later.UnixNano()), receivedAt: later, Serial: 2, Name: "later"},
		{Schema: 1, Received: timeText(at.UnixNano()), receivedAt: at, Serial: 1, Name: "first"},
	}
	_, _, b := overAll(runs, []string{broken, broken})
	if b.Total != 2 || b.Shown != 2 || b.Runs[0].Name != "first" {
		t.Errorf("broken runs %+v", b)
	}
}
