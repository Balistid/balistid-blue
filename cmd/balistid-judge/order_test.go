package main

import (
	"testing"
	"time"
)

// TestBrokenRunsInTimeOrder: RFC 3339 drops trailing zeros, so 10:00:00.5Z sorts before 10:00:00Z as text; the
// list is in the order of the times.
func TestBrokenRunsInTimeOrder(t *testing.T) {
	at := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC).UnixNano()
	runs := []execRun{
		{Schema: 1, Time: timeText(at + int64(time.Second/2)), Serial: 2, Name: "later"},
		{Schema: 1, Time: timeText(at), Serial: 1, Name: "first"},
	}
	c := cleanView(cleanDoc{State: "KNOWN", Intervals: []interval{{From: timeText(at), To: timeText(at + int64(time.Second))}}},
		runs, []string{broken, broken})
	if len(c.BrokenRuns) != 2 || c.BrokenRuns[0].Name != "first" {
		t.Errorf("broken runs %+v", c.BrokenRuns)
	}
}
