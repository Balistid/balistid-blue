package main

import (
	"context"
	"errors"
	"testing"
)

// The proof brackets the CLI: checked before it runs and after it returns, and a failure of either, or a CLI that
// did not run to an exit, is the run's proof instead of "yes".
func TestMeasureBracketsTheCLI(t *testing.T) {
	var order []string
	cli := func(context.Context) (int, []byte, error) { order = append(order, "cli"); return 1, []byte("{}"), nil }
	prove := func() string { order = append(order, "prove"); return "yes" }
	res := measure(t.Context(), cli, prove, "UNKNOWN")
	if len(order) != 3 || order[0] != "prove" || order[1] != "cli" || order[2] != "prove" || res.proof != "yes" || res.exit != 1 {
		t.Fatalf("order %v, %+v", order, res)
	}
	calls := 0
	afterFails := func() string {
		calls++
		if calls == 2 {
			return "x is \"active\""
		}
		return "yes"
	}
	if res := measure(t.Context(), cli, afterFails, ""); res.proof != "after: x is \"active\"" {
		t.Fatalf("after: %+v", res)
	}
	if res := measure(t.Context(), cli, func() string { return "no" }, ""); res.proof != "before: no" {
		t.Fatalf("before: %+v", res)
	}
	noExit := func(context.Context) (int, []byte, error) { return 0, nil, errors.New("signal: killed") }
	if res := measure(t.Context(), noExit, func() string { return "yes" }, ""); res.proof == "yes" {
		t.Fatalf("a CLI that did not exit proved the run: %+v", res)
	}
}

// The store's health at a run's end is its last record at or before the end; records without a time never count.
func TestHealthTimelineProvesTheStateAtTheEnd(t *testing.T) {
	tl := healthTimeline{{kind: "health", state: "UNKNOWN starting", at: 10}, {kind: "health", state: "OK", at: 20},
		{kind: "health", state: "UNKNOWN canary-missed", at: 30}, {kind: "health", state: "OK", at: 0}, {kind: "health", state: "OK", at: 40}}
	for _, c := range []struct {
		end        int64
		want, does string
	}{
		{5, "OK", "no health stored before the run"}, {10, "UNKNOWN", "yes"}, {19, "OK", `the store's health was "UNKNOWN starting"`},
		{25, "OK", "yes"}, {30, "UNKNOWN", "yes"}, {35, "OK", `the store's health was "UNKNOWN canary-missed"`},
		{45, "OK", "yes"}, {45, "UNKNOWN", `the store's health was "OK"`},
	} {
		if got := tl.proves(c.end, c.want); got != c.does {
			t.Errorf("end %d want %s: %q, want %q", c.end, c.want, got, c.does)
		}
	}
}

// untilCLI returns at the first wanted exit and fails on a cancelled context rather than waiting out statusWait.
func TestUntilCLIStopsAtTheWantedExit(t *testing.T) {
	n := 0
	cli := func(context.Context) (int, []byte, error) {
		n++
		return map[bool]int{true: 0, false: 1}[n == 2], nil, nil
	}
	if err := untilCLI(t.Context(), cli, 0); err != nil || n != 2 {
		t.Fatalf("%d calls, %v", n, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := untilCLI(ctx, func(context.Context) (int, []byte, error) { return 1, nil, nil }, 0); err == nil {
		t.Fatal("waited on a cancelled context")
	}
}
