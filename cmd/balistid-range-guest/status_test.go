package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// The proof brackets the CLI: checked before it runs and after it returns, and a failure of either, or a CLI that
// did not run to an exit, is the run's proof instead of "yes".
func TestMeasureBracketsTheCLI(t *testing.T) {
	var order []string
	cli := func(context.Context) (int, []byte, error) { order = append(order, "cli"); return 1, []byte("{}"), nil }
	prove := func() string { order = append(order, "prove"); return "yes" }
	res := measure(t.Context(), cli, prove, true)
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
	if res := measure(t.Context(), cli, afterFails, false); res.proof != "after: x is \"active\"" {
		t.Fatalf("after: %+v", res)
	}
	if res := measure(t.Context(), cli, func() string { return "no" }, false); res.proof != "before: no" {
		t.Fatalf("before: %+v", res)
	}
	noExit := func(context.Context) (int, []byte, error) { return 0, nil, errors.New("signal: killed") }
	if res := measure(t.Context(), noExit, func() string { return "yes" }, false); res.proof == "yes" {
		t.Fatalf("a CLI that did not exit proved the run: %+v", res)
	}
}

// The store's health over a run is its last record at or before the start and every record up to the end; records
// without a time never count.
func TestHealthTimelineOverTheRun(t *testing.T) {
	tl := healthTimeline{{kind: "health", state: "UNKNOWN starting", at: 10}, {kind: "health", state: "OK", at: 20},
		{kind: "health", state: "UNKNOWN canary-missed", at: 30}, {kind: "health", state: "OK", at: 0},
		{kind: "health", state: "UNKNOWN audit-stale", at: 35}, {kind: "health", state: "OK", at: 40}}
	for _, c := range []struct {
		start, end int64
		want       string
	}{
		{1, 5, rangevm.StoreNone}, {10, 15, rangevm.StoreUnknown}, {12, 19, rangevm.StoreUnknown},
		{21, 29, rangevm.StoreOK}, {25, 30, rangevm.StoreMixed}, {31, 36, rangevm.StoreUnknown},
		{36, 45, rangevm.StoreMixed}, {45, 50, rangevm.StoreOK}, {19, 21, rangevm.StoreMixed},
	} {
		if got := tl.over(c.start, c.end); got != c.want {
			t.Errorf("over(%d, %d) = %s, want %s", c.start, c.end, got, c.want)
		}
	}
}

// Every call that ran to an exit is kept under the run it served, and polls says the store's health over each.
func TestEveryCLICallIsKept(t *testing.T) {
	var calls []cliCall
	at := 0
	exits := []int{1, 0}
	var errs []error
	errs = append(errs, nil, nil, errors.New("killed"))
	n := 0
	cli := recorded(func(context.Context) (int, []byte, error) {
		n++
		if n == 3 {
			return 0, nil, errs[2]
		}
		return exits[n-1], nil, nil
	}, &calls, &at)
	_, _, _ = cli(t.Context())
	at = 3
	_, _, _ = cli(t.Context())
	_, _, _ = cli(t.Context())
	if len(calls) != 2 || calls[0].run != 0 || calls[0].exit != 1 || calls[1].run != 3 || calls[1].exit != 0 ||
		calls[1].start > calls[1].end || calls[0].shows != rangevm.ShowsBad {
		t.Fatalf("%+v", calls)
	}
	tl := healthTimeline{{kind: "health", state: "UNKNOWN canary-missed", at: 1}}
	calls[0].start, calls[0].end, calls[1].start, calls[1].end = 0, 5, 5, 9
	if got := tl.polls(calls); got != "0:1:bad:none,3:0:bad:UNKNOWN" {
		t.Fatalf("%q", got)
	}
}

// A wait of zero asks once and reports the floor not shown healthy, so a CLI that never shows it OK does not wait
// out the trial's wall clock before each run; the run is still measured.
func TestBreakAndRunWithoutWaitMeasuresAtOnce(t *testing.T) {
	calls := 0
	cli := func(context.Context) (int, []byte, error) { calls++; return 1, nil, nil }
	start := time.Now()
	res, healthy, err := breakAndRun(t.Context(), rangevm.StatusRun{Name: "healthy", Kind: rangevm.StatusHealthy}, cli, 0)
	if err != nil || healthy || calls != 2 || res.exit != 1 || time.Since(start) > statusPoll {
		t.Fatalf("healthy %v, %d calls, %+v, %v, %s", healthy, calls, res, err, time.Since(start))
	}
}

// A unit is stopped before it is masked, so its ExecStopPost runs, and stopped again after.
func TestStopUnitStopsBeforeMasking(t *testing.T) {
	got := stopUnit("balistid-net.service")
	want := [][]string{{"stop", "balistid-net.service"}, {"mask", "--runtime", "balistid-net.service"}, {"stop", "balistid-net.service"}}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("%q", got)
	}
}

// A timeout says which parts were not OK, so a run that never got healthy shows why.
func TestNotOKNamesTheParts(t *testing.T) {
	out := []byte(`{"schema_version":1,"ok":false,"parts":[{"part":"a","state":"OK","detail":"x"},` +
		`{"part":"health","state":"UNKNOWN","detail":"canary-missed"}]}`)
	if got := notOK(out); got != `health UNKNOWN "canary-missed"` {
		t.Fatalf("%q", got)
	}
	if got := notOK([]byte("{")); got != "unreadable output" {
		t.Fatalf("%q", got)
	}
}

// untilCLI returns at the first wanted exit and fails on a cancelled context rather than waiting out statusWait.
func TestUntilCLIStopsAtTheWantedExit(t *testing.T) {
	n := 0
	cli := func(context.Context) (int, []byte, error) {
		n++
		return map[bool]int{true: 0, false: 1}[n == 2], nil, nil
	}
	if err := untilCLI(t.Context(), cli, 0, statusWait); err != nil || n != 2 {
		t.Fatalf("%d calls, %v", n, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := untilCLI(ctx, func(context.Context) (int, []byte, error) { return 1, nil, nil }, 0, statusWait); err == nil {
		t.Fatal("waited on a cancelled context")
	}
}
