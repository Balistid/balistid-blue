package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/auditstat"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// A host line is one line of printable ASCII after the marker, at most hostLineMax bytes: a record's bytes or a
// journal's escape codes can neither end it nor put a line of their own in the host's log.
func TestHostLineIsOnePrintableLine(t *testing.T) {
	var out strings.Builder
	hostLine(&out, "a%sb", "\n::error::x\x1b[2Jé")
	hostLine(&out, "%s", strings.Repeat("y", 2*hostLineMax))
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 || lines[0] != hostPrefix+"a?::error::x?[2J??b" || lines[1] != hostPrefix+strings.Repeat("y", hostLineMax) {
		t.Errorf("host lines %q", lines)
	}
}

// A counted loss record shows what was lost and when, the store's and the collector's alike; a body that does not
// decode shows that.
func TestLossLineShowsWhatWasLost(t *testing.T) {
	for _, c := range []struct {
		x    rawrecord.Record
		want string
	}{
		{rawrecord.New(7, store.LossProvider, 0, 1, []byte(`{"schema_version":1,"dropped":12,"first_received":5,"last_received":9}`)),
			`loss record seq 7 balistid-loss kind="" stage="" count=0 dropped=12 at=0..0 received=5..9 decoded=true`},
		{rawrecord.New(8, store.HealthProvider, 0, 1, []byte(`{"schema_version":1,"kind":"lost","stage":"queue","count":3,"first_at":4,"last_at":6}`)),
			`loss record seq 8 balistid-health kind="lost" stage="queue" count=3 dropped=0 at=4..6 received=0..0 decoded=true`},
		{rawrecord.New(9, store.HealthProvider, 0, 1, []byte(`{"kind":"lost","stage":"é\n"`)),
			`loss record seq 9 balistid-health kind="" stage="" count=0 dropped=0 at=0..0 received=0..0 decoded=false`},
	} {
		if got := lossLine(c.x); got != c.want {
			t.Errorf("loss line %q\nwant       %q", got, c.want)
		}
	}
}

// A read shows at most lossLinesMax loss records in the host's log and then how many it counted: thousands would
// spend the serial budget and end the run without facts.
func TestLossLogShowsTheFirstAndACount(t *testing.T) {
	var out strings.Builder
	log := &lossLog{w: &out}
	for i := range lossLinesMax + 5 {
		log.add(rawrecord.New(uint64(i+1), store.LossProvider, 0, 1, []byte(`{"dropped":1}`)))
	}
	log.done()
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != lossLinesMax+1 || !strings.HasPrefix(lines[0], hostPrefix+"loss record seq 1 ") ||
		lines[lossLinesMax] != hostPrefix+"25 loss records counted, the first 20 shown" {
		t.Errorf("%d lines, first %q, last %q", len(lines), lines[0], lines[len(lines)-1])
	}
	out.Reset()
	few := &lossLog{w: &out}
	few.add(rawrecord.New(1, store.LossProvider, 0, 1, []byte(`{}`)))
	few.done()
	if strings.Count(out.String(), "\n") != 1 || strings.Contains(out.String(), "counted") {
		t.Errorf("one loss record: %q", out.String())
	}
}

// After the read's wait for an idle audit, also a failed one, after runs; the wait runs without one too.
func TestIdleThenRunsAfterTheWait(t *testing.T) {
	var steps []string
	wait := func(context.Context) error { steps = append(steps, "wait"); return errors.New("not idle") }
	err := idleThen(wait, func() { steps = append(steps, "after") })(t.Context())
	if err == nil || strings.Join(steps, ",") != "wait,after" {
		t.Errorf("%v, steps %v", err, steps)
	}
	if err := idleThen(func(context.Context) error { return nil }, nil)(t.Context()); err != nil {
		t.Error(err)
	}
}

// The backlog counts only from a report of a poll after the wait began: an older one is stale, an unreadable one
// says why.
func TestBacklogAfterTakesOnlyALaterReport(t *testing.T) {
	reports := []auditstat.Report{{Seq: 7, Status: auditstat.Status{Backlog: 3}}, {Seq: 8, Status: auditstat.Status{Backlog: 0}}}
	i := 0
	backlog := backlogAfter(7, true, func() (auditstat.Report, error) {
		if i == len(reports) {
			return auditstat.Report{}, errors.New("auditstat: a report of the wrong size")
		}
		i++
		return reports[i-1], nil
	})
	for _, want := range []string{"stale", "0", "auditstat: a report of the wrong size"} {
		if got := backlog(t.Context()); got != want {
			t.Errorf("backlog %q, want %q", got, want)
		}
	}
}

// The drain's parts are the ticks between each two reads, each its own: the store read's wait for an idle audit
// and the rest of the read; a read missing, as when the wait never ran, fails them.
func TestDrainPartsKeepEachInterval(t *testing.T) {
	stat := func(user, steal int) string { return fmt.Sprintf("cpu  %d 0 0 0 0 0 0 %d 0 0\n", user, steal) }
	loaded, idleTo, after := stat(1000, 10), stat(1100, 12), stat(11100, 12)
	c0, s0, _ := rangeguest.TickDelta(loaded, idleTo)
	c1, s1, _ := rangeguest.TickDelta(idleTo, after)
	if got, err := drainParts(loaded, idleTo, after); err != nil || got != fmt.Sprintf("%d:%d;%d:%d", c0, s0, c1, s1) {
		t.Errorf("parts %q, %v", got, err)
	}
	if _, err := drainParts(loaded, "", after); err == nil {
		t.Error("a drain without the wait's end counted")
	}
}

// Without a report when the wait began, as right after boot, the wait keeps polling: the missing report is no
// backlog, and the first report that appears is of a poll since and counts.
func TestBacklogWaitsForAFirstReport(t *testing.T) {
	missing := errors.New("auditstat: report: no such file")
	reads := []func() (auditstat.Report, error){
		func() (auditstat.Report, error) { return auditstat.Report{}, missing },
		func() (auditstat.Report, error) {
			return auditstat.Report{Seq: 1, Status: auditstat.Status{Backlog: 4}}, nil
		},
		func() (auditstat.Report, error) { return auditstat.Report{Seq: 2}, nil },
	}
	i := 0
	backlog := backlogAfter(0, false, func() (auditstat.Report, error) { i++; return reads[min(i-1, len(reads)-1)]() })
	for _, want := range []string{missing.Error(), "4", "0"} {
		if got := backlog(t.Context()); got != want {
			t.Errorf("backlog %q, want %q", got, want)
		}
	}
}
