package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// argvTruncated is 17 arguments of 125000 B, 2 125 000 B: over record_max_kib's 2 MiB, so stored truncated, and over
// ARG_MAX at the default stack, so it runs under the large one (ADR 0069, point 3).
var argvTruncated = argvCase{"truncation", 17, 125000, largeStack, 2_097_152}

// truncLosses counts the loss entries of a log from an index on: the truncated ones, the index of the last, and
// those of every other stage; size is the log's size under its checkpoint.
type truncLosses struct {
	truncated, other int
	last, size       uint64
}

// runTruncation runs truncation trial tr (ADR 0069): with the watcher started through the sink and the log growing,
// it runs tr's oversized execs (truncSchedule), waits TruncationWait after the last and reports the ledger's loss
// entries since the first, the truncated alerts at the sink and whether the watcher verified the last entry.
func runTruncation(ctx context.Context, tr rangejob.Trial, r *report) error {
	keys, err := rangeKeys()
	if err != nil {
		return r.fail(err.Error())
	}
	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	var cw cosignWatch
	go cw.run(wctx, keys)
	lctx, stopLoad := context.WithCancel(ctx)
	defer stopLoad()
	go lightLoad(lctx)
	if why := alarmReady(ctx, &cw); why != "" {
		return r.fail(why)
	}
	tok, err := token("balistid-truncation")
	if err != nil {
		return r.fail(err.Error())
	}
	before, err := ledgerLossesIn(ctx, ledgerLog, keys.Log, 0)
	if err != nil {
		return r.fail(err.Error())
	}
	auditLost := func() string { return valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"]) }
	restarts := func() string {
		return valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "NRestarts", piUnit)))
	}
	lostBefore, overflowBefore, restartsBefore := auditLost(), stateLine(ctx, rangeguest.StateOverflow), restarts()
	starts, err := truncExecs(ctx, rangejob.TruncatedExecs(tr.Inject), tok)
	if err != nil {
		return r.fail(err.Error())
	}
	last := starts[len(starts)-1]
	if !waitUptime(ctx, last+rangevm.TruncationWait) {
		return r.fail("the wait after the last exec ended early")
	}
	stopLoad()
	after, err := ledgerLossesIn(ctx, ledgerLog, keys.Log, before.size)
	if err != nil {
		return r.fail(err.Error())
	}
	each := make([]string, len(starts))
	for i, at := range starts {
		each[i] = ms(at)
	}
	r.add(rangevm.FactTruncStartsMS, strings.Join(each, ","))
	r.add(rangevm.FactTruncBefore, strconv.Itoa(before.truncated))
	r.add(rangevm.FactTruncEntries, strconv.Itoa(after.truncated))
	r.add(rangevm.FactOtherLoss, strconv.Itoa(after.other))
	r.add(rangevm.FactRestartsPre, restartsBefore)
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, auditLost())
	r.add(rangevm.FactOverflowBefore, overflowBefore)
	r.add(rangevm.FactOverflowAfter, stateLine(ctx, rangeguest.StateOverflow))
	end := truncEnd{
		active: func() string {
			return valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", piUnit)))
		},
		verify: piVerified, sink: readSink, restarts: restarts, clock: uptime,
	}
	if err := end.add(ctx, r, cw.cosignedSize(), after); err != nil {
		return r.fail(err.Error())
	}
	return r.send(r.facts)
}

// truncEnd reads the end of a truncation run through its fields, the range's watcher, sink and clock.
type truncEnd struct {
	active, restarts func() string
	verify           func(context.Context) string
	sink             func() ([]rangevm.Post, int, error)
	clock            func() (time.Duration, error)
}

// add adds the watcher's state and restarts, then whether it verified the log cosigned past the last truncated entry,
// then the sink's posts and refusals, the watcher's restarts and the end time: verify waits, stops and may restart
// the watcher, which resets its restarts, and what it lets through must be judged.
func (e truncEnd) add(ctx context.Context, r *report, cosigned uint64, after truncLosses) error {
	r.add(rangevm.FactPiActive, e.active())
	r.add(rangevm.FactRestartsVerify, e.restarts())
	r.add(rangevm.FactPiVerified, truncVerified(ctx, cosigned, after, e.verify))
	posts, refused, err := e.sink()
	if err != nil {
		return err
	}
	r.add(rangevm.FactPosts, truncPostsFact(posts))
	r.add(rangevm.FactRefused, strconv.Itoa(refused))
	r.add(rangevm.FactRestartsPost, e.restarts())
	end, err := e.clock()
	if err != nil {
		return err
	}
	r.add(rangevm.FactTruncEndMS, ms(end))
	return nil
}

// truncExecs runs n oversized execs at the uptimes truncSchedule gives and returns when each started.
func truncExecs(ctx context.Context, n int, tok string) ([]time.Duration, error) {
	var starts []time.Duration
	for i := range n {
		if i > 0 && !waitUptime(ctx, truncSchedule(starts, n)) {
			return nil, errors.Join(fmt.Errorf("the wait after %d oversized execs ended early", i), ctx.Err())
		}
		at, err := uptime()
		if err != nil {
			return nil, err
		}
		if err := execArgv(ctx, argvTruncated, tok); err != nil {
			return nil, err
		}
		starts = append(starts, at)
	}
	if len(starts) == 0 {
		return nil, fmt.Errorf("no oversized exec for %d", n)
	}
	return starts, nil
}

// truncSchedule is the uptime of the next of n oversized execs after those that started at starts: all but the last
// one every TruncationEvery from the first, the last TruncationWait after the one before, so an alert the others
// raised has reached the sink before it starts (ADR 0069, point 3).
func truncSchedule(starts []time.Duration, n int) time.Duration {
	if len(starts) == n-1 {
		return starts[len(starts)-1] + rangevm.TruncationWait
	}
	return starts[0] + time.Duration(len(starts))*rangevm.TruncationEvery
}

// ledgerLossesIn counts the loss entries of the log at root under v from index from on.
func ledgerLossesIn(ctx context.Context, root string, v note.Verifier, from uint64) (truncLosses, error) {
	var l truncLosses
	size, err := eachEntry(ctx, root, v, func(i uint64, e entry.Entry) {
		loss, ok := e.Body.(entry.Loss)
		switch {
		case !ok || i < from:
		case loss.Stage == entry.StageTruncated:
			l.truncated, l.last = l.truncated+1, i
		default:
			l.other++
		}
	})
	l.size = size
	return l, err
}

// truncVerified is "yes" once the witness cosigned past the last truncated entry and the watcher verified the log up
// to what it cosigned (verify, piVerified in the range, which stops the watcher), else why not.
func truncVerified(ctx context.Context, cosigned uint64, l truncLosses, verify func(context.Context) string) string {
	switch {
	case l.truncated == 0:
		return "no truncated entry to verify"
	case cosigned <= l.last:
		return fmt.Sprintf("the witness cosigned %d entries, the last truncated is entry %d", cosigned, l.last)
	}
	return verify(ctx)
}

// truncPostsFact keeps the sink's first start and every truncated alert, at most ParsePosts' 64; more is no posts
// fact, so a second alert is never cut off.
func truncPostsFact(posts []rangevm.Post) string {
	var keep []string
	started := false
	for _, p := range posts {
		if p.Tag == "start" && !started || p.Tag == rangevm.TruncatedTag {
			keep = append(keep, rangevm.FormatPost(p))
		}
		started = started || p.Tag == "start"
	}
	switch {
	case len(keep) == 0:
		return "none"
	case len(keep) > 64:
		return fmt.Sprintf("%d posts, over 64", len(keep))
	}
	return strings.Join(keep, ",")
}
