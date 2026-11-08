package main

import (
	"context"
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

// truncEvery spaces a truncation trial's oversized execs: 2 MB records at 2 execs/s overflowed auditd's dispatcher
// (ADR 0054), and at one every 5 s Laurel is idle between them.
const truncEvery = 5 * time.Second

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
// it runs tr's oversized execs one every truncEvery, waits TruncationWait after the last and reports the ledger's
// loss entries since the first, the truncated alerts at the sink and whether the watcher verified the last entry.
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
	n, first, last, err := truncExecs(ctx, rangejob.TruncatedExecs(tr.Inject), tok)
	if err != nil {
		return r.fail(err.Error())
	}
	if !waitUptime(ctx, last+rangevm.TruncationWait) {
		return r.fail("the wait after the last exec ended early")
	}
	end, err := uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	stopLoad()
	after, err := ledgerLossesIn(ctx, ledgerLog, keys.Log, before.size)
	if err != nil {
		return r.fail(err.Error())
	}
	posts, refused, err := readSink()
	if err != nil {
		return r.fail(err.Error())
	}
	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	r.add(rangevm.FactTruncExecs, strconv.Itoa(n))
	r.add(rangevm.FactTruncFirstMS, ms(first))
	r.add(rangevm.FactTruncLastMS, ms(last))
	r.add(rangevm.FactTruncEndMS, ms(end))
	r.add(rangevm.FactTruncBefore, strconv.Itoa(before.truncated))
	r.add(rangevm.FactTruncEntries, strconv.Itoa(after.truncated))
	r.add(rangevm.FactOtherLoss, strconv.Itoa(after.other))
	r.add(rangevm.FactPosts, truncPostsFact(posts))
	r.add(rangevm.FactRefused, strconv.Itoa(refused))
	r.add(rangevm.FactPiActive, valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", piUnit))))
	r.add(rangevm.FactRestartsPre, restartsBefore)
	r.add(rangevm.FactRestartsPost, restarts())
	r.add(rangevm.FactPiVerified, truncVerified(ctx, cw.cosignedSize(), after, piVerified))
	r.add(rangevm.FactLostBefore, lostBefore)
	r.add(rangevm.FactLostAfter, auditLost())
	r.add(rangevm.FactOverflowBefore, overflowBefore)
	r.add(rangevm.FactOverflowAfter, stateLine(ctx, rangeguest.StateOverflow))
	return r.send(r.facts)
}

// truncExecs runs n oversized execs one every truncEvery and returns how many ran and the uptime at the start of the
// first and the last.
func truncExecs(ctx context.Context, n int, tok string) (ran int, first, last time.Duration, err error) {
	for i := range n {
		if i > 0 && !pause(ctx, truncEvery) {
			return ran, first, last, fmt.Errorf("after %d oversized execs: %w", ran, ctx.Err())
		}
		if last, err = uptime(); err != nil {
			return ran, first, last, err
		}
		if i == 0 {
			first = last
		}
		if err := execArgv(ctx, argvTruncated, tok); err != nil {
			return ran, first, last, err
		}
		ran++
	}
	if ran == 0 {
		return 0, 0, 0, fmt.Errorf("no oversized exec for %d", n)
	}
	return ran, first, last, nil
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
