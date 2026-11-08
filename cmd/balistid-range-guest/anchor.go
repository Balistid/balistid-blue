package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// stallFor is how long the anchor control keeps the ledger stopped (ADR 0069, point 2).
const stallFor = 2 * time.Second

// runAnchor runs anchor trial tr (ADR 0069): rate trial tr's load and facts, beside it the control's stall of the
// ledger in the load's middle, then, a checkpoint later, the gaps between the ledger's batch entries over the load.
func runAnchor(ctx context.Context, tr rangejob.Trial, r *report) error {
	var during func(context.Context) error
	if tr.Inject == rangejob.InjectLedgerStall {
		during = func(ctx context.Context) error { return stallLedger(ctx, time.Duration(tr.Load.Seconds)*time.Second/2) }
	}
	from, to, why := rateLoad(ctx, tr, r, during)
	if why != "" {
		return r.fail(why)
	}
	if !pause(ctx, checkpointWait) {
		return r.fail("checkpoint wait: " + ctx.Err().Error())
	}
	gap, batches := anchorGaps(ctx, from, to)
	r.add(rangevm.FactAnchorGapMS, gap)
	r.add(rangevm.FactAnchorBatches, batches)
	return r.send(r.facts)
}

// anchorGaps is anchorGapsIn for the ledger's log.
func anchorGaps(ctx context.Context, from, to int64) (gap, batches string) {
	keys, err := rangeKeys()
	if err != nil {
		return "error: " + err.Error(), "error: " + err.Error()
	}
	return anchorGapsIn(ctx, ledgerLog, keys.Log, from, to)
}

// anchorGapsIn is the longest time in ms, rounded up, without a batch entry from from to to (ns, the entries'
// clock) and how many were stamped in between, in the log at root under v; both "error: ..." when it is unreadable.
func anchorGapsIn(ctx context.Context, root string, v note.Verifier, from, to int64) (gap, batches string) {
	var at []int64
	_, err := eachEntry(ctx, root, v, func(_ uint64, e entry.Entry) {
		if _, ok := e.Body.(entry.Batch); ok {
			at = append(at, e.At)
		}
	})
	if err != nil {
		return "error: " + err.Error(), "error: " + err.Error()
	}
	return batchGaps(at, from, to)
}

// batchGaps is anchorGapsIn's result for the batch stamps at in log order. A stamp before the previous one where
// the step back touches the window is an error: stampGaps, which takes them sorted, would see a shorter gap.
func batchGaps(at []int64, from, to int64) (gap, batches string) {
	for i := 1; i < len(at); i++ {
		if at[i] < at[i-1] && at[i-1] >= from && at[i] <= to {
			return "error: stamp before the previous one", "error: stamp before the previous one"
		}
	}
	n, longest := stampGaps(at, from, to)
	ms := (longest + int64(time.Millisecond) - 1) / int64(time.Millisecond)
	return strconv.FormatInt(ms, 10), strconv.Itoa(n)
}

// stallLedger waits after, stops the ledger by SIGSTOP for stallFor and proves it stopped a second in and right
// before SIGCONT, which goes out also when ctx ends.
func stallLedger(ctx context.Context, after time.Duration) error {
	if !pause(ctx, after) {
		return fmt.Errorf("before the stall: %w", ctx.Err())
	}
	pid, err := strconv.Atoi(mainPID(ctx, ledgerUnit))
	if err != nil {
		return fmt.Errorf("no ledger process: %w", err)
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP %d: %w", pid, err)
	}
	held := pause(ctx, time.Second) // the signal stops the process when it is next scheduled
	first := processStopped(pid)
	held = held && pause(ctx, stallFor-time.Second)
	last := processStopped(pid)
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT %d: %w", pid, err)
	}
	switch {
	case !held:
		return errors.Join(errors.New("the stall ended early"), ctx.Err())
	case first != "yes":
		return fmt.Errorf("the ledger a second after SIGSTOP: %s", first)
	case last != "yes":
		return fmt.Errorf("the ledger before SIGCONT: %s", last)
	}
	return nil
}
