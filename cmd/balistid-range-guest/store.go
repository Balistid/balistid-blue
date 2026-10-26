package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const collectorUnitName = "balistid-collector.service"

// collectorCanaryKey is collector.CanaryKey, the rule key of the collector's canary (ADR 0017, point 2);
// a test keeps them equal without linking the collector into the guest.
const collectorCanaryKey = "balistid-canary"

// collectorUnit is the collector as the guest reads its commit line from the journal and stops it.
type collectorUnit struct{}

// Follow runs one journalctl that follows the collector's journal from now on and sends the seq of
// each commit line; the channel closes once ctx ended and journalctl exited.
func (collectorUnit) Follow(ctx context.Context) (<-chan uint64, error) {
	return followCommits(exec.CommandContext(ctx, "/usr/bin/journalctl", "-f", "-n", "0", "-q", "--no-pager", "-o", "cat", "-u", collectorUnitName))
}

// followCommits starts cmd, a journal follower, and sends the seq of each commit line it prints; the
// channel closes once cmd exited, at once when a line is too long to scan.
func followCommits(cmd *exec.Cmd) (<-chan uint64, error) {
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("journalctl: %w", err)
	}
	commits := make(chan uint64, 1)
	go func() {
		defer close(commits)
		sc := bufio.NewScanner(out) // a line over 64 KiB ends the scan, and so the read, never silently
		for sc.Scan() {
			if n := rangeguest.LastCommitted(sc.Text()); n != 0 {
				select {
				case commits <- n: // only that it moved counts, so a full channel drops the value
				default:
				}
			}
		}
		if sc.Err() != nil {
			_ = cmd.Process.Kill() // a cut scan ends the follower now, so the read fails, not waits it out
		}
		_ = cmd.Wait()
	}()
	return commits, nil
}

func (collectorUnit) Stop(ctx context.Context) error {
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", collectorUnitName).Run(); err != nil {
		return fmt.Errorf("systemctl stop: %w", err)
	}
	return nil
}

// readStore reads every record the collector stored before a fresh barrier, and after it the rest
// of the run the read stopped (ADR 0022, point 3); after may be nil.
func readStore(ctx context.Context, before, after func(rawrecord.Record) error) error {
	sr := rangeguest.StoreRead{
		Dir: storeDir, Collector: collectorUnit{}, Clock: rangeguest.WallClock, Settle: time.Second, Poll: 100 * time.Millisecond,
		Mark: func(ctx context.Context, token string) error {
			return exec.CommandContext(ctx, "/usr/bin/true", token).Run() //nolint:gosec // our own random token
		},
	}
	return sr.Read(ctx, waitLimit, before, after) //nolint:wrapcheck // the reader's errors name the step
}

// laurelLines reads the store once and returns its Laurel lines, one per line, at most limit bytes of
// them: the self-test's few thousand records.
func laurelLines(ctx context.Context, limit int) ([]byte, error) {
	var buf bytes.Buffer
	err := readStore(ctx, func(r rawrecord.Record) error {
		if r.Provider != store.SensorProvider {
			return nil
		}
		if buf.Len()+len(r.Data)+1 > limit {
			return fmt.Errorf("the store holds over %d bytes of Laurel lines", limit)
		}
		buf.Write(r.Data)
		buf.WriteByte('\n')
		return nil
	}, nil)
	return buf.Bytes(), err
}

// selfTestLines bounds what the self-test reads of the store into memory.
const selfTestLines = 64 << 20

// readStatus is a store read's outcome as a fact value: "seen" once the barrier came back, which, as
// with Laurel's own order before, means the collector had everything written before it.
func readStatus(err error) string {
	switch {
	case err == nil:
		return "seen"
	case errors.Is(err, rangeguest.ErrBarrierMissing):
		return "missing"
	}
	return "error: " + err.Error()
}

// storeRead is readStore with its context bound; tests replace it.
type storeRead func(before, after func(rawrecord.Record) error) error

// jobWindow returns at most limit bytes of the Laurel lines a store read received from t0 on, whole
// lines only, and "no" only when that is everything the job caused (the host accepts only "no"):
// "yes" when it is cut, "lost" when the barrier did not come back, when a record from t0 to the end
// of the stopped run may mean records are gone (T25; keepsWindow), or when that end, its "stopping"
// record, is not there to show nothing came after, or kernel reports a loss before Laurel
// (kernelLoss); "error" when the store could not be read. why
// names the first record that broke the window, for the console (a security decision's reason).
func jobWindow(read storeRead, t0 int64, limit int, kernel func() string) (window []byte, truncated, why string, err error) {
	var buf bytes.Buffer
	cut, ended := false, false
	err = read(func(r rawrecord.Record) error {
		if r.Received < t0 {
			return nil
		}
		if r.Provider == store.SensorProvider {
			if cut = cut || r.Truncated() || buf.Len()+len(r.Data)+1 > limit; !cut {
				buf.Write(r.Data)
				buf.WriteByte('\n')
			}
			return nil
		}
		if why == "" && !keepsWindow(r, false) {
			why = describe(r, "in the window")
		}
		return nil
	}, func(r rawrecord.Record) error {
		switch {
		case ended || r.Provider == store.SensorProvider:
		case keepsWindow(r, true):
			ended = isStopping(r)
		case why == "":
			why = describe(r, "after the barrier")
		}
		return nil
	})
	switch {
	case errors.Is(err, rangeguest.ErrBarrierMissing):
		return buf.Bytes(), "lost", "the barrier did not come back", err
	case err != nil:
		return nil, "error", err.Error(), err
	case why == "" && !ended:
		why = "the stopped run's stopping record is not in the store"
	case why == "":
		why = kernel()
	}
	switch {
	case why != "":
		return buf.Bytes(), "lost", why, nil
	case cut:
		return buf.Bytes(), "yes", "", nil
	}
	return buf.Bytes(), "no", "", nil
}

// describe names a record that broke a window: its provider and, for a health record, its kind.
func describe(r rawrecord.Record, where string) string {
	if r.Provider != store.HealthProvider {
		return fmt.Sprintf("%s record %s", r.Provider, where)
	}
	h, ok := decodeHealth(r.Data)
	if !ok {
		h.kind = "unreadable"
	}
	return fmt.Sprintf("%s record %.40q %s", r.Provider, h.kind, where)
}

// laurelHold is how long the guest waits after a job before its barrier: Laurel 0.8.2 holds a kernel
// event without an end marker (a seccomp or crash record) until a later record is over 5 s newer,
// checking each 1 s (coalesce.rs EXPIRE_INFLIGHT_TIMEOUT, EXPIRE_PERIOD), so a barrier right after the
// job would pass the job's last such records; with 1 s margin they reach the store first. Laurel
// orders by audit timestamps, so a step back of the guest's realtime clock (only root or the hypervisor
// can make one; the job cannot) could still reorder them: a residual in T25.
const laurelHold = 7 * time.Second

// lossSample is the kernel's lost count and auditd's overflow flag at one moment.
type lossSample struct{ lost, overflow string }

// jobEvidence waits out Laurel's hold, then reads the job's window from the store and checks the
// kernel's and auditd's losses from before (sampled before the job) to a sample taken after the read:
// the interval is the job and its drain to the store, so a loss in the read itself counts against
// the window too, which can only make it "lost".
func jobEvidence(sleep func(time.Duration), read storeRead, t0 int64, limit int, before lossSample, sample func() lossSample) (window []byte, truncated, why string, err error) {
	sleep(laurelHold)
	return jobWindow(read, t0, limit, func() string {
		after := sample()
		return kernelLoss(before.lost, after.lost, before.overflow, after.overflow)
	})
}

// kernelLoss says why records may be missing before Laurel saw them, or "": the kernel's lost count
// moved while the job ran, or auditd's plugin queue overflowed (ADR 0016: both drop records the
// collector never receives). A count that is not a number, or an overflow flag that is not "no",
// is a loss too, never a whole window (R6).
func kernelLoss(lostBefore, lostAfter, overflowBefore, overflowAfter string) string {
	b, errB := strconv.ParseUint(lostBefore, 10, 64)
	a, errA := strconv.ParseUint(lostAfter, 10, 64)
	switch {
	case errB != nil || errA != nil:
		return fmt.Sprintf("the kernel's lost count is unknown (%.20q, %.20q)", lostBefore, lostAfter)
	case a < b:
		return fmt.Sprintf("the kernel's lost count went back from %d to %d", b, a)
	case a > b:
		return fmt.Sprintf("the kernel lost %d records during the job", a-b)
	case overflowBefore != "no" || overflowAfter != "no":
		return fmt.Sprintf("auditd's plugin queue overflowed (%.20q, %.20q)", overflowBefore, overflowAfter)
	}
	return ""
}

// reportWindow prints why an exec window is not whole, and by which rule, to the console, which the
// host keeps as serial.log; quoted, so a record cannot put a line of its own on the console.
func reportWindow(w io.Writer, truncated, why string) {
	if why != "" {
		_, _ = fmt.Fprintf(w, "balistid-range-guest: job window %s (rule %s): %q\n", truncated, jobWindowRule, why)
	}
}

// jobWindowRule names the rule jobWindow decides by, for the console line that gives its reason.
const jobWindowRule = "adr-0022-window-v4"

// healthSchema is the schema of the collector's and the store's health records it reads.
const healthSchema = 1

// keepsWindow is an allowlist (R7): only a health record of the known schema and a kind that says no
// record went missing keeps a window whole. stats counting no lost record or health record since the
// collector started (the job's VM is fresh), lag and refused (a peer that is not Laurel) do, health
// only while OK, and behind the barrier a connection record that counts only eofs: the read's own stop
// ends Laurel's connection so, and leaves unread only what Laurel sent after the barrier, as the
// collector reads connections in order. Inside the window an eof breaks it: there only another stop
// (deadline) or a Laurel close ends a connection. A connect of any cause (Laurel
// restarted or reconnected, the collector started), a read error, started, lost, recovered, a loss
// record, any other kind or schema break it. The stopped run's "stopping" is its end after the
// barrier, never inside.
func keepsWindow(r rawrecord.Record, afterBarrier bool) bool {
	if r.Provider != store.HealthProvider {
		return false
	}
	h, ok := decodeHealth(r.Data)
	switch {
	case !ok:
		return false
	case h.kind == "stats":
		return h.lost != nil && h.lostHealth != nil && *h.lost == 0 && *h.lostHealth == 0
	case h.kind == "lag" || h.kind == "refused":
		return true
	case h.kind == "health":
		return h.state == "OK"
	case h.kind == "connection":
		return afterBarrier && len(h.causes) == 1 && h.causes["eof"] > 0
	}
	return h.kind == "stopping" && afterBarrier
}

func isStopping(r rawrecord.Record) bool {
	h, ok := decodeHealth(r.Data)
	return ok && h.kind == "stopping"
}

// health is what a window reads of a health record: its kind, a health record's state and a
// connection record's counts per cause.
type health struct {
	kind, state      string
	causes           map[string]uint64
	lost, lostHealth *uint64 // a stats record's counts since the collector started
}

// decodeHealth decodes a health record of schema 1; a health record needs its state, a connection
// record its causes and a stats record its loss counts, or it is not read.
func decodeHealth(data []byte) (health, bool) {
	var rec map[string]json.RawMessage
	var schema int
	var h health
	if json.Unmarshal(data, &rec) != nil || json.Unmarshal(rec["schema_version"], &schema) != nil || schema != healthSchema ||
		json.Unmarshal(rec["kind"], &h.kind) != nil {
		return health{}, false
	}
	switch {
	case h.kind == "health" && json.Unmarshal(rec["state"], &h.state) != nil,
		h.kind == "connection" && json.Unmarshal(rec["causes"], &h.causes) != nil,
		h.kind == "stats" && (json.Unmarshal(rec["lost"], &h.lost) != nil || json.Unmarshal(rec["lost_health"], &h.lostHealth) != nil):
		return health{}, false
	}
	return h, true
}
