package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const collectorUnitName = "balistid-collector.service"

// collectorUnit is the collector as the guest reads its commit line from the journal and stops it.
type collectorUnit struct{}

// commitLines is how many of the collector's last journal lines are searched for its commit line: it
// writes few others (lag, health), so the last commit is among them.
const commitLines = "500"

func (collectorUnit) Committed(ctx context.Context) (uint64, error) {
	out, err := exec.CommandContext(ctx, "/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "cat", "-n", commitLines, "-u", collectorUnitName).Output()
	if err != nil {
		return 0, fmt.Errorf("journalctl: %w", err)
	}
	return rangeguest.LastCommitted(string(out)), nil
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
// record, is not there to show nothing came after; "error" when the store could not be read.
func jobWindow(read storeRead, t0 int64, limit int) (window []byte, truncated string, err error) {
	var buf bytes.Buffer
	whole, cut, ended := true, false, false
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
		whole = whole && keepsWindow(r, false)
		return nil
	}, func(r rawrecord.Record) error {
		switch {
		case ended || r.Provider == store.SensorProvider:
		case keepsWindow(r, true):
			ended = isStopping(r)
		default:
			whole = false
		}
		return nil
	})
	switch {
	case errors.Is(err, rangeguest.ErrBarrierMissing) || err == nil && (!whole || !ended):
		return buf.Bytes(), "lost", err
	case err != nil:
		return nil, "error", err
	case cut:
		return buf.Bytes(), "yes", nil
	}
	return buf.Bytes(), "no", nil
}

// healthSchema is the schema of the collector's and the store's health records it reads.
const healthSchema = 1

// keepsWindow is an allowlist (R7): only a health record of the known schema and a kind that says no
// record went missing keeps a window whole. stats, lag and refused (a peer that is not Laurel) do,
// and health only while OK; started, connection, lost, recovered, a loss record, any other kind or
// schema break it. The stopped run's own "stopping" is its end after the barrier, never inside.
func keepsWindow(r rawrecord.Record, afterBarrier bool) bool {
	if r.Provider != store.HealthProvider {
		return false
	}
	kind, state, ok := healthKind(r.Data)
	switch {
	case !ok:
		return false
	case kind == "stats" || kind == "lag" || kind == "refused":
		return true
	case kind == "health":
		return state == "OK"
	}
	return kind == "stopping" && afterBarrier
}

func isStopping(r rawrecord.Record) bool {
	kind, _, ok := healthKind(r.Data)
	return ok && kind == "stopping"
}

// healthKind decodes a health record's kind and, for kind health, its state; ok only for schema 1.
func healthKind(data []byte) (kind, state string, ok bool) {
	var rec map[string]json.RawMessage
	var schema int
	if json.Unmarshal(data, &rec) != nil || json.Unmarshal(rec["schema_version"], &schema) != nil || schema != healthSchema ||
		json.Unmarshal(rec["kind"], &kind) != nil {
		return "", "", false
	}
	if kind == "health" && json.Unmarshal(rec["state"], &state) != nil {
		return "", "", false
	}
	return kind, state, true
}
