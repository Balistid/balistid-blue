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

// readStore reads every record the collector stored before a fresh barrier (ADR 0022, point 3).
func readStore(ctx context.Context, fn func(rawrecord.Record) error) error {
	sr := rangeguest.StoreRead{
		Dir: storeDir, Collector: collectorUnit{}, Clock: rangeguest.WallClock, Settle: time.Second, Poll: 100 * time.Millisecond,
		Mark: func(ctx context.Context, token string) error {
			return exec.CommandContext(ctx, "/usr/bin/true", token).Run() //nolint:gosec // our own random token
		},
	}
	return sr.Read(ctx, waitLimit, fn) //nolint:wrapcheck // the reader's errors name the step
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
	})
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

// jobWindow returns at most limit bytes of the Laurel lines a store read received from t0 on, whole
// lines only, and "no" only when that is everything the job caused (the host accepts only "no"):
// "yes" when it is cut, "lost" when the barrier did not come back or a loss record, a collector start
// or a Laurel reconnect lies in the window, whose unread bytes are counted nowhere (T25), "error"
// when the store could not be read.
func jobWindow(read func(func(rawrecord.Record) error) error, t0 int64, limit int) (window []byte, truncated string, err error) {
	var buf bytes.Buffer
	whole, cut := true, false
	err = read(func(r rawrecord.Record) error {
		if r.Received < t0 {
			return nil
		}
		switch r.Provider {
		case store.SensorProvider:
			if cut = cut || r.Truncated() || buf.Len()+len(r.Data)+1 > limit; !cut {
				buf.Write(r.Data)
				buf.WriteByte('\n')
			}
		case store.LossProvider:
			whole = false
		case store.HealthProvider:
			whole = whole && !breaksWindow(r.Data)
		}
		return nil
	})
	switch {
	case errors.Is(err, rangeguest.ErrBarrierMissing) || err == nil && !whole:
		return buf.Bytes(), "lost", err
	case err != nil:
		return nil, "error", err
	case cut:
		return buf.Bytes(), "yes", nil
	}
	return buf.Bytes(), "no", nil
}

// breaksWindow reports whether a health record says records may be gone: a collector start, a
// Laurel connection or a loss the collector counted. A record it cannot read breaks it too.
func breaksWindow(data []byte) bool {
	var rec map[string]json.RawMessage
	var kind string
	if json.Unmarshal(data, &rec) != nil || json.Unmarshal(rec["kind"], &kind) != nil {
		return true
	}
	return kind == "started" || kind == "connection" || kind == "lost"
}
