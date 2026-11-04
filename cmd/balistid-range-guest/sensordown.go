package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// How long a sensor-down trial waits for a signalled process to exit, and keeps auditd stopped: past sensor_down_s,
// so an UNKNOWN late by a few seconds is timed, not lost when the floor recovers.
const (
	sensorExitWait = 30 * time.Second
	sensorDownHold = 20 * time.Second
)

// runSensorDown measures sensor_down_s (ADR 0059): once the floor shows healthy it SIGKILLs Laurel and waits for
// the floor healthy again, then SIGTERMs auditd, whose unit refuses a manual stop, starts it after sensorDownHold and
// waits again; then it tries auditctl -e 0 under -e 2. One read of the store, which stops the collector, gives the
// health records each stage is timed by and the kernel's record of the refusal.
func runSensorDown(ctx context.Context, r *report) error {
	cred, err := credential(statusUser)
	if err != nil {
		return r.fail(err.Error())
	}
	cli := func(ctx context.Context) (int, []byte, error) { return runCLI(ctx, cred) }
	if _, err := healthyFrom(ctx, cli, statusWait); err != nil {
		return r.fail("before the first stage: " + err.Error())
	}
	owner, err := collectorProcess(ctx)
	if err != nil {
		return r.fail(err.Error())
	}
	var failures []sensorFailure
	for _, s := range rangevm.SensorStages() {
		fl, err := failStage(ctx, s.Kind, cli)
		if err != nil {
			return r.fail(s.Name + ": " + err.Error())
		}
		if again, err := collectorProcess(ctx); fl.done == "yes" && (err != nil || again != owner) {
			fl.done = "the collector is not the process it was before the stage"
		}
		failures = append(failures, fl)
	}
	e0From := time.Now().UnixNano()
	disableAudit(ctx)
	r.add(rangevm.FactSensorE0Enabled, valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["enabled"]))
	var timeline healthTimeline
	refused := false
	each := func(x rawrecord.Record) error {
		if at, ok := refusedDisable(x); ok && at >= e0From-int64(time.Second) { // the kernel's coarse clock
			refused = true
		}
		return timeline.add(x)
	}
	if err := readStore(ctx, each, each); err != nil {
		return r.fail("store: " + err.Error())
	}
	r.add(rangevm.FactSensorE0Recorded, yesNo(refused))
	for i, s := range rangevm.SensorStages() {
		for _, f := range failures[i].facts(timeline) {
			r.add(rangevm.SensorFact(s.Name, f[0]), f[1])
		}
	}
	return r.send(r.facts)
}

// sensorFailure is one stage failed: "yes" when it was, or why not, and when, in the guest's wall clock in ns, the
// stamp before the signal was taken and the floor showed healthy again.
type sensorFailure struct {
	done      string
	at, until int64
}

// failStage signals the process of kind (rangevm.StatusFreezeLaurel or StatusFreezeAuditd) through a pidfd, SIGKILL
// for Laurel and SIGTERM for auditd, waits for its exit, starts auditd again after sensorDownHold and waits for the
// floor healthy. A failure it cannot cause is an error; one whose aftermath it cannot prove is in done.
func failStage(ctx context.Context, kind string, cli cliRun) (sensorFailure, error) {
	pid, err := frozenTarget(ctx, kind)
	if err != nil {
		return sensorFailure{}, err
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return sensorFailure{}, fmt.Errorf("pidfd of %d: %w", pid, err)
	}
	defer unix.Close(pidfd) //nolint:errcheck // a pidfd holds nothing to flush
	sig := unix.SIGKILL
	if kind == rangevm.StatusFreezeAuditd {
		sig = unix.SIGTERM
	}
	fl := sensorFailure{at: time.Now().UnixNano()}
	if err := unix.PidfdSendSignal(pidfd, sig, nil, 0); err != nil {
		return sensorFailure{}, fmt.Errorf("signal %d: %w", pid, err)
	}
	if err := waitExit(ctx, pidfd, sensorExitWait); err != nil {
		return sensorFailure{}, fmt.Errorf("pid %d: %w", pid, err)
	}
	fl.done = "yes"
	if kind == rangevm.StatusFreezeAuditd {
		if !pause(ctx, sensorDownHold) {
			return sensorFailure{}, fmt.Errorf("auditd stopped: %w", ctx.Err())
		}
		output(ctx, "/usr/bin/systemctl", "start", auditdUnitName)
	}
	if err := untilCLI(ctx, cli, 0, statusWait); err != nil {
		fl.done = "the floor not healthy again: " + err.Error()
	}
	fl.until = time.Now().UnixNano()
	return fl, nil
}

// waitExit waits up to wait for the process behind pidfd to exit.
func waitExit(ctx context.Context, pidfd int, wait time.Duration) error {
	for deadline := time.Now().Add(wait); ctx.Err() == nil; {
		left := time.Until(deadline)
		if left <= 0 {
			return fmt.Errorf("no exit within %s of the signal", wait)
		}
		exited, err := pidfdExited(pidfd, min(left, time.Second))
		switch {
		case err != nil:
			return err
		case exited:
			return nil
		}
	}
	return fmt.Errorf("waiting for an exit: %w", ctx.Err())
}

// facts are the stage's facts by rangevm.SensorFact's what: the proof, the store's health at the stamp, and the
// state and time after the stamp of the first health record not OK after it, up to the floor's recovery.
func (fl sensorFailure) facts(t healthTimeline) [][2]string {
	reason, unknown := rangevm.CanaryNone, rangevm.CanaryNone
	for _, h := range t {
		if h.at > fl.at && h.at <= fl.until && h.state != "OK" {
			reason, unknown = h.state, msString(h.at-fl.at)
			break
		}
	}
	return [][2]string{
		{rangevm.SensorDone, fl.done}, {rangevm.SensorHealth, t.over(fl.at, fl.at)},
		{rangevm.SensorReason, reason}, {rangevm.SensorUnknownMS, unknown},
	}
}

// refusedDisable is the audit time in ns of x when it is Laurel's event of the kernel refusing audit_enabled=0.
func refusedDisable(x rawrecord.Record) (int64, bool) {
	var top map[string]json.RawMessage
	var id string
	if x.Provider != store.SensorProvider || x.Truncated() || json.Unmarshal(x.Data, &top) != nil ||
		json.Unmarshal(top["ID"], &id) != nil || !rangeguest.HasRefusedDisable(bytes.NewReader(x.Data)) {
		return 0, false
	}
	return auditTime(id)
}
