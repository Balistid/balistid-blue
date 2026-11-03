package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// canaryMissed is the collector's health while two probes in a row missed (internal/collector/writer.go).
const canaryMissed = "UNKNOWN canary-missed"

// sysOpenat is openat's number on x86-64, the guest's arch: the collector's touch creates c-<n> with it
// (os.OpenFile), and Laurel, translate.universal off, writes the number.
const sysOpenat = "257"

// runCanary measures canary_interval_s (ADR 0017, ADR 0054): once the floor shows healthy it stays quiet for
// CanaryQuiet, then freezes Laurel and then auditd for CanaryFreeze each and watches CanaryAfter after each SIGCONT.
// Then it reads the store once, which stops the collector: the collector's canary records give their audit times,
// its health records when it went UNKNOWN and OK. The kernel stage is no stage: rules locked by -e 2 keep the
// canary's. A floor that never shows healthy fails the trial: nothing after it would be the injection's.
func runCanary(ctx context.Context, r *report) error {
	cred, err := credential(statusUser)
	if err != nil {
		return r.fail(err.Error())
	}
	quietFrom, err := healthyFrom(ctx, func(ctx context.Context) (int, []byte, error) { return runCLI(ctx, cred) }, statusWait)
	if err != nil {
		return r.fail("before the quiet phase: " + err.Error())
	}
	owner, err := collectorProcess(ctx)
	if err != nil {
		return r.fail(err.Error())
	}
	if !pause(ctx, rangevm.CanaryQuiet) {
		return r.fail("quiet phase: " + ctx.Err().Error())
	}
	quietTo := time.Now().UnixNano()
	var freezes []canaryFreeze
	for _, s := range rangevm.CanaryStages() {
		fr, err := freezeStage(ctx, s.Kind)
		if err != nil {
			return r.fail(s.Name + ": " + err.Error())
		}
		freezes = append(freezes, fr)
	}
	if again, err := collectorProcess(ctx); err != nil || again != owner {
		return r.fail("the collector is not the process it was before the quiet phase")
	}
	var timeline healthTimeline
	sent := map[uint64]int64{}
	each := func(x rawrecord.Record) error {
		if n, at, ok := canarySent(x, owner); ok {
			if _, dup := sent[n]; !dup { // a record stored twice is one probe (T25)
				sent[n] = at
			}
		}
		return timeline.add(x)
	}
	if err := readStore(ctx, each, each); err != nil {
		return r.fail("store: " + err.Error())
	}
	times := slices.Sorted(maps.Values(sent))
	count, gap := canaryGaps(times, quietFrom, quietTo)
	r.add(rangevm.FactCanaryQuietMS, msString(quietTo-quietFrom))
	r.add(rangevm.FactCanaryQuietHealth, timeline.over(quietFrom, quietTo))
	r.add(rangevm.FactCanaryCount, strconv.Itoa(count))
	r.add(rangevm.FactCanaryGapMS, msString(gap))
	for i, s := range rangevm.CanaryStages() {
		for _, f := range freezes[i].facts(times, timeline) {
			r.add(rangevm.CanaryFact(s.Name, f[0]), f[1])
		}
	}
	return r.send(r.facts)
}

// healthyFrom waits up to wait for the CLI to exit 0, the floor healthy, and returns when it did in the guest's wall
// clock in ns, where a canary trial's quiet phase starts; a floor not healthy by then is an error.
func healthyFrom(ctx context.Context, cli cliRun, wait time.Duration) (int64, error) {
	if err := untilCLI(ctx, cli, 0, wait); err != nil {
		return 0, err
	}
	return time.Now().UnixNano(), nil
}

// canaryOwner is the collector's process as its canary records name it: the uid and pid of its probes' syscalls.
type canaryOwner struct{ uid, pid string }

// collectorProcess is the collector's main process and its real uid.
func collectorProcess(ctx context.Context) (canaryOwner, error) {
	pid := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "MainPID", collectorUnitName))
	if n, err := strconv.Atoi(pid); err != nil || n <= 0 || strconv.Itoa(n) != pid {
		return canaryOwner{}, fmt.Errorf("no collector process: %q", pid)
	}
	uid := strings.Fields(rangeguest.StatusField(readTrim("/proc/"+pid+"/status"), "Uid"))
	if len(uid) == 0 {
		return canaryOwner{}, fmt.Errorf("no uid of the collector's pid %s", pid)
	}
	return canaryOwner{uid: uid[0], pid: pid}, nil
}

// canaryFreeze is one stage frozen: the proof that it held, and when, in the guest's wall clock in ns, the freeze
// began, SIGCONT went out and the watch after it ended.
type canaryFreeze struct {
	stopped           string
	from, thaw, until int64
}

// freezeStage stops the process of kind (rangevm.StatusFreezeLaurel or StatusFreezeAuditd) for CanaryFreeze,
// proves it stopped a second after SIGSTOP and right before SIGCONT, then waits CanaryAfter. SIGCONT goes out
// also when ctx ends.
func freezeStage(ctx context.Context, kind string) (canaryFreeze, error) {
	pid, err := frozenTarget(ctx, kind)
	if err != nil {
		return canaryFreeze{}, err
	}
	fr := canaryFreeze{from: time.Now().UnixNano()}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return canaryFreeze{}, fmt.Errorf("SIGSTOP %d: %w", pid, err)
	}
	held := pause(ctx, time.Second) // the signal stops the process when it is next scheduled, not at once
	before := processStopped(pid)
	held = held && pause(ctx, rangevm.CanaryFreeze-time.Second)
	after := processStopped(pid)
	fr.thaw = time.Now().UnixNano()
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return canaryFreeze{}, fmt.Errorf("SIGCONT %d: %w", pid, err)
	}
	if !held || !pause(ctx, rangevm.CanaryAfter) {
		return canaryFreeze{}, fmt.Errorf("frozen: %w", ctx.Err())
	}
	fr.until = time.Now().UnixNano()
	switch {
	case before != "yes":
		fr.stopped = "a second after SIGSTOP: " + before
	case after != "yes":
		fr.stopped = "before SIGCONT: " + after
	default:
		fr.stopped = "yes"
	}
	return fr, nil
}

// facts are the stage's facts by rangevm.CanaryFact's what: the proof, the store's health when the freeze
// began and from the first canaryMissed after it to SIGCONT, its length and the watch after it, the first canary
// sent from the freeze on, that first canaryMissed, until the watch ended, and the first OK from SIGCONT on and
// after that UNKNOWN.
func (fr canaryFreeze) facts(sent []int64, t healthTimeline) [][2]string {
	first, unknown, ok := rangevm.CanaryNone, rangevm.CanaryNone, rangevm.CanaryNone
	if i, _ := slices.BinarySearch(sent, fr.from); i < len(sent) && sent[i] <= fr.until {
		first = msString(sent[i] - fr.from)
	}
	unknownAt := int64(0)
	for _, h := range t {
		switch {
		case h.at < fr.from || h.at > fr.until:
		case unknownAt == 0 && h.state == canaryMissed:
			unknownAt, unknown = h.at, msString(h.at-fr.from)
		case unknownAt != 0 && ok == rangevm.CanaryNone && h.state == "OK" && h.at >= fr.thaw:
			ok = msString(h.at - fr.thaw)
		}
	}
	held := rangevm.CanaryNone
	if unknownAt != 0 {
		held = t.over(unknownAt, fr.thaw)
	}
	return [][2]string{
		{rangevm.CanaryStopped, fr.stopped}, {rangevm.CanaryHealth, t.over(fr.from, fr.from)}, {rangevm.CanaryHeld, held},
		{rangevm.CanaryFrozenMS, msString(fr.thaw - fr.from)}, {rangevm.CanaryAfterMS, msString(fr.until - fr.thaw)},
		{rangevm.CanaryFirstMS, first}, {rangevm.CanaryUnknownMS, unknown}, {rangevm.CanaryOKMS, ok},
	}
}

// canaryGaps counts the canaries sent from from to to (ns, sorted) and returns the longest time without one, from
// from to the first, between two and from the last to to: a canary that stopped shows as a long gap, never as
// fewer gaps.
func canaryGaps(sent []int64, from, to int64) (int, int64) {
	count, last, longest := 0, from, int64(0)
	for _, at := range sent {
		if at < from || at > to {
			continue
		}
		count, longest, last = count+1, max(longest, at-last), at
	}
	return count, max(longest, to-last)
}

// canarySent is the probe number and the audit time in ns of x when it is the record of owner's probe: the canary
// key, owner's uid and pid, a successful openat and a PATH item c-<n> it created. Removing an older c-<n>, which the
// next probe does, is no probe. Keys are matched exactly, as Laurel puts an enriched "PID" beside "pid".
func canarySent(x rawrecord.Record, owner canaryOwner) (uint64, int64, bool) {
	var top map[string]json.RawMessage
	var sc map[string]json.RawMessage
	var paths []map[string]json.RawMessage
	var id, success string
	if x.Provider != store.SensorProvider || x.Truncated() || json.Unmarshal(x.Data, &top) != nil ||
		json.Unmarshal(top["ID"], &id) != nil || json.Unmarshal(top["SYSCALL"], &sc) != nil ||
		json.Unmarshal(top["PATH"], &paths) != nil || json.Unmarshal(sc["success"], &success) != nil ||
		success != "yes" || string(sc["syscall"]) != sysOpenat || string(sc["uid"]) != owner.uid || string(sc["pid"]) != owner.pid ||
		!canaryKey(sc["key"]) {
		return 0, 0, false
	}
	at, ok := auditTime(id)
	if !ok {
		return 0, 0, false
	}
	for _, p := range paths {
		var name, nametype string
		if json.Unmarshal(p["name"], &name) != nil || json.Unmarshal(p["nametype"], &nametype) != nil || nametype != "CREATE" {
			continue
		}
		if n, found := strings.CutPrefix(filepath.Base(name), "c-"); found {
			v, err := strconv.ParseUint(n, 10, 64)
			return v, at, err == nil && strconv.FormatUint(v, 10) == n
		}
	}
	return 0, 0, false
}

// canaryKey reports whether an audit key field holds the canary's key: a string, in which the kernel joins
// several keys with \x01, or a list of strings.
func canaryKey(raw json.RawMessage) bool {
	var one string
	var many []string
	if json.Unmarshal(raw, &one) == nil {
		many = strings.Split(one, "\x01")
	} else if json.Unmarshal(raw, &many) != nil {
		return false
	}
	return slices.Contains(many, collectorCanaryKey)
}

// auditTime is the kernel's time of an audit event in ns from its ID "<sec>.<ms>:<serial>", the syscall's
// own time: Laurel may hold an event up to 5 s before the collector receives it.
func auditTime(id string) (int64, bool) {
	stamp, serial, ok := strings.Cut(id, ":")
	sec, milli, dot := strings.Cut(stamp, ".")
	s, errS := strconv.ParseInt(sec, 10, 64)
	m, errM := strconv.ParseInt(milli, 10, 64)
	_, errN := strconv.ParseUint(serial, 10, 64)
	if !ok || !dot || errS != nil || errM != nil || errN != nil || len(milli) != 3 || strings.Trim(milli, "0123456789") != "" ||
		strconv.FormatInt(s, 10) != sec || s < 0 || s > 1<<33 {
		return 0, false
	}
	return s*int64(time.Second) + m*int64(time.Millisecond), true
}

// msString is ns as whole ms, the unit of a canary trial's times.
func msString(ns int64) string { return strconv.FormatInt(ns/int64(time.Millisecond), 10) }
