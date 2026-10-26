package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// readyAfter is how long after kernel start a ready trial reads the store: past ready_s's 30 s, so a
// health record OK in time is stored by then.
const readyAfter = 31 * time.Second

// runReady reports the ms from kernel start to the store's receipt of the collector's first health
// record OK, or "none" (ready_s, ADR 0023 point 5).
func runReady(ctx context.Context, r *report) error {
	up, err := uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	time.Sleep(readyAfter - up)
	before := time.Now()
	up, err = uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	boot := bootBound(before, up)
	var ready int64
	each := func(x rawrecord.Record) error {
		if h, ok := decodeHealth(x.Data); ready == 0 && healthKind(x) == "health" && ok && h.state == "OK" {
			ready = x.Received
		}
		return nil
	}
	if err := readStore(ctx, each, each); err != nil {
		return r.fail("store: " + err.Error())
	}
	r.add(rangevm.FactReadyMS, readyMS(boot, ready))
	return r.send(r.facts)
}

// uptimeQuantum is how much /proc/uptime may lag, printing hundredths cut down.
const uptimeQuantum = 10 * time.Millisecond

// bootBound is the earliest kernel start, in ns since 1970, that an uptime read after the realtime
// before allows: a pause between the two readings, or the uptime's cut hundredths, move it earlier,
// so ready_s comes out at most too long, never too short.
func bootBound(before time.Time, up time.Duration) int64 {
	return before.Add(-up - uptimeQuantum).UnixNano()
}

// readyMS is the ms from boot to ready, both ns since 1970, "none" without a ready, and why when ready
// came before boot.
func readyMS(boot, ready int64) string {
	switch {
	case ready == 0:
		return "none"
	case ready < boot:
		return "before kernel start"
	}
	return strconv.FormatInt((ready-boot)/int64(time.Millisecond), 10)
}

// uptime is the time since kernel start (/proc/uptime).
func uptime() (time.Duration, error) {
	return parseUptime(readTrim("/proc/uptime"))
}

func parseUptime(s string) (time.Duration, error) {
	first, _, _ := strings.Cut(s, " ")
	sec, err := strconv.ParseFloat(first, 64)
	if err != nil || sec < 0 {
		return 0, fmt.Errorf("uptime %q", s)
	}
	return time.Duration(sec * float64(time.Second)), nil
}

// rangeOnlyUnits are the image's own units, never installed on a host; balistid-auditstat has its own
// metric (systemd_exposure_auditstat).
var rangeOnlyUnits = map[string]bool{
	"balistid-range-guest.service": true, "balistid-range-store.service": true, "balistid-auditstat.service": true,
}

// runExposure reports systemd-analyze's overall exposure of every Balistid Blue service the image has
// but its own and auditstat, as the range runs them with their drop-ins (systemd_exposure, ADR 0023
// point 5), as "unit=value,..."; the host judges each value's form and size.
func runExposure(ctx context.Context, r *report) error {
	list, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain",
		"balistid-*.service").Output()
	if err != nil {
		return r.fail("systemctl list-unit-files: " + err.Error())
	}
	var scores []string
	for _, unit := range productUnits(string(list)) {
		out, err := exec.CommandContext(ctx, "/usr/bin/systemd-analyze", "security", "--no-pager", unit).Output() //nolint:gosec // a unit name systemd listed
		if err != nil {
			return r.fail("systemd-analyze " + unit + ": " + err.Error())
		}
		value, err := exposureOf(out, unit)
		if err != nil {
			return r.fail(err.Error())
		}
		scores = append(scores, unit+"="+value)
	}
	r.add(rangevm.FactExposure, strings.Join(scores, ","))
	return r.send(r.facts)
}

// productUnits are the services of list-unit-files output that are not range-only.
func productUnits(list string) []string {
	var units []string
	for _, line := range strings.Split(list, "\n") {
		if f := strings.Fields(line); len(f) > 0 && !rangeOnlyUnits[f[0]] {
			units = append(units, f[0])
		}
	}
	return units
}

// exposureOf is the one exposure value of unit in systemd-analyze's output.
func exposureOf(out []byte, unit string) (string, error) {
	line := regexp.MustCompile(`Overall exposure level for ` + regexp.QuoteMeta(unit) + `: (\S+)`)
	m := line.FindAllSubmatch(out, -1)
	if len(m) != 1 {
		return "", errors.New("systemd-analyze did not print one exposure level for " + unit)
	}
	return string(m[0][1]), nil
}
