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
	up, err = uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	boot := time.Now().Add(-up).UnixNano()
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

// exposureLine is systemd-analyze's verdict on the collector's unit.
var exposureLine = regexp.MustCompile(`Overall exposure level for ` + regexp.QuoteMeta(collectorUnitName) + `: (\S+)`)

// runExposure reports the collector unit's overall exposure as the range runs it, with its drop-in
// (systemd_exposure, ADR 0023 point 5).
func runExposure(ctx context.Context, r *report) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/systemd-analyze", "security", "--no-pager", collectorUnitName).Output()
	if err != nil {
		return r.fail("systemd-analyze: " + err.Error())
	}
	value, err := exposureOf(out)
	if err != nil {
		return r.fail(err.Error())
	}
	r.add(rangevm.FactExposure, value)
	return r.send(r.facts)
}

// exposureOf is the one exposure value in systemd-analyze's output; the host judges its form.
func exposureOf(out []byte) (string, error) {
	m := exposureLine.FindAllSubmatch(out, -1)
	if len(m) != 1 {
		return "", errors.New("systemd-analyze did not print one exposure level for the collector")
	}
	return string(m[0][1]), nil
}
