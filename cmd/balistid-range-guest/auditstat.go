package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/auditstat"
)

const auditstatReportPath = "/run/balistid-auditstat/report"

// auditstatReport is "yes" when auditstat's report moves on over one poll and agrees with the kernel, audit locked
// and auditd's pid (ADR 0038 point 1), else what differs.
func auditstatReport(ctx context.Context) string {
	read := func() (auditstat.Report, error) {
		b, err := os.ReadFile(auditstatReportPath)
		if err != nil {
			return auditstat.Report{}, err //nolint:wrapcheck // the fact names the read
		}
		return auditstat.DecodeReport(b)
	}
	first, err := read()
	if err != nil {
		return "first read: " + err.Error()
	}
	if !pause(ctx, auditstat.Interval+time.Second) {
		return "stopped before the second read"
	}
	second, err := read()
	auditd := mainPID(ctx, "auditd.service")
	switch {
	case err != nil:
		return "second read: " + err.Error()
	case second.Seq <= first.Seq:
		return fmt.Sprintf("seq %d, then %d", first.Seq, second.Seq)
	case second.Status.Enabled != 2:
		return fmt.Sprintf("enabled %d", second.Status.Enabled)
	case strconv.FormatUint(uint64(second.Status.PID), 10) != auditd:
		return fmt.Sprintf("pid %d, auditd's %q", second.Status.PID, auditd)
	}
	return "yes"
}
