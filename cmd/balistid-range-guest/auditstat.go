package main

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/auditstat"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// firstReportWait bounds the wait for auditstat's first report: its unit is ready at execve, before its first poll.
const firstReportWait = 3 * auditstat.Interval

// auditstatReport is "yes" when auditstat's report, read as the collector will read it, moves on over one poll and
// agrees with the kernel (ADR 0038 point 1); else what differs.
func auditstatReport(ctx context.Context) string {
	uid, err := unixsock.LookupUID("balistid-auditstat")
	if err != nil {
		return err.Error()
	}
	first, err := auditstat.ReadReport(auditstat.ReportPath, uid)
	for deadline := time.Now().Add(firstReportWait); err != nil && time.Now().Before(deadline); {
		if !pause(ctx, time.Second) {
			return "stopped before the first read"
		}
		first, err = auditstat.ReadReport(auditstat.ReportPath, uid)
	}
	if err != nil {
		return "first read: " + err.Error()
	}
	if !pause(ctx, auditstat.Interval+time.Second) {
		return "stopped before the second read"
	}
	second, err := auditstat.ReadReport(auditstat.ReportPath, uid)
	if err != nil {
		return "second read: " + err.Error()
	}
	return reportAgrees(first, second, rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s")))
}

// reportAgrees is "yes" when second is a later report than first that matches the kernel's status as auditctl -s
// prints it, with audit locked and auditd running; else what differs.
func reportAgrees(first, second auditstat.Report, kernel map[string]string) string {
	if second.Seq == first.Seq {
		return fmt.Sprintf("seq %d twice", second.Seq)
	}
	s := second.Status
	for name, got := range map[string]uint32{"enabled": s.Enabled, "failure": s.Failure, "pid": s.PID,
		"backlog_limit": s.BacklogLimit, "rate_limit": s.RateLimit} {
		if want := kernel[name]; strconv.FormatUint(uint64(got), 10) != want {
			return fmt.Sprintf("%s %d, the kernel's %q", name, got, want)
		}
	}
	if s.Enabled != 2 || s.PID == 0 {
		return fmt.Sprintf("enabled %d, pid %d", s.Enabled, s.PID)
	}
	return "yes"
}
