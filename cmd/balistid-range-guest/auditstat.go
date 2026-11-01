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

// auditstatReport is "yes" when auditstat's report, read as the collector will read it, moves on over one poll and
// agrees with the kernel: audit locked, auditd's pid and the loaded settings (ADR 0038 point 1); else what differs.
func auditstatReport(ctx context.Context) string {
	uid, err := unixsock.LookupUID("balistid-auditstat")
	if err != nil {
		return err.Error()
	}
	first, err := auditstat.ReadReport(auditstat.ReportPath, uid)
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
	if second.Seq == first.Seq {
		return fmt.Sprintf("seq %d twice", second.Seq)
	}
	kernel := rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))
	s := second.Status
	for name, got := range map[string]uint32{"enabled": s.Enabled, "failure": s.Failure, "pid": s.PID,
		"backlog_limit": s.BacklogLimit, "rate_limit": s.RateLimit} {
		if want := kernel[name]; strconv.FormatUint(uint64(got), 10) != want {
			return fmt.Sprintf("%s %d, the kernel's %q", name, got, want)
		}
	}
	if s.Enabled != 2 {
		return fmt.Sprintf("enabled %d", s.Enabled)
	}
	return "yes"
}
