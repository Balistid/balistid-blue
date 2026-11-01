package main

import (
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/auditstat"
)

// The report agrees only when it moved on and matches the kernel, audit locked and auditd running.
func TestReportAgrees(t *testing.T) {
	s := auditstat.Status{Enabled: 2, Failure: 1, PID: 412, BacklogLimit: 65536}
	kernel := map[string]string{"enabled": "2", "failure": "1", "pid": "412", "backlog_limit": "65536", "rate_limit": "0"}
	first, second := auditstat.Report{Seq: 4, Status: s}, auditstat.Report{Seq: 5, Status: s}
	if got := reportAgrees(first, second, kernel); got != "yes" {
		t.Fatalf("a sound pair: %s", got)
	}
	down := s
	down.PID = 0
	for name, c := range map[string]struct {
		first, second auditstat.Report
		kernel        map[string]string
		why           string
	}{
		"the same seq":   {second, second, kernel, "twice"},
		"another limit":  {first, second, map[string]string{"enabled": "2", "failure": "1", "pid": "412", "backlog_limit": "8192", "rate_limit": "0"}, "backlog_limit"},
		"auditd stopped": {first, auditstat.Report{Seq: 5, Status: down}, map[string]string{"enabled": "2", "failure": "1", "pid": "0", "backlog_limit": "65536", "rate_limit": "0"}, "pid 0"},
		"unlocked":       {first, auditstat.Report{Seq: 5, Status: auditstat.Status{Enabled: 1, Failure: 1, PID: 412, BacklogLimit: 65536}}, map[string]string{"enabled": "1", "failure": "1", "pid": "412", "backlog_limit": "65536", "rate_limit": "0"}, "enabled 1"},
	} {
		if got := reportAgrees(c.first, c.second, c.kernel); !strings.Contains(got, c.why) {
			t.Errorf("%s: %q, want %q", name, got, c.why)
		}
	}
}
