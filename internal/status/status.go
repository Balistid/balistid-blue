package status

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// SchemaVersion is the version of the JSON result; readers reject another major version.
const SchemaVersion = 1

// The states of a part. Only OK is healthy; UNKNOWN is a part status could not read (R6).
const (
	OK      = "OK"
	Fail    = "FAIL"
	Unknown = "UNKNOWN"
)

// HealthPart names the collector's health among the parts; every other part is a unit of units.
const HealthPart = "health"

// Part is one line of the result: a unit or the health, its state, what was seen and, when not OK, where to look.
type Part struct {
	Name   string `json:"part"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

// Result is what balistid status shows: OK only when every part is.
type Result struct {
	SchemaVersion int    `json:"schema_version"`
	OK            bool   `json:"ok"`
	Parts         []Part `json:"parts"`
}

// Sources are where Check reads the floor; Host reads this host's.
type Sources struct {
	Units    func(ctx context.Context, names []string) ([]UnitState, error)
	Report   func() (Report, error)
	Boottime func() (uint64, error)
}

// Host reads systemd and the collector's report on this host.
func Host() Sources {
	return Sources{Units: ShowUnits, Boottime: Boottime, Report: func() (Report, error) {
		uid, err := unixsock.LookupUID("balistid-collector")
		if err != nil {
			return Report{}, err //nolint:wrapcheck // names the account
		}
		return ReadReport(ReportPath, uid)
	}}
}

// Check reads every part. A part it cannot read is UNKNOWN, never OK.
func Check(ctx context.Context, src Sources) Result {
	names := make([]string, len(units))
	for i, u := range units {
		names[i] = u.Name
	}
	parts := make([]Part, 0, len(units)+1)
	states, err := src.Units(ctx, names)
	for i, u := range units {
		if err != nil {
			parts = append(parts, Part{Name: u.Name, State: Unknown, Detail: "systemd did not answer",
				Hint: "systemctl status " + u.Name})
			continue
		}
		parts = append(parts, unitPart(u, states[i]))
	}
	parts = append(parts, healthPart(src))
	res := Result{SchemaVersion: SchemaVersion, OK: true, Parts: parts}
	for _, p := range parts {
		res.OK = res.OK && p.State == OK
	}
	return res
}

func unitPart(u Unit, s UnitState) Part {
	p := Part{Name: u.Name, State: OK, Detail: s.Active + "/" + s.Sub}
	switch {
	case s.Load != "loaded":
		p.State, p.Detail, p.Hint = Fail, s.Load, "the unit is not installed: install Balistid Blue again"
	case s.Active != "active" || !slices.Contains(u.Subs, s.Sub):
		p.State, p.Hint = Fail, "systemctl status "+u.Name+"; journalctl -u "+u.Name
	}
	return p
}

func healthPart(src Sources) Part {
	p := Part{Name: HealthPart, State: Unknown}
	const collectorHint = "systemctl status balistid-collector.service; journalctl -u balistid-collector.service"
	rep, err := src.Report()
	if err != nil {
		p.Detail, p.Hint = "the collector's report is unreadable", collectorHint
		if errors.Is(err, fs.ErrNotExist) {
			p.Detail = "no report: the collector is not running or cannot write it"
		}
		return p
	}
	now, err := src.Boottime()
	switch {
	case err != nil:
		p.Detail, p.Hint = "no boot clock to age the report", collectorHint
		return p
	case rep.Boot > now:
		p.Detail, p.Hint = "a report from after now", collectorHint
		return p
	case time.Duration(now-rep.Boot) > MaxAge: //nolint:gosec // a difference of two boot clock readings
		p.Detail = fmt.Sprintf("the report is %d s old: the collector stopped or is stuck", (now-rep.Boot)/uint64(time.Second))
		p.Hint = collectorHint
		return p
	case rep.Health.State == entry.StateOK:
		return Part{Name: HealthPart, State: OK, Detail: "OK"}
	}
	why, ok := reasons[rep.Health.Reason]
	if !ok {
		p.Detail, p.Hint = "a reason this version does not know", collectorHint
		return p
	}
	p.Detail, p.Hint = why.name, why.hint
	return p
}

// reasons name each UNKNOWN of the collector (entry.Reason) and say where to look.
var reasons = map[entry.Reason]struct{ name, hint string }{
	entry.ReasonStarting: {"starting",
		"the collector started; health is UNKNOWN until its first canary is stored and auditstat's report read (up to 15 s)"},
	entry.ReasonStoreDown: {"store-down",
		"the store refuses writes: a full disk, an I/O error or a damaged shard; journalctl -u balistid-collector.service"},
	entry.ReasonLaurelDisconnected: {"laurel-disconnected",
		"Laurel is not connected: auditd or its laurel plugin is down; journalctl -u auditd.service"},
	entry.ReasonCanaryMissed: {"canary-missed",
		"two canaries were not recorded: auditd or Laurel stalled, or the audit rules changed; journalctl -u auditd.service"},
	entry.ReasonCanaryPending: {"canary-pending", "the first canary over this connection is not recorded yet (up to 30 s)"},
	entry.ReasonStream: {"ledger-stream",
		"the stream to the ledger stopped; journalctl -u balistid-ledger.service -u balistid-collector.service"},
	entry.ReasonLogCap: {"log-cap", "the ledger's log is full: nothing new is anchored"},
	entry.ReasonAuditStale: {"audit-stale",
		"auditstat's report or auditd's state file is not fresh; systemctl status balistid-auditstat.service auditd.service"},
	entry.ReasonDispatcher: {"dispatcher-overflow",
		"auditd's dispatcher dropped events before Laurel: records were lost; journalctl -u auditd.service"},
	entry.ReasonAuditd: {"auditd",
		"auditd is not running, restarted, or audit is not locked; systemctl status auditd.service"},
	entry.ReasonRulesDiffer: {"rules-differ",
		"the loaded audit rules or -b, -f, -r differ from the installed balistid.rules; auditctl -l, auditctl -s, then reboot"},
}
