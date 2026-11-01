package rangevm

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of the audit-set trial (ADR 0038, Consequences): the child's capability sets and user, the kernel's
// enabled flag before and after it ("2,2"), and each request it sent as "op=result,...", where a result is ok,
// an errno name or timeout.
const (
	FactAuditSet        = "audit_set"
	FactAuditSetCaps    = "audit_set_caps"
	FactAuditSetUser    = "audit_set_user"
	FactAuditSetEnabled = "audit_set_enabled"
)

// AuditSetOps are the requests the audit-set child sends, in order. get proves the capability and user, which
// needs CAP_AUDIT_WRITE, its absence; auditGates are what -e 2 must refuse, auditResiduals what the kernel
// leaves to the capability under -e 2 (kernel/audit.c: counter resets, features with their own lock), and pid
// what only a running auditd's ownership refuses.
func AuditSetOps() []string { return slices.Clone(auditSetOps) }

var (
	auditSetOps = []string{"get", "enabled", "failure", "rate", "backlog", "wait", "pid", "lost", "wait_actual",
		"rule_add", "rule_del", "trim", "equiv", "feature", "user"}
	auditGates     = []string{"enabled", "failure", "rate", "backlog", "wait", "rule_add", "rule_del", "trim", "equiv"}
	auditResiduals = []string{"lost", "wait_actual", "feature"}
	auditSetFacts  = []string{FactTrial, FactPhase, FactKernel, FactAuditSet, FactAuditSetCaps, FactAuditSetUser,
		FactAuditSetEnabled}
)

// judgeAuditSet: the child ran as balistid-auditstat with CAP_AUDIT_CONTROL alone (prm, eff and amb) on a locked
// kernel, else INVALID. A gate, pid or user that went through, or audit unlocked after the child, is a MISS; then
// a get that failed, a gate refused with anything but EPERM, a pid without EEXIST or a user without EPERM is
// INVALID: no recognised refusal. Residuals are recorded, ok or EPERM, and decide nothing.
func judgeAuditSet(tr rangejob.Trial, o Outcome) (string, string) {
	f, _, why := probeFacts(tr, o, auditSetFacts, nil)
	if why != "" {
		return Invalid, why
	}
	caps := capsAuditControl + "," + capsAuditControl + "," + capsAuditControl
	before, after, _ := strings.Cut(f[FactAuditSetEnabled], ",")
	switch {
	case f[FactAuditSetCaps] != caps:
		return Invalid, fmt.Sprintf("the child's capabilities %q are not CAP_AUDIT_CONTROL alone", Printable(f[FactAuditSetCaps], 64))
	case f[FactAuditSetUser] != "balistid-auditstat":
		return Invalid, fmt.Sprintf("the child ran as %q", Printable(f[FactAuditSetUser], 64))
	case before != "2" || after != "0" && after != "1" && after != "2":
		return Invalid, fmt.Sprintf("audit enabled %q: not locked before the child, or unread", Printable(f[FactAuditSetEnabled], 32))
	}
	res, err := auditSetResults(f[FactAuditSet])
	if err != nil {
		return Invalid, err.Error()
	}
	for _, op := range append(slices.Clone(auditGates), "pid", "user") {
		if res[op] == "ok" {
			return Miss, fmt.Sprintf("auditstat's uid changed %s under -e 2", op)
		}
	}
	if after != "2" {
		return Miss, "audit enabled " + after + " after the child"
	}
	if res["get"] != "ok" {
		return Invalid, fmt.Sprintf("the child's AUDIT_GET gave %s: it did not hold the capability", res["get"])
	}
	for _, op := range auditGates {
		if res[op] != "EPERM" {
			return Invalid, fmt.Sprintf("%s gave %s, not the lock's EPERM", op, res[op])
		}
	}
	for _, op := range auditResiduals {
		if res[op] != "ok" && res[op] != "EPERM" {
			return Invalid, fmt.Sprintf("residual %s gave %s, neither ok nor EPERM", op, res[op])
		}
	}
	if res["pid"] != "EEXIST" || res["user"] != "EPERM" {
		return Invalid, fmt.Sprintf("pid gave %s and user %s, not the running auditd's EEXIST and the missing capability's EPERM",
			res["pid"], res["user"])
	}
	return Pass, fmt.Sprintf("every gate EPERM, pid EEXIST, user EPERM; residuals lost %s, wait_actual %s, feature %s",
		res["lost"], res["wait_actual"], res["feature"])
}

// auditSetResults maps the child's "op=result,..." line: exactly AuditSetOps in order, each result a short
// upper-case errno name, ok or timeout.
func auditSetResults(line string) (map[string]string, error) {
	parts := strings.Split(line, ",")
	if len(parts) != len(auditSetOps) {
		return nil, fmt.Errorf("audit-set reported %d requests, want %d", len(parts), len(auditSetOps))
	}
	res := map[string]string{}
	for i, p := range parts {
		op, result, ok := strings.Cut(p, "=")
		if !ok || op != auditSetOps[i] || !auditResult(result) {
			return nil, fmt.Errorf("audit-set request %d is %q, want %s=<result>", i, Printable(p, 48), auditSetOps[i])
		}
		res[op] = result
	}
	return res, nil
}

func auditResult(s string) bool {
	if s == "ok" || s == "timeout" {
		return true
	}
	if len(s) < 2 || len(s) > 16 || s[0] != 'E' {
		return false
	}
	return strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == ""
}
