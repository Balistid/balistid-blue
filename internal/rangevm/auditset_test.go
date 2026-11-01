package rangevm

import (
	"strings"
	"testing"
)

// auditSetRun is an audit-set report with the kernel's answers of 2026-11 (kernel/audit.c under -e 2), op=result
// pairs in ops replacing those answers and fact=value pairs in facts replacing the other facts.
func auditSetRun(ops map[string]string, facts ...string) Outcome {
	res := map[string]string{"get": "ok", "pid": "EEXIST", "lost": "ok", "wait_actual": "ok", "feature": "ok", "user": "EPERM"}
	for _, op := range auditGates {
		res[op] = "EPERM"
	}
	for op, r := range ops {
		res[op] = r
	}
	line := make([]string, 0, len(auditSetOps))
	for _, op := range auditSetOps {
		line = append(line, op+"="+res[op])
	}
	caps := capsAuditControl + "," + capsAuditControl + "," + capsAuditControl
	base := map[string]string{FactAuditSet: strings.Join(line, ","), FactAuditSetCaps: caps,
		FactAuditSetUser: "balistid-auditstat", FactAuditSetEnabled: "2,2"}
	return probeRun("audit-set", auditSetFacts, base, facts...)
}

func TestJudgeAuditSet(t *testing.T) {
	tr := trial(t, "audit-set")
	cases := []struct {
		want  string
		ops   map[string]string
		facts []string
	}{
		{want: Pass},
		{want: Pass, ops: map[string]string{"lost": "EPERM", "wait_actual": "EPERM", "feature": "EPERM"}},
		{want: Invalid, ops: map[string]string{"pid": "EINVAL"}},
		{want: Invalid, ops: map[string]string{"pid": "EUNKNOWN"}},
		{want: Invalid, ops: map[string]string{"user": "E0"}},
		{want: Invalid, ops: map[string]string{"user": "EINVAL"}},
		{want: Invalid, facts: []string{FactAuditSetEnabled + "=2,3"}},
		{want: Invalid, facts: []string{FactAuditSetEnabled + "=2,9"}},
		{want: Miss, facts: []string{FactAuditSetEnabled + "=2,0"}},
		{want: Miss, ops: map[string]string{"enabled": "ok"}},
		{want: Miss, ops: map[string]string{"rule_add": "ok"}},
		{want: Miss, ops: map[string]string{"equiv": "ok"}},
		{want: Miss, ops: map[string]string{"pid": "ok"}},
		{want: Miss, ops: map[string]string{"user": "ok"}},
		{want: Miss, ops: map[string]string{"get": "EPERM", "trim": "ok"}},
		{want: Miss, facts: []string{FactAuditSetEnabled + "=2,1"}},
		{want: Invalid, ops: map[string]string{"get": "EPERM"}},
		{want: Invalid, ops: map[string]string{"failure": "EINVAL"}},
		{want: Invalid, ops: map[string]string{"backlog": "timeout"}},
		{want: Invalid, ops: map[string]string{"lost": "timeout"}},
		{want: Invalid, ops: map[string]string{"feature": "EINVAL"}},
		{want: Invalid, ops: map[string]string{"pid": "timeout"}},
		{want: Invalid, ops: map[string]string{"user": "timeout"}},
		{want: Invalid, ops: map[string]string{"trim": "eperm"}},
		{want: Invalid, ops: map[string]string{"trim": "E"}},
		{want: Invalid, ops: map[string]string{"trim": "EPERM;x"}},
		{want: Invalid, facts: []string{FactAuditSetEnabled + "=1,1"}},
		{want: Invalid, facts: []string{FactAuditSetEnabled + "=2,"}},
		{want: Invalid, facts: []string{FactAuditSetEnabled + "=2,22"}},
		{want: Invalid, facts: []string{FactAuditSetEnabled + "=2"}},
		{want: Invalid, facts: []string{FactAuditSetUser + "=root"}},
		{want: Invalid, facts: []string{FactAuditSetCaps + "=0000000040000000,0000000040000000,0000000000000000"}},
		{want: Invalid, facts: []string{FactAuditSetCaps + "=000001ffffffffff,000001ffffffffff,0000000040000000"}},
		{want: Invalid, facts: []string{FactAuditSet}},
		{want: Invalid, facts: []string{"extra=1"}},
		{want: Invalid, facts: []string{FactKernel + "=6.0.0"}},
	}
	for _, c := range cases {
		if v, r := JudgeTrial(tr, auditSetRun(c.ops, c.facts...), cleanBuild, cleanBuild); v != c.want {
			t.Errorf("ops %v facts %v: %s (%s); want %s", c.ops, c.facts, v, r, c.want)
		}
	}
}

// The child's line is exactly AuditSetOps, in order, each once.
func TestAuditSetResultsRefuseAnotherShape(t *testing.T) {
	good := auditSetRun(nil).Facts
	var line string
	for _, f := range good {
		if f.Name == FactAuditSet {
			line = f.Value
		}
	}
	if _, err := auditSetResults(line); err != nil {
		t.Fatalf("sound line: %v", err)
	}
	for _, bad := range []string{
		"", line + ",get=ok", strings.Replace(line, "get=ok,enabled=EPERM", "enabled=EPERM,get=ok", 1),
		strings.Replace(line, "trim=", "trim==", 1), strings.Replace(line, "user=EPERM", "tty=EPERM", 1),
		strings.Replace(line, "lost=ok", "lost", 1),
	} {
		if _, err := auditSetResults(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
