package rangeguest

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAuditStatus(t *testing.T) {
	out := "enabled 2\nfailure 1\npid 312\nrate_limit 0\nbacklog_limit 65536\nlost 0\nbacklog 0\nbacklog_wait_time 60000\n"
	got := AuditStatus(out)
	for k, want := range map[string]string{"enabled": "2", "failure": "1", "backlog_limit": "65536", "rate_limit": "0", "lost": "0"} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	if len(AuditStatus("")) != 0 {
		t.Error("empty output produced fields")
	}
}

const status = "Name:\tlaurel\nPPid:\t312\nUid:\t977\t977\t977\t977\nCapInh:\t0000000000080004\nCapPrm:\t0000000000080004\nCapEff:\t0000000000080004\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n"

func TestCaps(t *testing.T) {
	prm, eff, amb := Caps(status)
	if prm != "0000000000080004" || eff != "0000000000080004" || amb != "0000000000000000" {
		t.Fatalf("Caps = %s %s %s", prm, eff, amb)
	}
	if p, e, a := Caps("Name:\tlaurel\n"); p != "missing" || e != "missing" || a != "missing" {
		t.Fatalf("Caps without fields = %s %s %s", p, e, a)
	}
}

func TestStatusFieldAndUserName(t *testing.T) {
	if StatusField(status, "PPid") != "312" || StatusField(status, "Uid") != "977\t977\t977\t977" || StatusField(status, "Nope") != "" {
		t.Fatal("StatusField")
	}
	passwd := "root:x:0:0::/root:/bin/bash\n_laurel:x:977:977:Laurel:/var/log/laurel:/usr/bin/nologin\n" //nolint:gosec // an /etc/passwd fixture, no secret
	if UserName(passwd, "977") != "_laurel" || UserName(passwd, "1000") != "" {
		t.Fatal("UserName")
	}
}

func TestHasExecArg(t *testing.T) {
	log := `{"ID":"1:2","SYSCALL":{"syscall":"execve"},"EXECVE":{"argc":2,"ARGV":["/usr/bin/true","balistid-canary-ab"]}}
not json
{"ID":"1:3","EXECVE":{"argc":2,"ARGV":["/usr/bin/echo","balistid-canary-abc-other"]}}
`
	if !HasExecArg(strings.NewReader(log), "balistid-canary-ab") {
		t.Fatal("token in ARGV not found")
	}
	for _, miss := range []string{"balistid-canary-a", "balistid-canary-zz"} {
		if HasExecArg(strings.NewReader(log), miss) {
			t.Fatalf("%q matched; only a whole argv element may match", miss)
		}
	}
	// The token anywhere else in an event is not an exec of it.
	if HasExecArg(strings.NewReader(`{"PROCTITLE":{"ARGV":["balistid-canary-x"]},"note":"balistid-canary-x"}`), "balistid-canary-x") {
		t.Fatal("matched outside EXECVE")
	}
}

// Shapes as Laurel 0.8.2 wrote them in the range on 2026-10-03: CONFIG_CHANGE is a list.
func TestHasRefusedDisable(t *testing.T) {
	cases := map[string]bool{
		`{"ID":"1:130","CONFIG_CHANGE":[{"op":"set","audit_enabled":0,"old":"2","auid":4294967295,"ses":4294967295,"res":0,"AUID":"unset"}]}`: true,
		`{"ID":"1:130","CONFIG_CHANGE":[{"op":"set","audit_enabled":"0","old":"2","res":"0"}]}`:                                               true,
		`{"ID":"1:130","CONFIG_CHANGE":[{"op":"set","audit_backlog_limit":65536,"old":"d","res":1},{"op":"set","audit_enabled":0,"res":0}]}`:  true,
		`{"ID":"1:130","CONFIG_CHANGE":[{"op":"set","audit_enabled":0,"old":"2","res":1}]}`:                                                   false,
		`{"ID":"1:130","CONFIG_CHANGE":[{"op":"set","audit_enabled":2,"old":"1","res":0}]}`:                                                   false,
		`{"ID":"1:130","CONFIG_CHANGE":{"op":"set","audit_enabled":0,"res":0}}`:                                                               false,
		`{"ID":"1:130","SYSCALL":{"audit_enabled":0,"res":0}}`:                                                                                false,
	}
	for line, want := range cases {
		if got := HasRefusedDisable(strings.NewReader(line + "\n")); got != want {
			t.Errorf("%s: %v, want %v", line, got, want)
		}
	}
}

func TestOverflowDetected(t *testing.T) {
	state := "audit version = 4.2.1\nplugin queue size = 16384\nplugin queue overflow detected = yes\nmax plugin queue depth used = 16384\n"
	if OverflowDetected(state) != "yes" || OverflowDetected("audit version = 4.2.1\n") != "missing" {
		t.Fatal("OverflowDetected")
	}
}

// FuzzParsers feeds the same bytes to every parser; none may panic on what a guest could write.
func FuzzParsers(f *testing.F) {
	f.Add([]byte(`{"EXECVE":{"argc":2,"ARGV":["/usr/bin/true","t"]},"CONFIG_CHANGE":[{"audit_enabled":0,"res":0}]}` + "\n"))
	f.Add([]byte("enabled 2\nCapPrm:\t0000000000080004\nplugin queue overflow detected = yes\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := string(data)
		_ = AuditStatus(s)
		_, _, _ = Caps(s)
		_ = StatusField(s, "Uid")
		_ = UserName(s, "0")
		_ = OverflowDetected(s)
		_ = HasExecArg(bytes.NewReader(data), "t")
		_ = HasRefusedDisable(bytes.NewReader(data))
		_ = HasRuleKey(bytes.NewReader(data), "t")
		_ = LastCommitted(s)
		_, _ = ParseKmsg(s)
		_, _ = AuditLost(s)
	})
}

// A kmsg record gives its sequence, the kernel's time and its first line; the kernel's lost line its count.
func TestParseKmsg(t *testing.T) {
	r, err := ParseKmsg("4,1203,61234567,-;audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=65536\n SUBSYSTEM=x\n")
	if err != nil || r.Seq != 1203 || r.At != 61234567*time.Microsecond || r.Msg != "audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=65536" {
		t.Fatalf("%+v %v", r, err)
	}
	if n, ok := AuditLost(r.Msg); !ok || n != 1 {
		t.Errorf("lost %d %v", n, ok)
	}
	for _, bad := range []string{"", "audit_lost=1", "4,1,2;x", "4,x,2,-;x", "4,1,-2,-;x", "4,1,99999999999999999999,-;x",
		"4,1,9223372036854776,-;x"} {
		if r, err := ParseKmsg(bad); err == nil {
			t.Errorf("%q parsed as %+v", bad, r)
		}
	}
	for _, msg := range []string{"audit: backlog limit exceeded", "audit: audit_lost=", "audit: audit_lost=+1 x",
		"audit: audit_lost=4294967296 x", "x audit: audit_lost=1"} {
		if n, ok := AuditLost(msg); ok {
			t.Errorf("%q read as lost %d", msg, n)
		}
	}
}

// The collector's canary record is found by its rule key, as a string with other keys joined by \x01
// or as a list, and never by the key's text elsewhere in the record.
func TestHasRuleKey(t *testing.T) {
	for line, want := range map[string]bool{
		`{"SYSCALL":{"key":"balistid-canary"}}`:                           true,
		`{"SYSCALL":{"key":"other\u0001balistid-canary"}}`:                true,
		`{"SYSCALL":{"key":["other","balistid-canary"]}}`:                 true,
		`{"SYSCALL":{"key":"balistid-canary-x"}}`:                         false,
		`{"SYSCALL":{"key":"other"},"PATH":[{"name":"balistid-canary"}]}`: false,
		`{"EXECVE":{"ARGV":["/usr/bin/true","balistid-canary"]}}`:         false,
	} {
		if got := HasRuleKey(strings.NewReader(line+"\n"), "balistid-canary"); got != want {
			t.Errorf("%s: %v, want %v", line, got, want)
		}
	}
}
