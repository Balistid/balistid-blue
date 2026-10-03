package rangevm

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// passing returns the facts of a run that passes, with overrides applied; an override "-" drops a fact.
func passing(overrides map[string]string) []Record {
	values := map[string]string{FactKernel: TargetKernel}
	for k, v := range expected {
		values[k] = v
	}
	for k, v := range overrides {
		values[k] = v
	}
	var facts []Record
	for k, v := range values {
		if v != "-" {
			facts = append(facts, fact(k, v))
		}
	}
	return facts
}

func TestSelftest(t *testing.T) {
	cases := []struct {
		name  string
		facts []Record
		want  string
	}{
		{"everything right", passing(nil), Pass},
		{"guest sees a NIC", passing(map[string]string{FactNet: "eth0,lo"}), Fail},
		{"NIC without a driver yet", passing(map[string]string{FactPCINet: "0000:00:02.0"}), Fail},
		{"NIC beats kernel mismatch", passing(map[string]string{FactKernel: "6.1.0", FactNet: "lo,wlan0"}), Fail},
		{"guest sees nothing at all", passing(map[string]string{FactNet: ""}), Fail},
		{"other kernel", passing(map[string]string{FactKernel: "7.2.8-hardened1-2-hardened"}), Unknown},
		{"sensor wrong on another kernel", passing(map[string]string{FactKernel: "6.1.0", "canary": "missing"}), Fail},
		{"missing kernel", passing(map[string]string{FactKernel: "-"}), Invalid},
		{"missing sensor fact", passing(map[string]string{"overflow_after": "-"}), Invalid},
		{"no facts", nil, Invalid},
		{"duplicate fact", append(passing(nil), fact(FactNet, "lo")), Invalid},
		{"unexpected fact", append(passing(nil), fact("verdict", Pass)), Invalid},
	}
	for name, want := range expected {
		if name == FactNet || name == FactPCINet {
			continue
		}
		cases = append(cases, struct {
			name  string
			facts []Record
			want  string
		}{"wrong " + name, passing(map[string]string{name: want + "x"}), Fail})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, reason := Selftest(c.facts); got != c.want {
				t.Fatalf("Selftest = %s (%s), want %s", got, reason, c.want)
			}
		})
	}
}

// The expected audit settings must be the ones deploy/audit/kordon.rules loads.
func TestExpectedAuditSettingsMatchTheRules(t *testing.T) {
	rules, err := os.ReadFile("../../deploy/audit/kordon.rules")
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]string{"-b": "audit_backlog_limit", "-r": "audit_rate_limit", "-f": "audit_failure", "-e": "audit_enabled"}
	found := map[string]bool{}
	for _, line := range strings.Split(string(rules), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if name, ok := flags[f[0]]; ok {
				found[name] = true
				if expected[name] != f[1] {
					t.Errorf("%s %s in the rules, verdict expects %s=%q", f[0], f[1], name, expected[name])
				}
			}
		}
	}
	if len(found) != len(flags) {
		t.Fatalf("rules set %d of the %d checked settings", len(found), len(flags))
	}
	conf, err := os.ReadFile("../../range/mkosi.conf")
	if err != nil {
		t.Fatal(err)
	}
	if why := bootAuditProblem(string(conf), expected["audit_backlog_limit"]); why != "" {
		t.Fatal("range/mkosi.conf: " + why)
	}
}

// bootAuditProblem checks the effective KernelCommandLine of the [Content] section, comments
// excluded and continuation lines included: audit=1 and a boot-time backlog equal to the rules' -b
// (ADR 0004), each exactly once.
func bootAuditProblem(conf, backlog string) string {
	var tokens []string
	section, inCmdline := "", false
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#") || trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "["):
			section, inCmdline = trimmed, false
		case line != trimmed && strings.HasPrefix(line, " ") && inCmdline:
			tokens = append(tokens, strings.Fields(trimmed)...)
		default:
			key, value, _ := strings.Cut(trimmed, "=")
			inCmdline = section == "[Content]" && key == "KernelCommandLine"
			if inCmdline {
				tokens = append(tokens, strings.Fields(value)...)
			}
		}
	}
	for _, want := range []string{"audit=1", "audit_backlog_limit=" + backlog} {
		name, _, _ := strings.Cut(want, "=")
		var seen []string
		for _, tok := range tokens {
			if strings.HasPrefix(tok, name+"=") {
				seen = append(seen, tok)
			}
		}
		if len(seen) != 1 || seen[0] != want {
			return fmt.Sprintf("kernel command line has %q, want exactly %s", seen, want)
		}
	}
	return ""
}

func TestBootAuditProblem(t *testing.T) {
	ok := "[Content]\nKernelCommandLine=console=ttyS0 audit=1\n                  audit_backlog_limit=65536 x=y\n"
	cases := map[string]bool{
		ok: true,
		"[Content]\n# audit=1 audit_backlog_limit=65536\nKernelCommandLine=console=ttyS0\n": false,
		"[Content]\nKernelCommandLine=audit=1\n# audit_backlog_limit=65536 \n":              false,
		"[Content]\nKernelCommandLine=audit=0 audit_backlog_limit=65536\n":                  false,
		"[Content]\nKernelCommandLine=audit=1 audit_backlog_limit=64\n":                     false,
		"[Content]\nKernelCommandLine=audit=1 audit_backlog_limit=65536 audit=0\n":          false,
		"[Output]\nKernelCommandLine=audit=1 audit_backlog_limit=65536\n":                   false,
		"[Content]\nPackages=audit=1\n         audit_backlog_limit=65536\n":                 false,
		"[Content]\nKernelCommandLine=audit=1\n    # audit_backlog_limit=65536\n":           false,
		"[Content]\nKernelCommandLine=audit=1\nPackages=x\n    audit_backlog_limit=65536\n": false,
	}
	for conf, valid := range cases {
		if got := bootAuditProblem(conf, "65536"); (got == "") != valid {
			t.Errorf("%q: problem %q, want valid=%v", conf, got, valid)
		}
	}
}
