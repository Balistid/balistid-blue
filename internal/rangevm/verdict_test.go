package rangevm

import (
	"os"
	"slices"
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

// reach is a passing report with one change to pi_reach's value.
func reach(old, replacement string) []Record {
	return passing(map[string]string{"pi_reach": strings.Replace(expected["pi_reach"], old, replacement, 1)})
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
		{"loopback only, no tunnel", passing(map[string]string{FactNet: "lo"}), Fail},
		{"a NIC beside the range's links", passing(map[string]string{FactNet: "balistid-lan,balistid0,eth0,lo"}), Fail},
		{"a uid besides the relay reaches the Pi", reach("job_tcp=timeout", "job_tcp=open"), Fail},
		{"the relay does not reach the Pi", reach("relay_tcp=open", "relay_tcp=timeout"), Fail},
		{"root reaches the Pi", reach("root_tcp=timeout", "root_tcp=open"), Fail},
		{"the endpoint takes an unmarked datagram", reach("job_endpoint=EPERM", "job_endpoint=sent"), Fail},
		{"the job fetches bundles", reach("job_bundles=timeout", "job_bundles=open"), Fail},
		{"the tunnel's input rule refused nothing", reach("tunnel_refused=counted", "tunnel_refused=none"), Fail},
		{"no input rule for the host's address", reach("host_refused=counted", "host_refused=error: no rule"), Fail},
		{"a probe left out", reach(",pi_host_port=timeout", ""), Fail},
		{"a refusal not logged", reach("logged=yes", "logged=missing to-pi-not-relay"), Fail},
		{"an unmarked datagram from WireGuard's port", reach("job_squat=EPERM", "job_squat=sent"), Fail},
		{"the ledger sees the tunnel", passing(map[string]string{"ledger_net": "balistid0,lo"}), Fail},
		{"other kernel", passing(map[string]string{FactKernel: "7.2.8-hardened1-2-hardened"}), Unknown},
		{"sensor wrong on another kernel", passing(map[string]string{FactKernel: "6.1.0", "canary": "missing"}), Fail},
		{"missing kernel", passing(map[string]string{FactKernel: "-"}), Invalid},
		{"missing sensor fact", passing(map[string]string{"overflow_after": "-"}), Invalid},
		{"no facts", nil, Invalid},
		{"duplicate fact", append(passing(nil), fact(FactNet, "balistid-lan,balistid0,lo")), Invalid},
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

// The required facts are pinned here, apart from the expected table, so dropping a requirement from the
// table fails a test instead of silently removing its coverage.
func TestRequiredFactsArePinned(t *testing.T) {
	want := []string{
		FactNet, FactPCINet, "audit_enabled", "audit_failure", "audit_backlog_limit", "audit_rate_limit",
		"audit_lost", "laurel_user", "laurel_cap_prm", "laurel_cap_eff", "laurel_cap_amb", "collector_user",
		"collector_cap_prm", "collector_cap_eff", "collector_cap_amb", "auditstat_user", "auditstat_cap_prm",
		"auditstat_cap_eff", "auditstat_cap_amb", "auditstat_report", "collector_canary", "ledger_anchored", "ledger_cosigned", "fork_refused", "shard_cosigned",
		"announce_cosigned", "suspend_announced", "pi_verified", "pi_reach", "ledger_net", "canary",
		"audit_enabled_after_e0", "e0_recorded", "io_uring_sysctl", "io_uring_off",
		"io_uring_on", "overflow_before", "overflow_after", "overflow_journal", "audit_lost_after",
	}
	got := make([]string, 0, len(expected))
	for k := range expected {
		got = append(got, k)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("required facts changed:\n got %q\nwant %q", got, want)
	}
}

// The expected audit settings must be the ones deploy/audit/balistid.rules loads.
func TestExpectedAuditSettingsMatchTheRules(t *testing.T) {
	rules, err := os.ReadFile("../../deploy/audit/balistid.rules")
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
}
