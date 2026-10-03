package rangevm

import (
	"fmt"
	"slices"
	"strings"
)

// TargetKernel is `uname -r` of the kernel the maintainer runs and the image pins; results from any
// other kernel are UNKNOWN (ADR 0009, point 8). Change it together with the snapshot in range/mkosi.conf.
const TargetKernel = "7.2.8-arch1-2"

// Verdicts of the range self-test.
const (
	Pass    = "PASS"
	Fail    = "FAIL"
	Unknown = "UNKNOWN"
	Invalid = "INVALID"
)

// Fact names the verdict treats specially.
const (
	FactKernel = "kernel"
	FactNet    = "net"
	FactPCINet = "pci_net"
)

// capsLaurel is CAP_DAC_READ_SEARCH (bit 2) and CAP_SYS_PTRACE (bit 19), the only capabilities
// Laurel keeps after dropping root (ADR 0004).
const capsLaurel = "0000000000080004"

// expected is every fact the guest reports besides the kernel, with the one value that passes.
// Isolation: no interface but loopback and no network-class PCI device (present before any driver
// binds, so a slow driver cannot hide a PCI NIC; TestQemuArgv pins that no other device is added).
// Sensor (ADR 0004 smoke test): the loaded audit settings of deploy/audit/kordon.rules, Laurel as
// _laurel with only its two capabilities, a canary through Laurel, -e 2 refusing and recording a
// disable, io_uring refused with a control that the probe tells both states apart, and a
// plugin-queue overflow reported while the kernel loses nothing.
var expected = map[string]string{
	FactNet:                  "lo",
	FactPCINet:               "",
	"audit_enabled":          "2",
	"audit_failure":          "1",
	"audit_backlog_limit":    "65536",
	"audit_rate_limit":       "0",
	"audit_lost":             "0",
	"laurel_user":            "_laurel",
	"laurel_cap_prm":         capsLaurel,
	"laurel_cap_eff":         capsLaurel,
	"laurel_cap_amb":         "0000000000000000",
	"canary":                 "seen",
	"e0_result":              "refused",
	"audit_enabled_after_e0": "2",
	"e0_recorded":            "yes",
	"io_uring_sysctl":        "2",
	"io_uring_off":           "EPERM",
	"io_uring_on":            "EFAULT",
	"io_uring_off_again":     "EPERM",
	"overflow_before":        "no",
	"overflow_after":         "yes",
	"overflow_journal":       "yes",
	"audit_lost_after":       "0",
}

// Selftest judges a run of the range image. Missing, unknown or repeated facts are INVALID; any wrong
// value is FAIL, checked before the kernel, so a visible NIC fails even on another kernel (UNKNOWN
// would hide a broken boundary); all values right on another kernel is UNKNOWN.
func Selftest(facts []Record) (verdict, reason string) {
	seen := map[string]string{}
	for _, f := range facts {
		if _, known := expected[f.Name]; !known && f.Name != FactKernel {
			return Invalid, fmt.Sprintf("unexpected fact %q", f.Name)
		}
		if _, dup := seen[f.Name]; dup {
			return Invalid, fmt.Sprintf("fact %q reported twice", f.Name)
		}
		seen[f.Name] = f.Value
	}
	if _, ok := seen[FactKernel]; !ok || len(seen) != len(expected)+1 {
		return Invalid, fmt.Sprintf("guest reported %d of %d facts", len(seen), len(expected)+1)
	}
	var wrong []string
	for name, want := range expected {
		if seen[name] != want {
			wrong = append(wrong, fmt.Sprintf("%s=%q (want %q)", name, seen[name], want))
		}
	}
	if len(wrong) > 0 {
		slices.Sort(wrong)
		return Fail, strings.Join(wrong, "; ")
	}
	if seen[FactKernel] != TargetKernel {
		return Unknown, fmt.Sprintf("guest kernel %q is not the target %q", seen[FactKernel], TargetKernel)
	}
	return Pass, "isolated guest on the target kernel; every sensor check passed"
}
