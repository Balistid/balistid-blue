package rangevm

import (
	"fmt"
	"strconv"
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

// Facts of an exec job (ADR 0011): the program's sha256 as the guest decoded it, its exit, and its
// output and the Laurel log written while it ran, as base64 chunks in order. The host matches no
// pattern on them; the agent reads them.
const (
	FactJobSHA256    = "job_sha256"
	FactJobResult    = "job_result"
	FactJobExit      = "job_exit" // a signal number unless job_result is success or exit-code
	FactJobOut       = "job_out"
	FactJobOutCut    = "job_out_truncated"
	FactJobLaurel    = "job_laurel"
	FactJobLaurelCut = "job_laurel_truncated"
	FactJobError     = "job_error"
)

// capsLaurel is CAP_DAC_READ_SEARCH (bit 2) and CAP_SYS_PTRACE (bit 19), the only capabilities
// Laurel keeps after dropping root (ADR 0004).
const capsLaurel = "0000000000080004"

// expected is every fact the guest reports besides the kernel, with the one value that passes.
// Isolation: no interface but loopback and no network-class PCI device (present before any driver
// binds, so a slow driver cannot hide a PCI NIC; TestQemuArgv pins that no other device is added).
// Sensor (ADR 0004 smoke test): the loaded audit settings of deploy/audit/balistid.rules (audit=1 at
// boot is set in the image but not proven at runtime, ADR 0004), Laurel as
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
	"audit_enabled_after_e0": "2",
	"e0_recorded":            "yes",
	"io_uring_sysctl":        "2",
	"io_uring_off":           "EPERM",
	"io_uring_on":            "EFAULT",
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

// Ran is the verdict of an exec job that ran and reported in full. It says nothing about the
// sensor: the agent judges the output and Laurel records itself (ADR 0011, point 7).
const Ran = "RAN"

// ExecReport checks that facts are the report of an exec job of the program with sha256 want:
// only exec facts, each single fact once, the guest's hash equal to want, a result systemd
// recorded for a program that started (systemd's own exec and setup failures are exit-code 200 and
// above, which a program cannot be told apart from), the canary seen and the whole Laurel window
// from one file, uncut. Anything else is INVALID; another kernel is UNKNOWN.
func ExecReport(facts []Record, want string) (verdict, reason string) {
	single := map[string]string{}
	for _, f := range facts {
		switch f.Name {
		case FactJobOut, FactJobLaurel:
		case FactJobError:
			return Invalid, "the guest could not run the job"
		case FactKernel, FactJobSHA256, FactJobResult, FactJobExit, FactJobOutCut, FactJobLaurelCut, "canary":
			if _, dup := single[f.Name]; dup {
				return Invalid, fmt.Sprintf("fact %q reported twice", f.Name)
			}
			single[f.Name] = f.Value
		default:
			return Invalid, fmt.Sprintf("unexpected fact %q in an exec report", f.Name)
		}
	}
	if len(single) != 7 {
		return Invalid, fmt.Sprintf("exec report has %d of 7 facts", len(single))
	}
	switch {
	case single[FactJobSHA256] != want:
		return Invalid, "the guest ran another program than the job disk's"
	case !programRan(single[FactJobResult], single[FactJobExit]):
		return Invalid, "systemd's record does not show that the program ran"
	case single["canary"] != "seen" || single[FactJobLaurelCut] != "no":
		return Invalid, "the Laurel window may be incomplete"
	case single[FactKernel] != TargetKernel:
		return Unknown, fmt.Sprintf("guest kernel %q is not the target %q", single[FactKernel], TargetKernel)
	}
	return Ran, "the job ran; its output and Laurel records are the agent's to judge"
}

// programRan allows only the systemd results of a program that started: success with status 0,
// its own exit below 200 (systemd's exec and setup failures use 200 and above), or its end by a
// signal, core dump, timeout or OOM kill. Any other result, such as resources, is INVALID.
func programRan(result, status string) bool {
	switch result {
	case "success":
		return status == "0"
	case "exit-code":
		return below200(status)
	case "signal", "core-dump", "timeout", "oom-kill":
		return true
	}
	return false
}

func below200(status string) bool {
	n, err := strconv.Atoi(status)
	return err == nil && n >= 0 && n < 200
}
