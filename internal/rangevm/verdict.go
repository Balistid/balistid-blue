package rangevm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
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
	FactJobExit      = "job_exit" // a signal for signal or core-dump; timeout, oom-kill: a signal or the exit
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

// Limits of an exec job's report, shared with the guest: the results disk holds 16 MiB, and base64
// adds a third. Output and Laurel records travel as base64 chunks of JobChunk raw bytes, the last
// one shorter.
const (
	JobChunk     = 32 << 10
	JobOutCap    = 2 << 20
	JobLaurelCap = 6 << 20
)

// ExecResult is the judged report of an exec job. Only Verdict == Ran is a complete report on the
// target kernel; the zero value is no verdict, and UNKNOWN carries the data for the agent but is
// not a run. Out and Laurel are the decoded bytes the program and Laurel wrote, which a caller
// stores or shows only through Printable (ADR 0011, point 7). Result and Exit are systemd's record
// of the program, set for RAN and UNKNOWN.
type ExecResult struct {
	Verdict string
	Reason  string
	Result  string
	Exit    int
	Out     []byte
	OutCut  bool
	Laurel  []byte
}

// ExecReport checks that facts are the report of an exec job of the program with sha256 want:
// only exec facts, each single fact once, the guest's hash equal to want, a result systemd
// recorded for a program that started (systemd's own exec and setup failures are exit-code 200 and
// above, which a program cannot be told apart from) with an exit status in that result's range,
// the canary seen, the whole Laurel window from one file, uncut, and output and Laurel records as
// canonical base64 in full chunks within their caps. Anything else is INVALID; another kernel is
// UNKNOWN. Every value comes from a guest the agent ran code in (T30), so none is trusted further
// than these checks and none is quoted unescaped.
func ExecReport(facts []Record, want [sha256.Size]byte) ExecResult {
	invalid := func(reason string) ExecResult { return ExecResult{Verdict: Invalid, Reason: reason} }
	single := map[string]string{}
	var out, laurel []string
	for _, f := range facts {
		switch f.Name {
		case FactJobOut:
			out = append(out, f.Value)
		case FactJobLaurel:
			laurel = append(laurel, f.Value)
		case FactJobError:
			return invalid("the guest could not run the job")
		case FactKernel, FactJobSHA256, FactJobResult, FactJobExit, FactJobOutCut, FactJobLaurelCut, "canary":
			if _, dup := single[f.Name]; dup {
				return invalid(fmt.Sprintf("fact %s reported twice", f.Name))
			}
			single[f.Name] = f.Value
		default:
			return invalid(fmt.Sprintf("unexpected fact \"%s\" in an exec report", Printable(f.Name, 64)))
		}
	}
	if len(single) != 7 {
		return invalid(fmt.Sprintf("exec report has %d of 7 facts", len(single)))
	}
	exit, ok := exitStatus(single[FactJobResult], single[FactJobExit])
	switch {
	case single[FactJobSHA256] != hex.EncodeToString(want[:]):
		return invalid("the guest ran another program than the job disk's")
	case !ok:
		return invalid("systemd's record does not show that the program ran")
	case single["canary"] != "seen" || single[FactJobLaurelCut] != "no":
		return invalid("the Laurel window may be incomplete")
	}
	outBytes, err := chunks(out, JobOutCap)
	if err != nil {
		return invalid("job output: " + err.Error())
	}
	laurelBytes, err := chunks(laurel, JobLaurelCap)
	if err != nil {
		return invalid("Laurel records: " + err.Error())
	}
	// The guest marks output cut only once it filled the cap, so "yes" with less is not its report.
	cut := single[FactJobOutCut]
	if cut != "no" && (cut != "yes" || len(outBytes) != JobOutCap) {
		return invalid("job output is marked cut inconsistently")
	}
	res := ExecResult{Result: single[FactJobResult], Exit: exit, Out: outBytes, OutCut: cut == "yes", Laurel: laurelBytes}
	if single[FactKernel] != TargetKernel {
		res.Verdict, res.Reason = Unknown, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(single[FactKernel], 128), TargetKernel)
		return res
	}
	res.Verdict, res.Reason = Ran, "the job ran; its output and Laurel records are the agent's to judge"
	return res
}

// exitStatus allows only the systemd results of a program that started, each with the status range
// it can carry: success with 0, its own exit below 200 (systemd's exec and setup failures use 200
// and above), a signal or core dump with a signal number, and a timeout or OOM kill with whatever
// the program's end left (a signal number, or its own exit if it handled SIGTERM). The status must
// be a plain decimal number; any other result, such as resources, is refused. systemd reports
// exit-code only for an unclean exit, so its status is never 0.
func exitStatus(result, status string) (int, bool) {
	n, err := strconv.Atoi(status)
	if err != nil || strconv.Itoa(n) != status {
		return 0, false
	}
	switch result {
	case "success":
		return n, n == 0
	case "exit-code":
		return n, n >= 1 && n < 200
	case "signal", "core-dump":
		return n, n >= 1 && n <= 64
	case "timeout", "oom-kill":
		return n, n >= 0 && n <= 255
	}
	return 0, false
}

// chunks decodes base64 chunks of the guest's encoding: each canonical (re-encoding gives the same
// text, so no line breaks, which even strict decoding skips, and no other spelling of the bytes),
// every chunk but the last exactly JobChunk bytes, none empty, and the total within limit.
func chunks(values []string, limit int) ([]byte, error) {
	var data []byte
	for i, v := range values {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || base64.StdEncoding.EncodeToString(b) != v {
			return nil, fmt.Errorf("chunk %d is not canonical base64", i)
		}
		if len(b) == 0 || len(b) > JobChunk || (i < len(values)-1 && len(b) != JobChunk) {
			return nil, fmt.Errorf("chunk %d has %d bytes", i, len(b))
		}
		if len(data)+len(b) > limit {
			return nil, fmt.Errorf("over %d bytes", limit)
		}
		data = append(data, b...)
	}
	return data, nil
}

// Printable returns s with every byte outside printable ASCII, the backslash and the double quote
// written as \xNN, cut to at most limit bytes of output, so text a guest or agent chose cannot
// carry terminal escapes, line breaks or look-alike characters into a log line or a result someone
// reads, nor end the quotes it is put in.
func Printable(s string, limit int) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(min(4*len(s), max(limit, 0)))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e && c != '\\' && c != '"' {
			if b.Len()+1 > limit {
				break
			}
			b.WriteByte(c)
			continue
		}
		if b.Len()+4 > limit {
			break
		}
		b.WriteString(`\x`)
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0xf])
	}
	return b.String()
}
