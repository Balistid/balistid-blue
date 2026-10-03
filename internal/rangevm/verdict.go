package rangevm

import "fmt"

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

// Fact names the guest reports. Any other name makes the run INVALID.
const (
	FactKernel = "kernel"
	FactNet    = "net"
)

// Selftest judges a run of the bare range image: the guest must see no network interface but
// loopback and must run the target kernel.
func Selftest(facts []Record) (verdict, reason string) {
	seen := map[string]string{}
	for _, f := range facts {
		if f.Name != FactKernel && f.Name != FactNet {
			return Invalid, fmt.Sprintf("unexpected fact %q", f.Name)
		}
		if _, dup := seen[f.Name]; dup {
			return Invalid, fmt.Sprintf("fact %q reported twice", f.Name)
		}
		seen[f.Name] = f.Value
	}
	kernel, okKernel := seen[FactKernel]
	net, okNet := seen[FactNet]
	if !okKernel || !okNet {
		return Invalid, "guest did not report both kernel and net"
	}
	if net != "lo" {
		return Fail, fmt.Sprintf("guest sees network interfaces %q, want only lo", net)
	}
	if kernel != TargetKernel {
		return Unknown, fmt.Sprintf("guest kernel %q is not the target %q", kernel, TargetKernel)
	}
	return Pass, "no interface but lo, target kernel"
}
