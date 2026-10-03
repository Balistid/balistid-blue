package rangevm

import "testing"

func TestSelftest(t *testing.T) {
	cases := []struct {
		name  string
		facts []Record
		want  string
	}{
		{"isolated guest on the target kernel", []Record{fact(FactKernel, TargetKernel), fact(FactNet, "lo")}, Pass},
		{"guest sees a NIC", []Record{fact(FactKernel, TargetKernel), fact(FactNet, "eth0,lo")}, Fail},
		{"NIC beats kernel mismatch", []Record{fact(FactKernel, "6.1.0"), fact(FactNet, "lo,wlan0")}, Fail},
		{"guest sees nothing at all", []Record{fact(FactKernel, TargetKernel), fact(FactNet, "")}, Fail},
		{"other kernel", []Record{fact(FactKernel, "7.2.8-hardened1-2-hardened"), fact(FactNet, "lo")}, Unknown},
		{"missing net", []Record{fact(FactKernel, TargetKernel)}, Invalid},
		{"no facts", nil, Invalid},
		{"duplicate fact", []Record{fact(FactKernel, TargetKernel), fact(FactNet, "lo"), fact(FactNet, "lo")}, Invalid},
		{"unexpected fact", []Record{fact(FactKernel, TargetKernel), fact(FactNet, "lo"), fact("verdict", Pass)}, Invalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, reason := Selftest(c.facts); got != c.want {
				t.Fatalf("Selftest = %s (%s), want %s", got, reason, c.want)
			}
		})
	}
}
