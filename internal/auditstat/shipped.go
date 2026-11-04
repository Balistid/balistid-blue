package auditstat

// Loaded is what the kernel holds of a rules file: its rule list and the status fields the file sets (-f, -r, -b,
// --backlog_wait_time). A report says what is loaded; Shipped says what must be (ADR 0059, point 3).
type Loaded struct {
	Rules                                             Rules
	Failure, RateLimit, BacklogLimit, BacklogWaitTime uint32
}

// Loaded is what r reports loaded.
func (r Report) Loaded() Loaded {
	s := r.Status
	return Loaded{Rules: r.Rules, Failure: s.Failure, RateLimit: s.RateLimit, BacklogLimit: s.BacklogLimit,
		BacklogWaitTime: s.BacklogWaitTime}
}

// ShippedRulesSHA256 is the SHA-256 of deploy/audit/balistid.rules that Shipped pins: a test fails when the file
// changes until both are renewed, the digest from the range self-test's audit_rules fact.
const ShippedRulesSHA256 = "94358bbaa57c084472581991bd08ff61b9ac1f899d0b873ada9fd122137e1e5e"

// Shipped is deploy/audit/balistid.rules as augenrules loads it on the range's kernel, linux 7.2.8 with audit 4.2.1:
// 64 rules: the exec, inject and memfd rules, the canary's watch and ADR 0061's rules (ADR 0059, point 3).
func Shipped() Loaded {
	return Loaded{
		// the self-test's audit_rules in range-kvm run 41792174384 (ef72118), linux 7.2.8.arch1-2, audit 4.2.1-1
		Rules: Rules{Count: 64, Digest: [32]byte{
			0x01, 0x96, 0xc2, 0x32, 0xd7, 0x43, 0x9d, 0x4b, 0xcb, 0x07, 0x15, 0x02, 0x23, 0x77, 0x7b, 0x94,
			0xce, 0x8e, 0x01, 0xa0, 0x52, 0xe6, 0x20, 0xa4, 0x15, 0x39, 0x72, 0xb1, 0xf5, 0xac, 0x74, 0xe2,
		}},
		Failure: 1, RateLimit: 0, BacklogLimit: 65536, BacklogWaitTime: 60000,
	}
}
