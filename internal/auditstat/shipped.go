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
const ShippedRulesSHA256 = "4ab57bc2b468c93e74274a6f020a697bc1e99271e419f46a1ce756d4ebef2c4f"

// Shipped is deploy/audit/balistid.rules as augenrules loads it on the range's kernel, linux 7.2.8 with audit 4.2.1:
// 22 rules: the exec, inject and memfd rules, the canary's watch and ADR 0061's rules (ADR 0059, point 3).
func Shipped() Loaded {
	return Loaded{
		// the self-test's audit_rules in range-kvm run 41783225009 (fd8c84a), linux 7.2.8.arch1-2, audit 4.2.1-1
		Rules: Rules{Count: 22, Digest: [32]byte{
			0xd8, 0xb1, 0x0f, 0xbd, 0x43, 0x53, 0x5c, 0x39, 0x49, 0xa8, 0x48, 0xa0, 0x89, 0x04, 0xcc, 0xa5,
			0x46, 0x64, 0xd5, 0x31, 0x14, 0xb7, 0x70, 0xf9, 0x86, 0x7c, 0xd2, 0x8d, 0x22, 0x02, 0xe3, 0x50,
		}},
		Failure: 1, RateLimit: 0, BacklogLimit: 65536, BacklogWaitTime: 60000,
	}
}
