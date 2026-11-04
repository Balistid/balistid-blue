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
// seven rules, six syscall rules and the canary's watch (ADR 0059, point 3).
func Shipped() Loaded {
	return Loaded{
		// the self-test's audit_rules in range-kvm run 41770932438 (f8a6832), linux 7.2.8.arch1-2, audit 4.2.1-1
		Rules: Rules{Count: 22, Digest: [32]byte{
			0x3f, 0x86, 0x31, 0x7d, 0xcd, 0x19, 0x2a, 0xc7, 0x96, 0xf9, 0xb8, 0xd9, 0xb3, 0x15, 0xa7, 0x4e,
			0x49, 0xe4, 0x56, 0x02, 0x09, 0x12, 0x33, 0x35, 0x28, 0xc7, 0x98, 0x02, 0xc4, 0x8c, 0x1b, 0x7a,
		}},
		Failure: 1, RateLimit: 0, BacklogLimit: 65536, BacklogWaitTime: 60000,
	}
}
