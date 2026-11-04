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
const ShippedRulesSHA256 = "d78f8f1b23dfbd05f1b4cc121584672f6ca96b81449f7e46a734ce8763269f28"

// Shipped is deploy/audit/balistid.rules as augenrules loads it on the range's kernel, linux 7.2.8 with audit 4.2.1:
// 80 rules: the exec, inject and memfd rules, the canary's watch and ADR 0061's rules (ADR 0059, point 3).
func Shipped() Loaded {
	return Loaded{
		// the self-test's audit_rules in range-kvm run 41873290927 (ba5404b), linux 7.2.8.arch1-2, audit 4.2.1-1
		Rules: Rules{Count: 80, Digest: [32]byte{
			0x07, 0x36, 0x71, 0x22, 0xe1, 0x30, 0xf5, 0x7c, 0x90, 0x49, 0x7f, 0x3c, 0x5e, 0xab, 0x1a, 0xb3,
			0x47, 0x57, 0x74, 0x16, 0x8d, 0x1d, 0xdb, 0xfc, 0xdc, 0x95, 0xaf, 0x43, 0x8c, 0xff, 0x63, 0x6e,
		}},
		Failure: 1, RateLimit: 0, BacklogLimit: 65536, BacklogWaitTime: 60000,
	}
}
