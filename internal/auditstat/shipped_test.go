package auditstat

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The pin is of the rules file as it stands: a changed file fails here until the pin is renewed from a range run.
func TestShippedPinsTheRulesFile(t *testing.T) {
	b, err := os.ReadFile("../../deploy/audit/balistid.rules")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != ShippedRulesSHA256 {
		t.Fatalf("balistid.rules is %x, the pin is of %s: renew Shipped from the range self-test's audit_rules",
			sum, ShippedRulesSHA256)
	}
	set := map[string]uint32{}
	rules := uint32(0)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 2 && (f[0] == "-f" || f[0] == "-r" || f[0] == "-b" || f[0] == "--backlog_wait_time"):
			v, err := strconv.ParseUint(f[1], 10, 32)
			if err != nil {
				t.Fatalf("%s %s: %v", f[0], f[1], err)
			}
			set[f[0]] = uint32(v)
		case len(f) > 0 && (f[0] == "-a" || f[0] == "-w"):
			rules++
		}
	}
	s := Shipped()
	got := map[string]uint32{"-f": s.Failure, "-r": s.RateLimit, "-b": s.BacklogLimit, "--backlog_wait_time": s.BacklogWaitTime}
	if len(set) != 4 || set["-f"] != got["-f"] || set["-r"] != got["-r"] || set["-b"] != got["-b"] ||
		set["--backlog_wait_time"] != got["--backlog_wait_time"] || s.Rules.Count != rules {
		t.Errorf("the rules file sets %v and %d rules, Shipped pins %v and %d", set, rules, got, s.Rules.Count)
	}
}

// A report's Loaded is its rules and the four status fields a rules file sets, nothing the kernel counts.
func TestLoadedIsWhatTheRulesFileSets(t *testing.T) {
	r := Report{Seq: 9, Status: sample, Rules: sampleRules}
	want := Loaded{Rules: sampleRules, Failure: 1, RateLimit: 0, BacklogLimit: 65536, BacklogWaitTime: 60000}
	if r.Loaded() != want {
		t.Fatalf("loaded %+v, want %+v", r.Loaded(), want)
	}
	r.Status.Lost, r.Status.Backlog, r.Status.PID, r.Status.BacklogWaitTimeActual, r.Seq = 99, 99, 99, 99, 10
	if r.Loaded() != want {
		t.Errorf("a count changed what is loaded: %+v", r.Loaded())
	}
}
