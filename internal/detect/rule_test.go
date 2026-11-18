package detect

import (
	"strings"
	"testing"
)

func ruleOf(t *testing.T, js string) Rule {
	t.Helper()
	v, err := decode([]byte(js), false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeRule(v)
	if err != nil {
		t.Fatalf("%s: %v", js, err)
	}
	return r
}

// TestRulesOnTheBaseWindow walks the false-verdict paths of a rule on the real window (ADR 0078 point 4,
// ADR 0079 points 4 and 5).
func TestRulesOnTheBaseWindow(t *testing.T) {
	w := baseFixture(t).judge(t)
	for _, c := range []struct {
		name, rule string
		want       Verdict
	}{
		{"a leaf on a list element", `{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"}]}`, Caught},
		{"all on one event", `{"all":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"},{"field":["EXECVE","ARGV"],"op":"eq","value":"-r"}]}`, Caught},
		{"all split across two events", `{"all":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"},{"field":["EXECVE","ARGV"],"op":"eq","value":"id"}]}`, Missed},
		{"any split across two events", `{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"},{"field":["EXECVE","ARGV"],"op":"eq","value":"id"}]}`, Caught},
		{"a root event is not the job's", `{"any":[{"field":["EXECVE","ARGV"],"op":"contains","value":"User=balistid-job"}]}`, Missed},
		{"the canary is not the job's", `{"any":[{"field":["EXECVE","ARGV"],"op":"contains","value":"balistid-canary-"}]}`, Missed},
		{"an integer equals an integer", `{"any":[{"field":["SYSCALL","uid"],"op":"eq","value":970}]}`, Caught},
		{"a string is not an integer", `{"any":[{"field":["SYSCALL","uid"],"op":"eq","value":"970"}]}`, Missed},
		{"an integer is not a string", `{"any":[{"field":["SYSCALL","UID"],"op":"eq","value":970}]}`, Missed},
		{"contains takes strings only", `{"any":[{"field":["SYSCALL","uid"],"op":"contains","value":"97"}]}`, Missed},
		{"has on a value", `{"any":[{"field":["SYSCALL","exe"],"op":"has"}]}`, Caught},
		{"has on a missing key", `{"any":[{"field":["SYSCALL","nope"],"op":"has"}]}`, Missed},
		{"a path through a missing object", `{"any":[{"field":["NOPE","exe"],"op":"eq","value":"x"}]}`, Missed},
		{"keys are exact case", `{"any":[{"field":["syscall","exe"],"op":"has"}]}`, Missed},
		{"empty any", `{"any":[]}`, Missed},
		{"empty all", `{"all":[]}`, Caught},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := verdict(ruleOf(t, c.rule), w); got != c.want {
				t.Fatalf("%s: %s, want %s", c.rule, got, c.want)
			}
		})
	}
}

func TestTwinVerdicts(t *testing.T) {
	w := baseFixture(t).judge(t)
	w.Run = "twin-a"
	if got := verdict(ruleOf(t, `{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"uname"}]}`), w); got != Noisy {
		t.Fatalf("a match on a twin: %s, want NOISY", got)
	}
	if got := verdict(ControlEmpty, w); got != Quiet {
		t.Fatalf("no match on a twin: %s, want QUIET", got)
	}
}

func TestRulesThatDoNotDecode(t *testing.T) {
	for _, js := range []string{
		`{"all":[],"any":[]}`,
		`{"ANY":[]}`,
		`{"any":{}}`,
		`{"any":[{"field":["a"],"op":"regex","value":"x"}]}`,
		`{"any":[{"field":["a"],"op":"has","value":"x"}]}`,
		`{"any":[{"field":["a"],"op":"eq"}]}`,
		`{"any":[{"field":["a"],"op":"contains"}]}`,
		`{"any":[{"field":["a"],"op":"contains","value":1}]}`,
		`{"any":[{"field":["a"],"op":"eq","value":1.5}]}`,
		`{"any":[{"field":["a"],"op":"eq","value":1e3}]}`,
		`{"any":[{"field":["a"],"op":"eq","value":true}]}`,
		`{"any":[{"field":[],"op":"has"}]}`,
		`{"any":[{"field":[""],"op":"has"}]}`,
		`{"any":[{"field":"a","op":"has"}]}`,
		`{"any":[{"field":["a"],"op":"has","extra":1}]}`,
		`{"any":[{"Field":["a"],"op":"has"}]}`,
	} {
		v, err := decode([]byte(js), false)
		if err != nil {
			continue
		}
		if _, err := decodeRule(v); err == nil {
			t.Errorf("%s decoded", js)
		}
	}
}

func TestStrictDecode(t *testing.T) {
	for _, c := range []struct {
		in      string
		sameDup bool
		ok      bool
	}{
		{`{"a":1}`, false, true},
		{`{"a":1}{"b":2}`, false, false},
		{`{"a":1,"a":1}`, false, false},
		{`{"a":1,"a":1}`, true, true},
		{`{"a":1,"a":2}`, true, false},
		{`{"a":{"b":[1,"x"]},"a":{"b":[1,"x"]}}`, true, true},
		{`{"a":{"b":[1,"x"]},"a":{"b":[1,"y"]}}`, true, false},
		{`{"a":[1],"a":[1,2]}`, true, false},
		{`{"a":null,"a":false}`, true, false},
		{"{\"a\":\"\xff\"}", false, false},
		{`[1,`, false, false},
	} {
		_, err := decode([]byte(c.in), c.sameDup)
		if (err == nil) != c.ok {
			t.Errorf("decode(%q, %v): err %v, want ok %v", c.in, c.sameDup, err, c.ok)
		}
	}
}

func TestEscapeRoundTrip(t *testing.T) {
	for _, c := range []struct {
		file string
		ok   bool
	}{
		{`a\x0ab`, true},
		{`\x5c\x22`, true},
		{`\x0A`, false},
		{`\x41`, false},
		{"a\n", false},
		{`"`, false},
		{`\`, false},
		{`\x`, false},
		{`\x0`, false},
		{"\x7f", false},
		{"é", false},
	} {
		if _, ok := unescape([]byte(c.file)); ok != c.ok {
			t.Errorf("unescape(%q) ok %v, want %v", c.file, ok, c.ok)
		}
	}
	if got := string(escape([]byte("a\"\\\n\x7f"))); got != `a\x22\x5c\x0a\x7f` {
		t.Fatalf("escape: %s", got)
	}
	if !strings.HasPrefix(string(escape([]byte{0})), `\x00`) {
		t.Fatal("escape of NUL")
	}
}
