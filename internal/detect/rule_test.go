package detect

import (
	"encoding/json"
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

// TestLeavesOnSyntheticEvents pins ADR 0079 point 4 where the real window has no example.
func TestLeavesOnSyntheticEvents(t *testing.T) {
	ev := func(js string) object {
		v, err := decode([]byte(js), false)
		if err != nil {
			t.Fatal(err)
		}
		return v.(object)
	}
	for _, c := range []struct {
		event, rule string
		want        bool
	}{
		{`{"a":[null]}`, `{"any":[{"field":["a"],"op":"has"}]}`, true},
		{`{"a":[]}`, `{"any":[{"field":["a"],"op":"has"}]}`, false},
		{`{"a":null}`, `{"any":[{"field":["a"],"op":"has"}]}`, false},
		{`{"a":[[]]}`, `{"any":[{"field":["a"],"op":"has"}]}`, true},
		{`{"a":[{"b":null},{"b":1}]}`, `{"any":[{"field":["a","b"],"op":"has"}]}`, true},
		{`{"a":[{"b":null}]}`, `{"any":[{"field":["a","b"],"op":"has"}]}`, false},
		{`{"a":-0}`, `{"any":[{"field":["a"],"op":"eq","value":0}]}`, true},
		{`{"a":1.0}`, `{"any":[{"field":["a"],"op":"eq","value":1}]}`, false},
		{`{"a":[1,2]}`, `{"any":[{"field":["a"],"op":"eq","value":2}]}`, true},
		{`{"a":[[2]]}`, `{"any":[{"field":["a"],"op":"eq","value":2}]}`, true},
		{`{"a":[{"b":"x"},{"c":"y"}]}`, `{"all":[{"field":["a","b"],"op":"eq","value":"x"},{"field":["a","c"],"op":"eq","value":"y"}]}`, true},
		{`{"a":"xyz"}`, `{"any":[{"field":["a"],"op":"contains","value":"y"}]}`, true},
		{`{"a":"xyz"}`, `{"any":[{"field":["a"],"op":"contains","value":"q"}]}`, false},
		{`{"a":{"b":"x"}}`, `{"any":[{"field":["a"],"op":"eq","value":"x"}]}`, false},
		{`{"a":"x"}`, `{"any":[{"field":["a","b"],"op":"has"}]}`, false},
		{`{"a":true}`, `{"any":[{"field":["a"],"op":"eq","value":"true"}]}`, false},
	} {
		if got := ruleOf(t, c.rule).matches([]object{ev(c.event)}); got != c.want {
			t.Errorf("%s on %s: %v, want %v", c.rule, c.event, got, c.want)
		}
	}
	if _, err := decodeRule(object{"any": []any{object{"field": []any{"a"}, "op": "eq", "value": json.Number("-0")}}}); err == nil {
		t.Error("a rule's -0 decoded")
	}
	if (Rule{}).matches(nil) || ControlAll.matches(nil) {
		t.Error("a rule matched no events")
	}
}

func FuzzRule(f *testing.F) {
	f.Add([]byte(reference), []byte(`{"EXECVE":{"ARGV":["uname","-r"]}}`))
	f.Fuzz(func(t *testing.T, rule, event []byte) {
		rv, err := decode(rule, false)
		if err != nil {
			return
		}
		r, err := decodeRule(rv)
		if err != nil {
			return
		}
		ev, err := decode(event, true)
		if o, ok := ev.(object); err == nil && ok {
			a := r.matches([]object{o})
			if a != r.matches([]object{o}) {
				t.Fatal("matching is not deterministic")
			}
			if len(r.Leaves) == 0 && a != r.All {
				t.Fatal("an empty rule did not give its control's answer")
			}
		}
	})
}
