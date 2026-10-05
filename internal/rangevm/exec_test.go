package rangevm

import "testing"

func execFacts(edit func(map[string]string)) []Record {
	single := map[string]string{
		FactKernel: TargetKernel, FactJobSHA256: "ab", FactJobResult: "success", FactJobExit: "0",
		FactJobOutCut: "no", FactJobLaurelCut: "no", "canary": "seen",
	}
	if edit != nil {
		edit(single)
	}
	var facts []Record
	for name, value := range single {
		facts = append(facts, Record{SchemaVersion: SchemaVersion, Kind: KindFact, Name: name, Value: value})
	}
	return append(facts,
		Record{SchemaVersion: SchemaVersion, Kind: KindFact, Name: FactJobOut, Value: "aGk="},
		Record{SchemaVersion: SchemaVersion, Kind: KindFact, Name: FactJobLaurel, Value: "e30="},
		Record{SchemaVersion: SchemaVersion, Kind: KindFact, Name: FactJobLaurel, Value: "e30="})
}

func TestExecReport(t *testing.T) {
	if v, r := ExecReport(execFacts(nil), "ab"); v != Ran {
		t.Fatalf("full report: %s %s", v, r)
	}
	cases := map[string]struct {
		facts   []Record
		sha     string
		verdict string
	}{
		"other program":  {execFacts(nil), "cd", Invalid},
		"canary missing": {execFacts(func(m map[string]string) { m["canary"] = "missing" }), "ab", Invalid},
		"fact missing":   {execFacts(func(m map[string]string) { delete(m, FactJobExit) }), "ab", Invalid},
		"no unit result": {execFacts(func(m map[string]string) { delete(m, FactJobResult) }), "ab", Invalid},
		"unit unknown":   {execFacts(func(m map[string]string) { m[FactJobResult] = "unknown" }), "ab", Invalid},
		"log rotated":    {execFacts(func(m map[string]string) { m[FactJobLaurelCut] = "rotated" }), "ab", Invalid},
		"log error":      {execFacts(func(m map[string]string) { m[FactJobLaurelCut] = "error" }), "ab", Invalid},
		"log cut at cap": {execFacts(func(m map[string]string) { m[FactJobLaurelCut] = "yes" }), "ab", Invalid},
		"exit 1":         {execFacts(func(m map[string]string) { m[FactJobResult], m[FactJobExit] = "exit-code", "1" }), "ab", Ran},
		"exit 203":       {execFacts(func(m map[string]string) { m[FactJobResult], m[FactJobExit] = "exit-code", "203" }), "ab", Invalid},
		"exit 200":       {execFacts(func(m map[string]string) { m[FactJobResult], m[FactJobExit] = "exit-code", "200" }), "ab", Invalid},
		"success, 7":     {execFacts(func(m map[string]string) { m[FactJobExit] = "7" }), "ab", Invalid},
		"oom-kill":       {execFacts(func(m map[string]string) { m[FactJobResult], m[FactJobExit] = "oom-kill", "9" }), "ab", Ran},
		"resources":      {execFacts(func(m map[string]string) { m[FactJobResult] = "resources" }), "ab", Invalid},
		"start limit":    {execFacts(func(m map[string]string) { m[FactJobResult] = "start-limit-hit" }), "ab", Invalid},
		"exec condition": {execFacts(func(m map[string]string) { m[FactJobResult] = "exec-condition" }), "ab", Invalid},
		"exit -1":        {execFacts(func(m map[string]string) { m[FactJobResult], m[FactJobExit] = "exit-code", "-1" }), "ab", Invalid},
		"exit garbage":   {execFacts(func(m map[string]string) { m[FactJobResult], m[FactJobExit] = "exit-code", "x" }), "ab", Invalid},
		"timed out":      {execFacts(func(m map[string]string) { m[FactJobResult] = "timeout" }), "ab", Ran},
		"self-test fact": {append(execFacts(nil), Record{Name: "io_uring_off", Value: "EPERM"}), "ab", Invalid},
		"job error":      {append(execFacts(nil), Record{Name: FactJobError, Value: "x"}), "ab", Invalid},
		"sha twice":      {append(execFacts(nil), Record{Name: FactJobSHA256, Value: "ab"}), "ab", Invalid},
		"other kernel":   {execFacts(func(m map[string]string) { m[FactKernel] = "6.1" }), "ab", Unknown},
	}
	for name, c := range cases {
		if verdict, _ := ExecReport(c.facts, c.sha); verdict != c.verdict {
			t.Errorf("%s: %s, want %s", name, verdict, c.verdict)
		}
	}
	// A self-test run never passes with exec facts in it.
	if v, _ := Selftest(execFacts(nil)); v != Invalid {
		t.Errorf("Selftest of an exec report: %s", v)
	}
}
