package detect

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestTheBaseFixtureIsValid(t *testing.T) {
	w := baseFixture(t).judge(t)
	if !w.Valid() || w.Pair != fixturePair || w.Run != "tech-a" || len(w.Hash) != 32 {
		t.Fatalf("base window: %+v", w)
	}
	if len(w.events) != 3 {
		t.Fatalf("job events %d, want the program, uname and id", len(w.events))
	}
}

func replaceOnce(t *testing.T, b []byte, old, repl string) []byte {
	t.Helper()
	if !bytes.Contains(b, []byte(old)) {
		t.Fatalf("%q not found", old)
	}
	return bytes.Replace(b, []byte(old), []byte(repl), 1)
}

// records sets the window's records to raw, its result rebuilt for raw's length when fixBytes is set.
func (f *fixture) records(t *testing.T, raw []byte, fixBytes bool) {
	t.Helper()
	if fixBytes {
		f.window = f.windowFor(t, "tech-a", raw)
		return
	}
	f.window[LaurelFile] = escape(raw)
}

// lines edits the base records line by line; edit returns the new line.
func lines(t *testing.T, edit func(i int, l []byte) []byte) []byte {
	t.Helper()
	ls := bytes.SplitAfter(baseRecords(t), []byte("\n"))
	for i := range ls {
		ls[i] = edit(i, ls[i])
	}
	return bytes.Join(ls, nil)
}

const programArgv = `"/bin/sh","/run/balistid-job/program"`

func onProgramLine(t *testing.T, old, repl string) []byte {
	t.Helper()
	return lines(t, func(_ int, l []byte) []byte {
		if bytes.Contains(l, []byte(programArgv)) {
			return replaceOnce(t, l, old, repl)
		}
		return l
	})
}

func onCanaryLine(t *testing.T, old, repl string) []byte {
	t.Helper()
	return lines(t, func(_ int, l []byte) []byte {
		if bytes.Contains(l, []byte("balistid-canary-")) {
			return replaceOnce(t, l, old, repl)
		}
		return l
	})
}

// repeatPID changes the second `pid` of one SPAWNED_BY object to another value of the same length.
func repeatPID(t *testing.T, raw []byte) []byte {
	t.Helper()
	re := regexp.MustCompile(`"SPAWNED_BY":\{[^}]*"pid":([0-9]+)[^}]*"pid":([0-9]+)`)
	loc := re.FindSubmatchIndex(raw)
	if loc == nil {
		t.Fatal("no SPAWNED_BY with two pids")
	}
	out := append([]byte{}, raw...)
	last := loc[5] - 1
	if out[last] == '0' {
		out[last] = '1'
	} else {
		out[last] = '0'
	}
	return out
}

func flipFirstHex(t *testing.T, b []byte, key string) []byte {
	t.Helper()
	i := bytes.Index(b, []byte(`"`+key+`": "`))
	if i < 0 {
		t.Fatalf("%s not found", key)
	}
	i += len(`"` + key + `": "`)
	out := append([]byte{}, b...)
	if out[i] == '0' {
		out[i] = '1'
	} else {
		out[i] = '0'
	}
	return out
}

type reasonCase struct {
	name   string
	want   Reason
	mutate func(t *testing.T, f *fixture)
}

func res(old, repl string) func(*testing.T, *fixture) {
	return func(t *testing.T, f *fixture) { f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], old, repl) }
}

func recs(edit func(t *testing.T) []byte) func(*testing.T, *fixture) {
	return func(t *testing.T, f *fixture) {
		r := edit(t)
		if len(r) != len(baseRecords(t)) || bytes.Equal(r, baseRecords(t)) {
			t.Fatal("the edit must change the records and keep their length")
		}
		f.records(t, r, false)
	}
}

func reasonCases() []reasonCase {
	return []reasonCase{
		{"a key in another case", ReasonResultDecode, res(`"label"`, `"Label"`)},
		{"result.json missing", ReasonResultDecode, func(_ *testing.T, f *fixture) { delete(f.window, ResultFile) }},
		{"result.json over its cap", ReasonResultDecode, func(_ *testing.T, f *fixture) {
			f.window[ResultFile] = append(f.window[ResultFile], bytes.Repeat([]byte(" "), resultCap)...)
		}},
		{"two JSON values", ReasonResultDecode, func(_ *testing.T, f *fixture) { f.window[ResultFile] = append(f.window[ResultFile], []byte("{}")...) }},
		{"a key the runner never writes", ReasonResultDecode, res(`"label": "agent",`, `"label": "agent", "extra": 1,`)},
		{"schema 2", ReasonSchema, res(`"schema_version": 1`, `"schema_version": 2`)},
		{"label evidence", ReasonLabel, res(`"label": "agent"`, `"label": "evidence"`)},
		{"kind run", ReasonKind, res(`"kind": "exec"`, `"kind": "run"`)},
		{"no program fields", ReasonKind, res(`"program": "prog.sh",`, ``)},
		{"two runs", ReasonRuns, res("    }\n  ]\n}", "    },\n    {\"verdict\": \"RAN\", \"reason\": \"x\"}\n  ]\n}")},
		{"top verdict not RAN", ReasonNotRan, res(`"verdict": "RAN"`, `"verdict": "INVALID"`)},
		{"run verdict not RAN", ReasonNotRan, res("\"verdict\": \"RAN\",\n      \"reason\"", "\"verdict\": \"INVALID\",\n      \"reason\"")},
		{"exit 1", ReasonJobFailed, res(`"job_exit": 0`, `"job_exit": 1`)},
		{"exit absent", ReasonJobFailed, res(`"job_exit": 0,`, ``)},
		{"job result failed", ReasonJobFailed, res(`"job_result": "success"`, `"job_result": "failed"`)},
		{"another image sha", ReasonImage, res(`"image_sha256": "693e`, `"image_sha256": "693f`)},
		{"another image commit", ReasonImage, res(`"image_commit": "2c09`, `"image_commit": "3c09`)},
		{"another runner", ReasonImage, res(`"runner_commit": "2c09`, `"runner_commit": "3c09`)},
		{"directory of another id", ReasonDirectory, func(_ *testing.T, f *fixture) { f.dir = strings.Replace(f.dir, "120000z", "120001z", 1) }},
		{"an id of another grammar", ReasonDirectory, func(t *testing.T, f *fixture) {
			f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], `"id": "`+strings.TrimSuffix(fixtureStamp, "-"), `"id": "20261118T120000Z-0123ABCD`)
		}},
		{"result before the anchor", ReasonBeforeAnchor, func(t *testing.T, f *fixture) {
			before := "20261117T164346Z-4e1197c7-"
			f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], fixtureStamp, before)
			f.dir = strings.Replace(f.dir, strings.ToLower(fixtureStamp), strings.ToLower(before), 1)
		}},
		{"the anchor itself", ReasonBeforeAnchor, func(t *testing.T, f *fixture) {
			at := strings.TrimSuffix(Anchor, "-pr13-run-d4") + "-"
			f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], fixtureStamp, at)
			f.dir = strings.Replace(f.dir, strings.ToLower(fixtureStamp), strings.ToLower(at), 1)
		}},
		{"pair does not decode", ReasonPair, func(_ *testing.T, f *fixture) { f.pair = strings.Replace(f.pair, `"attack"`, `"Attack"`, 1) }},
		{"rule with an unknown op", ReasonRule, func(_ *testing.T, f *fixture) {
			f.rules[fixtureRuleFile] = strings.Replace(fixtureRule, `"op":"eq"`, `"op":"regex"`, 1)
		}},
		{"rule for another brief", ReasonRule, func(_ *testing.T, f *fixture) { f.rules[fixtureRuleFile] = ruleJSON(reference, "another") }},
		{"rule not a .json", ReasonRule, func(_ *testing.T, f *fixture) { f.rules["rules/fix/opus-2.txt"] = fixtureRule }},
		{"a pair nobody wrote", ReasonName, func(t *testing.T, f *fixture) {
			f.window[ResultFile] = bytes.ReplaceAll(f.window[ResultFile], []byte("fix-tech-a-"), []byte("fiz-tech-a-"))
			f.dir = strings.Replace(f.dir, "fix-tech-a-", "fiz-tech-a-", 1)
		}},
		{"a byte added to a rule after the job", ReasonName, func(_ *testing.T, f *fixture) { f.rules[fixtureRuleFile] += " " }},
		{"a rule added after the job", ReasonName, func(_ *testing.T, f *fixture) { f.rules["rules/fix/opus-2.json"] = fixtureRule }},
		{"content key of another request", ReasonContentKey, func(t *testing.T, f *fixture) {
			f.window[ResultFile] = flipFirstHex(t, f.window[ResultFile], "content_key")
		}},
		{"timeout of another request", ReasonContentKey, res(`"timeout_s": 60`, `"timeout_s": 61`)},
		{"another program name", ReasonContentKey, res(`"program": "prog.sh"`, `"program": "prox.sh"`)},
		{"program sha256 of another program", ReasonProgram, func(t *testing.T, f *fixture) {
			f.window[ResultFile] = flipFirstHex(t, f.window[ResultFile], "program_sha256")
		}},
		{"the same program in a second window", ReasonProgramRepeated, func(t *testing.T, f *fixture) {
			other := strings.Replace(f.dir, "120000z", "130000z", 1)
			r := replaceOnce(t, f.window[ResultFile], "T120000Z", "T130000Z")
			f.extra[other] = map[string][]byte{ResultFile: r, LaurelFile: f.window[LaurelFile]}
		}},
		{"records missing", ReasonLaurelFile, func(_ *testing.T, f *fixture) { delete(f.window, LaurelFile) }},
		{"a raw newline in the records", ReasonLaurelEscape, func(_ *testing.T, f *fixture) { f.window[LaurelFile] = append(f.window[LaurelFile], '\n') }},
		{"an upper-case escape", ReasonLaurelEscape, func(t *testing.T, f *fixture) {
			f.window[LaurelFile] = replaceOnce(t, f.window[LaurelFile], `\x0a`, `\x0A`)
		}},
		{"records over the cap", ReasonLaurelCap, func(t *testing.T, f *fixture) {
			f.records(t, append(bytes.Repeat([]byte(" "), LaurelCap), baseRecords(t)...), false)
		}},
		{"a records file over its read cap", ReasonLaurelCap, func(_ *testing.T, f *fixture) {
			f.window[LaurelFile] = bytes.Repeat([]byte("a"), textCap+1)
		}},
		{"laurel_bytes one more", ReasonLaurelBytes, func(t *testing.T, f *fixture) {
			f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], `"laurel_bytes": 11334`, `"laurel_bytes": 11335`)
		}},
		{"laurel_bytes absent", ReasonLaurelBytes, res(`,
      "laurel_bytes": 11334`, ``)},
		{"last line without its LF", ReasonLaurelLine, func(t *testing.T, f *fixture) {
			r := baseRecords(t)
			f.records(t, r[:len(r)-1], true)
		}},
		{"no records at all", ReasonLaurelLine, func(t *testing.T, f *fixture) { f.records(t, nil, true) }},
		{"a line that is a list", ReasonLaurelLine, func(t *testing.T, f *fixture) {
			f.records(t, lines(t, func(i int, l []byte) []byte {
				if i == 1 {
					return []byte("[]\n")
				}
				return l
			}), true)
		}},
		{"a pid repeated with another value", ReasonDuplicateKey, recs(func(t *testing.T) []byte { return repeatPID(t, baseRecords(t)) })},
		{"the program run by another shell", ReasonNoProgramExec, recs(func(t *testing.T) []byte { return onProgramLine(t, `"/bin/sh"`, `"/bin/zz"`) })},
		{"the program's exec failed", ReasonNoProgramExec, recs(func(t *testing.T) []byte { return onProgramLine(t, `"success":"yes"`, `"success":"no!"`) })},
		{"the program's exec another syscall", ReasonNoProgramExec, recs(func(t *testing.T) []byte { return onProgramLine(t, `"syscall":59,`, `"syscall":58,`) })},
		{"the program's exec named otherwise", ReasonNoProgramExec, recs(func(t *testing.T) []byte { return onProgramLine(t, `"SYSCALL":"execve"`, `"SYSCALL":"execvf"`) })},
		{"the program's exec exit 1", ReasonNoProgramExec, recs(func(t *testing.T) []byte { return onProgramLine(t, `"exit":0,`, `"exit":1,`) })},
		{"every job event under another uid", ReasonNoProgramExec, recs(func(t *testing.T) []byte {
			return bytes.ReplaceAll(baseRecords(t), []byte(`,"uid":970,`), []byte(`,"uid":971,`))
		})},
		{"the program's uid alone another", ReasonJobUID, func(t *testing.T, f *fixture) {
			// The program keeps 970; another job event moves, so name and number disagree there.
			f.records(t, lines(t, func(_ int, l []byte) []byte {
				if bytes.Contains(l, []byte(`"ARGV":["uname","-r"]`)) {
					return replaceOnce(t, l, `,"uid":970,`, `,"uid":971,`)
				}
				return l
			}), false)
		}},
		{"a root event under the job's uid", ReasonJobUID, func(t *testing.T, f *fixture) {
			f.records(t, onCanaryLine(t, `,"uid":0,`, `,"uid":970,`), true)
		}},
		{"canary renamed", ReasonNoCanary, recs(func(t *testing.T) []byte {
			return bytes.ReplaceAll(baseRecords(t), []byte("balistid-canary-"), []byte("balistid-canarx-"))
		})},
		{"canary run by another binary", ReasonNoCanary, recs(func(t *testing.T) []byte { return onCanaryLine(t, `"exe":"/usr/bin/true"`, `"exe":"/usr/bin/tru2"`) })},
		{"canary under another user's name", ReasonNoCanary, func(t *testing.T, f *fixture) {
			f.records(t, onCanaryLine(t, `"UID":"root"`, `"UID":"nobody"`), true)
		}},
		{"canary under another uid", ReasonNoCanary, func(t *testing.T, f *fixture) {
			f.records(t, onCanaryLine(t, `,"uid":0,`, `,"uid":5,`), false)
		}},
		{"canary exec failed", ReasonNoCanary, recs(func(t *testing.T) []byte { return onCanaryLine(t, `"success":"yes"`, `"success":"no!"`) })},
		{"canary before the program", ReasonNoCanary, func(t *testing.T, f *fixture) {
			ls := bytes.SplitAfter(baseRecords(t), []byte("\n"))
			var canaryLine []byte
			var rest [][]byte
			for _, l := range ls {
				if bytes.Contains(l, []byte("balistid-canary-")) {
					canaryLine = l
					continue
				}
				rest = append(rest, l)
			}
			f.records(t, append(append([]byte{}, canaryLine...), bytes.Join(rest, nil)...), false)
		}},
	}
}

func TestEachReasonHasAFixture(t *testing.T) {
	covered := map[Reason]bool{}
	for _, c := range reasonCases() {
		t.Run(c.name, func(t *testing.T) {
			f := baseFixture(t)
			c.mutate(t, f)
			w := f.judge(t)
			if w.Reason != c.want {
				t.Fatalf("reason %q, want %q", w.Reason, c.want)
			}
			if w.events != nil {
				t.Fatal("an INVALID window keeps events a rule could match")
			}
		})
		covered[c.want] = true
	}
	for _, r := range Reasons {
		if !covered[r] {
			t.Errorf("reason %q has no fixture", r)
		}
	}
	if len(covered) != len(Reasons) {
		t.Errorf("%d reasons covered, %d in the closed list", len(covered), len(Reasons))
	}
}
