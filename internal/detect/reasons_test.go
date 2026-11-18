package detect

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func TestTheBaseFixtureIsValid(t *testing.T) {
	w := baseFixture(t).judge(t)
	if !w.Valid() || w.Pair != fixturePair || w.Run != "tech-a" {
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

// records sets the window's records to raw, keeping laurel_bytes as the runner wrote it unless fix is set.
func (f *fixture) records(t *testing.T, raw []byte, fixBytes bool) {
	t.Helper()
	f.window[LaurelFile] = escape(raw)
	if fixBytes {
		f.window = f.rebuilt(t, raw)
	}
}

func (f *fixture) rebuilt(t *testing.T, raw []byte) map[string][]byte {
	t.Helper()
	return f.windowFor(t, "tech-a", raw)
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
	out[last] = map[bool]byte{true: '1', false: '0'}[out[last] == '0']
	return out
}

func TestEachReasonHasOneFixture(t *testing.T) {
	type fx struct {
		name   string
		want   Reason
		mutate func(t *testing.T, f *fixture)
	}
	res := func(old, repl string) func(*testing.T, *fixture) {
		return func(t *testing.T, f *fixture) { f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], old, repl) }
	}
	raw := func(old, repl string) func(*testing.T, *fixture) {
		return func(t *testing.T, f *fixture) {
			r := bytes.ReplaceAll(baseRecords(t), []byte(old), []byte(repl))
			if len(r) != len(baseRecords(t)) || bytes.Equal(r, baseRecords(t)) {
				t.Fatalf("%q -> %q must change the records and keep their length", old, repl)
			}
			f.records(t, r, false)
		}
	}
	cases := []fx{
		{"a key in another case", ReasonResultDecode, res(`"label"`, `"Label"`)},
		{"result.json missing", ReasonResultDecode, func(_ *testing.T, f *fixture) { delete(f.window, ResultFile) }},
		{"two JSON values", ReasonResultDecode, func(_ *testing.T, f *fixture) { f.window[ResultFile] = append(f.window[ResultFile], []byte("{}")...) }},
		{"a key the runner never writes", ReasonResultDecode, res(`"label": "agent",`, `"label": "agent", "extra": 1,`)},
		{"schema 2", ReasonSchema, res(`"schema_version": 1`, `"schema_version": 2`)},
		{"label evidence", ReasonLabel, res(`"label": "agent"`, `"label": "evidence"`)},
		{"kind run", ReasonKind, res(`"kind": "exec"`, `"kind": "run"`)},
		{"two runs", ReasonRuns, res("    }\n  ]\n}", "    },\n    {\"verdict\": \"RAN\", \"reason\": \"x\"}\n  ]\n}")},
		{"top verdict not RAN", ReasonNotRan, res(`"verdict": "RAN"`, `"verdict": "INVALID"`)},
		{"run verdict not RAN", ReasonNotRan, res(`"verdict": "RAN",
      "reason"`, `"verdict": "INVALID",
      "reason"`)},
		{"exit 1", ReasonJobFailed, res(`"job_exit": 0`, `"job_exit": 1`)},
		{"exit absent", ReasonJobFailed, res(`"job_exit": 0,`, ``)},
		{"job result failed", ReasonJobFailed, res(`"job_result": "success"`, `"job_result": "failed"`)},
		{"another image", ReasonImage, res(`"image_sha256": "693e`, `"image_sha256": "693f`)},
		{"directory of another id", ReasonDirectory, func(_ *testing.T, f *fixture) { f.dir = strings.Replace(f.dir, "120000z", "120001z", 1) }},
		{"result before the anchor", ReasonBeforeAnchor, func(t *testing.T, f *fixture) {
			id := strings.TrimPrefix(f.dir, strings.ToLower(fixtureStamp))
			old := fixtureStamp + id
			before := "20261117T164346Z-4e1197c7-" + id
			f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], old, before)
			f.dir = strings.ToLower(before)
		}},
		{"pair does not decode", ReasonPair, func(_ *testing.T, f *fixture) { f.pair = strings.Replace(f.pair, `"attack"`, `"Attack"`, 1) }},
		{"rule with an unknown op", ReasonRule, func(_ *testing.T, f *fixture) {
			f.rules[fixtureRuleFile] = strings.Replace(fixtureRule, `"op":"eq"`, `"op":"regex"`, 1)
		}},
		{"a byte added to a rule after the job", ReasonName, func(_ *testing.T, f *fixture) { f.rules[fixtureRuleFile] += " " }},
		{"a rule added after the job", ReasonName, func(_ *testing.T, f *fixture) { f.rules["rules/fix/opus-2.json"] = fixtureRule }},
		{"content key of another request", ReasonContentKey, func(t *testing.T, f *fixture) {
			r := f.window[ResultFile]
			i := bytes.Index(r, []byte(`"content_key": "`)) + len(`"content_key": "`)
			r[i] = map[bool]byte{true: '1', false: '0'}[r[i] == '0']
		}},
		{"timeout of another request", ReasonContentKey, res(`"timeout_s": 60`, `"timeout_s": 61`)},
		{"program sha256 of another program", ReasonProgram, func(t *testing.T, f *fixture) {
			r := f.window[ResultFile]
			i := bytes.Index(r, []byte(`"program_sha256": "`)) + len(`"program_sha256": "`)
			r[i] = map[bool]byte{true: '1', false: '0'}[r[i] == '0']
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
		{"laurel_bytes one more", ReasonLaurelBytes, func(t *testing.T, f *fixture) {
			f.window[ResultFile] = replaceOnce(t, f.window[ResultFile], `"laurel_bytes": 11334`, `"laurel_bytes": 11335`)
		}},
		{"last line without its LF", ReasonLaurelLine, func(t *testing.T, f *fixture) {
			r := baseRecords(t)
			f.records(t, r[:len(r)-1], true)
		}},
		{"a line that is a list", ReasonLaurelLine, func(t *testing.T, f *fixture) {
			lines := bytes.SplitAfter(baseRecords(t), []byte("\n"))
			lines[1] = []byte("[]\n")
			f.records(t, bytes.Join(lines, nil), true)
		}},
		{"a pid repeated with another value", ReasonDuplicateKey, func(t *testing.T, f *fixture) { f.records(t, repeatPID(t, baseRecords(t)), false) }},
		{"the program run by another shell", ReasonNoProgramExec, raw(`"/bin/sh","/run/balistid-job/program"`, `"/bin/zz","/run/balistid-job/program"`)},
		{"the job's uid under another number", ReasonJobUID, func(t *testing.T, f *fixture) {
			lines := bytes.SplitAfter(baseRecords(t), []byte("\n"))
			for i, l := range lines {
				if bytes.Contains(l, []byte(`"/bin/sh","/run/balistid-job/program"`)) {
					lines[i] = replaceOnce(t, l, `,"uid":970,`, `,"uid":971,`)
				}
			}
			f.records(t, bytes.Join(lines, nil), false)
		}},
		{"canary renamed", ReasonNoCanary, raw("balistid-canary-", "balistid-canarx-")},
	}
	covered := map[Reason]bool{}
	for _, c := range cases {
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
