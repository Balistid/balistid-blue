package detect

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodePair(t *testing.T) {
	good := pairJSON(reference, programsFor())
	p, err := decodePair(fixturePair, []byte(good))
	if err != nil || p.Name != fixturePair || p.Attack != "T0000" || p.Author != "test" || p.Brief != fixtureBrief || len(p.Runs) != 4 ||
		p.Runs["tech-a"].Program != "prog.sh" || string(p.Runs["tech-a"].Text) != baseProgram || p.Runs["twin-b"].TimeoutS != 60 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, c := range []struct{ name, old, repl, pair string }{
		{"CRLF", "\n", "\r\n", ""},
		{"a run missing", `"twin-b":`, `"twin-c":`, ""},
		{"a key added", `"attack":`, `"x":1,"attack":`, ""},
		{"attack a number", `"attack":"T0000"`, `"attack":1`, ""},
		{"author missing", `"author":"test",`, ``, ""},
		{"brief a list", `"brief":"a test pair"`, `"brief":["a"]`, ""},
		{"reference broken", `"op":"eq"`, `"op":"regex"`, ""},
		{"program named job.json", `"program":"prog.sh"`, `"program":"job.json"`, ""},
		{"program name with a slash", `"program":"prog.sh"`, `"program":"a/b"`, ""},
		{"timeout 0", `"timeout_s":60`, `"timeout_s":0`, ""},
		{"timeout 301", `"timeout_s":60`, `"timeout_s":301`, ""},
		{"timeout a string", `"timeout_s":60`, `"timeout_s":"60"`, ""},
		{"text not a shell script", `"text":"#!/bin/sh\nuname -r`, `"text":"#!/bin/bash\nuname -r`, ""},
		{"text a number", `"text":"#!/bin/sh\nid -g\n"`, `"text":1`, ""},
		{"a run key added", `"timeout_s":60,"text"`, `"timeout_s":60,"x":1,"text"`, ""},
		{"pair name with a capital", "", "", "Fix"},
		{"pair name too long", "", "", strings.Repeat("a", MaxPairRun-len("-twin-a")+1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data, name := good, fixturePair
			if c.old != "" {
				data = strings.Replace(good, c.old, c.repl, 1)
				if data == good {
					t.Fatalf("%q not found", c.old)
				}
			}
			if c.pair != "" {
				name = c.pair
			}
			if _, err := decodePair(name, []byte(data)); err == nil {
				t.Fatal("decoded")
			}
		})
	}
	if _, err := decodePair(strings.Repeat("a", MaxPairRun-len("-twin-a")), []byte(good)); err != nil {
		t.Fatalf("a pair name at the limit: %v", err)
	}
	if MaxPairRun != 30 {
		t.Fatalf("MaxPairRun %d, ADR 0077 point 2 says 30", MaxPairRun)
	}
	for _, c := range []struct{ name, old, repl string }{
		{"timeout 1", `"timeout_s":60`, `"timeout_s":1`},
		{"timeout 300", `"timeout_s":60`, `"timeout_s":300`},
		{"text of exactly 1 MiB", `"text":"#!/bin/sh\nid -g\n"`, `"text":"#!/bin/sh\n` + strings.Repeat("x", 1<<20-len("#!/bin/sh\n")) + `"`},
	} {
		if _, err := decodePair(fixturePair, []byte(strings.Replace(good, c.old, c.repl, 1))); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	big := strings.Replace(good, `"text":"#!/bin/sh\nid -g\n"`, `"text":"#!/bin/sh\n`+strings.Repeat("x", 1<<20)+`"`, 1)
	if _, err := decodePair(fixturePair, []byte(big)); err == nil {
		t.Fatal("a program over 1 MiB decoded")
	}
}

// TestEachPairRefusalNamesItsCause: a check that let its case through to a later one fails with another cause.
func TestEachPairRefusalNamesItsCause(t *testing.T) {
	good := pairJSON(reference, programsFor())
	for _, c := range []struct {
		name, old, repl, why string
		wraps                bool
	}{
		{"not JSON", `"attack":`, `"attack"`, "not one valid JSON value", false},
		{"a key repeated, same value", `"attack":"T0000"`, `"attack":"T0000","attack":"T0000"`, "repeated key", true},
		{"a key missing", `"author":"test",`, ``, `key "author" missing`, false},
		{"attack a number", `"attack":"T0000"`, `"attack":1`, "attack, author and brief", false},
		{"author a number", `"author":"test"`, `"author":1`, "attack, author and brief", false},
		{"brief a number", `"brief":"` + fixtureBrief + `"`, `"brief":1`, "attack, author and brief", false},
		{"the reference broken", `"op":"eq"`, `"op":"regex"`, "reference: ", true},
		{"a run missing", `"twin-b":`, `"twin-c":`, "runs: ", true},
		{"a run's key missing", `"timeout_s":60,"text"`, `"text"`, "run tech-a: ", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := strings.Replace(good, c.old, c.repl, 1)
			if data == good {
				t.Fatalf("%q not found", c.old)
			}
			_, err := decodePair(fixturePair, []byte(data))
			if err == nil || !strings.Contains(err.Error(), c.why) || (errors.Unwrap(err) != nil) != c.wraps {
				t.Fatalf("err %v, want %q (wraps %v)", err, c.why, c.wraps)
			}
		})
	}
}

// TestEachRuleFileRefusalNamesItsCause, as for a pair.
func TestEachRuleFileRefusalNamesItsCause(t *testing.T) {
	for _, c := range []struct{ name, old, repl, why string }{
		{"not JSON", `"model":`, `"model"`, "not one valid JSON value"},
		{"a key repeated, same value", `"model":"test"`, `"model":"test","model":"test"`, "repeated key"},
		{"a key missing", `"model":"test",`, ``, `key "model" missing`},
		{"model a number", `"model":"test"`, `"model":1`, "model, sample and brief_sha256"},
		{"sample a string", `"sample":1`, `"sample":"1"`, "model, sample and brief_sha256"},
		{"brief sha a number", `"brief_sha256":"` + sha([]byte(fixtureBrief)) + `"`, `"brief_sha256":1`, "model, sample and brief_sha256"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := strings.Replace(fixtureRule, c.old, c.repl, 1)
			if data == fixtureRule {
				t.Fatalf("%q not found", c.old)
			}
			if _, err := decodeRuleFile(fixtureRuleFile, []byte(data)); err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("err %v, want %q", err, c.why)
			}
		})
	}
}

func TestDecodeRuleFile(t *testing.T) {
	rf, err := decodeRuleFile(fixtureRuleFile, []byte(fixtureRule))
	if err != nil || rf.Model != "test" || rf.Sample != 1 || rf.BriefSHA256 != sha([]byte(fixtureBrief)) || rf.Path != fixtureRuleFile {
		t.Fatalf("%+v %v", rf, err)
	}
	for _, c := range []struct{ name, old, repl string }{
		{"CRLF", "\n", "\r\n"},
		{"model missing", `"model":"test",`, ``},
		{"sample a string", `"sample":1`, `"sample":"1"`},
		{"params a list", `"params":{}`, `"params":[]`},
		{"brief sha upper case", `"brief_sha256":"`, `"brief_sha256":"A`},
		{"a key added", `"model":`, `"x":1,"model":`},
		{"the rule broken", `"op":"eq"`, `"op":"regex"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := strings.Replace(fixtureRule, c.old, c.repl, 1)
			if data == fixtureRule {
				t.Fatalf("%q not found", c.old)
			}
			if _, err := decodeRuleFile(fixtureRuleFile, []byte(data)); err == nil {
				t.Fatal("decoded")
			}
		})
	}
}

func TestContentHash(t *testing.T) {
	a := contentHash(map[string][]byte{"pairs/x.json": []byte("1"), "rules/x/a.json": []byte("2")})
	if len(a) != 32 {
		t.Fatalf("hash %q", a)
	}
	for _, other := range []map[string][]byte{
		{"pairs/x.json": []byte("1"), "rules/x/a.json": []byte("3")},
		{"pairs/x.json": []byte("1"), "rules/x/b.json": []byte("2")},
		{"pairs/x.json": []byte("12"), "rules/x/a.json": []byte("")}, // bytes moved across a boundary
		{"pairs/x.json1": []byte(""), "rules/x/a.json": []byte("2")}, // a path and its bytes run together
		{"pairs/x.json": []byte("1")},
	} {
		if contentHash(other) == a {
			t.Errorf("%v binds the same hash", other)
		}
	}
	if contentHash(map[string][]byte{"rules/x/a.json": []byte("2"), "pairs/x.json": []byte("1")}) != a {
		t.Error("the hash depends on map order")
	}
}

func TestJobNames(t *testing.T) {
	h := strings.Repeat("ab", 16)
	for _, run := range RunNames {
		p, r, got, ok := splitJobName(jobName("my-pair", run, h))
		if !ok || p != "my-pair" || r != run || got != h {
			t.Errorf("%s: %q %q %q %v", run, p, r, got, ok)
		}
	}
	for _, name := range []string{
		"x-tech-a-" + strings.Repeat("A", 32),
		"x-tech-c-" + h,
		"x-tech-a" + h,
		"x-tech-ax" + h, // the dash before the hash is the name's, not any byte
		"x-tech-a-" + h + "0",
		"tech-a-" + h,
		"-tech-a-" + h,
		"X-tech-a-" + h,
		h,
		"",
	} {
		if _, _, _, ok := splitJobName(name); ok {
			t.Errorf("%q parsed", name)
		}
	}
	if !technique("tech-b") || technique("twin-a") {
		t.Error("technique")
	}
}

func FuzzDecodePair(f *testing.F) {
	f.Add([]byte(pairJSON(reference, programsFor())))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := decodePair(fixturePair, data)
		if err != nil {
			return
		}
		if !plainText(data) || len(p.Runs) != len(RunNames) {
			t.Fatalf("decoded a pair that is not plain text or lacks a run: %+v", p)
		}
		for _, run := range p.Runs {
			if !strings.HasPrefix(string(run.Text), "#!/bin/sh\n") || run.TimeoutS < 1 || run.TimeoutS > 300 {
				t.Fatalf("decoded a run out of its bounds: %+v", run)
			}
		}
	})
}

func FuzzDecodeRuleFile(f *testing.F) {
	f.Add([]byte(fixtureRule))
	f.Fuzz(func(t *testing.T, data []byte) {
		rf, err := decodeRuleFile("rules/x/y.json", data)
		if err == nil && !hex64.MatchString(rf.BriefSHA256) {
			t.Fatal("decoded a rule whose brief sha is not 64 hex digits")
		}
	})
}
