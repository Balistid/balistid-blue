package rangevm

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

var testProgram = sha256.Sum256([]byte("#!/bin/sh\necho hi\n"))

// execFacts is a complete exec report of testProgram that printed "hi", edited by edit; the output
// and Laurel chunks are replaced when out or laurel are not nil.
func execFacts(edit func(map[string]string), out, laurel []string) []Record {
	single := map[string]string{
		FactKernel: TargetKernel, FactJobSHA256: hex.EncodeToString(testProgram[:]), FactJobResult: "success",
		FactJobExit: "0", FactJobOutCut: "no", FactJobLaurelCut: "no", "canary": "seen",
	}
	if edit != nil {
		edit(single)
	}
	if out == nil {
		out = []string{"aGk="}
	}
	if laurel == nil {
		laurel = []string{"e30="}
	}
	var facts []Record
	for name, value := range single {
		facts = append(facts, fact(name, value))
	}
	for _, c := range out {
		facts = append(facts, fact(FactJobOut, c))
	}
	for _, c := range laurel {
		facts = append(facts, fact(FactJobLaurel, c))
	}
	return facts
}

func set(name, value string) func(map[string]string) {
	return func(m map[string]string) { m[name] = value }
}

func ended(result, exit string) func(map[string]string) {
	return func(m map[string]string) { m[FactJobResult], m[FactJobExit] = result, exit }
}

func b64(n int, c byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{c}, n)) }

func TestExecReport(t *testing.T) {
	got := ExecReport(execFacts(nil, nil, nil), testProgram)
	if got.Verdict != Ran || string(got.Out) != "hi" || string(got.Laurel) != "{}" || got.Result != "success" || got.Exit != 0 || got.OutCut {
		t.Fatalf("full report: %+v", got)
	}
	full := strings.Repeat(b64(JobChunk, 'a')+" ", JobOutCap/JobChunk)
	cases := map[string]struct {
		facts   []Record
		verdict string
	}{
		"canary missing":     {execFacts(set("canary", "missing"), nil, nil), Invalid},
		"fact missing":       {execFacts(func(m map[string]string) { delete(m, FactJobExit) }, nil, nil), Invalid},
		"no unit result":     {execFacts(func(m map[string]string) { delete(m, FactJobResult) }, nil, nil), Invalid},
		"unit unknown":       {execFacts(set(FactJobResult, "unknown"), nil, nil), Invalid},
		"records lost":       {execFacts(set(FactJobLaurelCut, "lost"), nil, nil), Invalid},
		"barrier missing":    {execFacts(set("canary", "missing"), nil, nil), Invalid},
		"log error":          {execFacts(set(FactJobLaurelCut, "error"), nil, nil), Invalid},
		"log cut at cap":     {execFacts(set(FactJobLaurelCut, "yes"), nil, nil), Invalid},
		"exit 1":             {execFacts(ended("exit-code", "1"), nil, nil), Ran},
		"exit-code 0":        {execFacts(ended("exit-code", "0"), nil, nil), Invalid},
		"exit 199":           {execFacts(ended("exit-code", "199"), nil, nil), Ran},
		"exit 203":           {execFacts(ended("exit-code", "203"), nil, nil), Invalid},
		"exit 200":           {execFacts(ended("exit-code", "200"), nil, nil), Invalid},
		"success, 7":         {execFacts(set(FactJobExit, "7"), nil, nil), Invalid},
		"oom-kill":           {execFacts(ended("oom-kill", "9"), nil, nil), Ran},
		"resources":          {execFacts(set(FactJobResult, "resources"), nil, nil), Invalid},
		"start limit":        {execFacts(set(FactJobResult, "start-limit-hit"), nil, nil), Invalid},
		"exec condition":     {execFacts(set(FactJobResult, "exec-condition"), nil, nil), Invalid},
		"exit -1":            {execFacts(ended("exit-code", "-1"), nil, nil), Invalid},
		"exit garbage":       {execFacts(ended("exit-code", "x"), nil, nil), Invalid},
		"exit +5":            {execFacts(ended("exit-code", "+5"), nil, nil), Invalid},
		"exit 05":            {execFacts(ended("exit-code", "05"), nil, nil), Invalid},
		"exit with space":    {execFacts(ended("exit-code", " 5"), nil, nil), Invalid},
		"timed out, SIGTERM": {execFacts(ended("timeout", "15"), nil, nil), Ran},
		"timed out, exit 0":  {execFacts(ended("timeout", "0"), nil, nil), Ran},
		"timed out, empty":   {execFacts(ended("timeout", ""), nil, nil), Invalid},
		"timed out, 256":     {execFacts(ended("timeout", "256"), nil, nil), Invalid},
		"signal 9":           {execFacts(ended("signal", "9"), nil, nil), Ran},
		"signal, empty":      {execFacts(ended("signal", ""), nil, nil), Invalid},
		"signal 0":           {execFacts(ended("signal", "0"), nil, nil), Invalid},
		"signal 65":          {execFacts(ended("signal", "65"), nil, nil), Invalid},
		"core dump 11":       {execFacts(ended("core-dump", "11"), nil, nil), Ran},
		"self-test fact":     {append(execFacts(nil, nil, nil), fact("io_uring_off", "EPERM")), Invalid},
		"job error":          {append(execFacts(nil, nil, nil), fact(FactJobError, "x")), Invalid},
		"sha twice":          {append(execFacts(nil, nil, nil), fact(FactJobSHA256, "ab")), Invalid},
		"sha upper case":     {execFacts(set(FactJobSHA256, strings.ToUpper(hex.EncodeToString(testProgram[:]))), nil, nil), Invalid},
		"other program":      {execFacts(set(FactJobSHA256, strings.Repeat("0", 64)), nil, nil), Invalid},
		"other kernel":       {execFacts(set(FactKernel, "6.1"), nil, nil), Unknown},
		// Output and Laurel records.
		"no output":             {execFacts(nil, []string{}, nil), Ran},
		"not base64":            {execFacts(nil, []string{"%%%not-base64\x1b[31m"}, nil), Invalid},
		"line break":            {execFacts(nil, []string{"aGk=\n"}, nil), Invalid},
		"no padding":            {execFacts(nil, []string{"aGk"}, nil), Invalid},
		"padding bits":          {execFacts(nil, []string{"aGl="}, nil), Invalid},
		"empty chunk":           {execFacts(nil, []string{""}, nil), Invalid},
		"short chunk first":     {execFacts(nil, []string{"aGk=", b64(JobChunk, 'a')}, nil), Invalid},
		"full chunks":           {execFacts(nil, []string{b64(JobChunk, 'a'), "aGk="}, nil), Ran},
		"chunk over size":       {execFacts(nil, []string{b64(JobChunk+1, 'a')}, nil), Invalid},
		"output over cap":       {execFacts(nil, append(strings.Fields(full), "aGk="), nil), Invalid},
		"laurel not base64":     {execFacts(nil, nil, []string{"{}"}), Invalid},
		"cut garbage":           {execFacts(set(FactJobOutCut, "garbage"), nil, nil), Invalid},
		"cut but short":         {execFacts(set(FactJobOutCut, "yes"), nil, nil), Invalid},
		"cut at the cap":        {execFacts(set(FactJobOutCut, "yes"), strings.Fields(full), nil), Ran},
		"at the cap, not cut":   {execFacts(nil, strings.Fields(full), nil), Ran},
		"unexpected fact":       {append(execFacts(nil, nil, nil), fact("x\x1b[2J", "1")), Invalid},
		"unexpected empty fact": {append(execFacts(nil, nil, nil), fact("", "1")), Invalid},
	}
	for name, c := range cases {
		got := ExecReport(c.facts, testProgram)
		if got.Verdict != c.verdict {
			t.Errorf("%s: %s (%s), want %s", name, got.Verdict, got.Reason, c.verdict)
		}
		if got.Verdict == Invalid && (got.Out != nil || got.Laurel != nil || got.Result != "") {
			t.Errorf("%s: an INVALID report carries output or a result: %+v", name, got)
		}
		if strings.ContainsFunc(got.Reason, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			t.Errorf("%s: reason is not printable text: %q", name, got.Reason)
		}
	}
	if r := ExecReport(execFacts(set(FactKernel, strings.Repeat("a", 1000)), nil, nil), testProgram); len(r.Reason) > 300 {
		t.Errorf("a long kernel string makes a %d-byte reason", len(r.Reason))
	}
	// A kernel string cannot pose as the verdict's own words: it stays inside its quotes.
	forged := ExecReport(execFacts(set(FactKernel, `x" is the target; the job ran and "`), nil, nil), testProgram)
	if forged.Verdict != Unknown || strings.Count(forged.Reason, `"`) != 2 {
		t.Errorf("forged kernel string: %s %s", forged.Verdict, forged.Reason)
	}
	if got := ExecReport(execFacts(set(FactJobOutCut, "yes"), strings.Fields(full), nil), testProgram); !got.OutCut || len(got.Out) != JobOutCap {
		t.Errorf("cut output: cut %v, %d bytes", got.OutCut, len(got.Out))
	}
	// A self-test run never passes with exec facts in it.
	if v, _ := Selftest(execFacts(nil, nil, nil)); v != Invalid {
		t.Errorf("Selftest of an exec report: %s", v)
	}
}

func TestPrintable(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"plain text 7.2.8", 100, "plain text 7.2.8"},
		{"\x1b[31mred", 100, `\x1b[31mred`},
		{"line\nforged", 100, `line\x0aforged`},
		{`a\x1b`, 100, `a\x5cx1b`},
		{`end"quote`, 100, `end\x22quote`},
		{"é", 100, `\xc3\xa9`},
		{"\u202e", 100, `\xe2\x80\xae`},
		{"abcdef", 3, "abc"},
		{"a\x1b", 4, "a"},
		{"", 10, ""},
	}
	for _, c := range cases {
		if got := Printable(c.in, c.limit); got != c.want {
			t.Errorf("Printable(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}
}

func FuzzPrintable(f *testing.F) {
	f.Add("\x1b[31m\\\n\u202e", 16)
	f.Fuzz(func(t *testing.T, s string, limit int) {
		limit = int(uint(limit) % 4096)
		got := Printable(s, limit)
		if len(got) > limit {
			t.Fatalf("%d bytes over the limit %d", len(got), limit)
		}
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] > 0x7e {
				t.Fatalf("byte %#x at %d", got[i], i)
			}
		}
	})
}

// Whatever the decoder accepts is exactly what the guest's encoding of those bytes gives.
func FuzzChunks(f *testing.F) {
	f.Add("aGk=", "", uint16(0))
	f.Add("aGk=\n", "e30=", uint16(3))
	f.Fuzz(func(t *testing.T, a, b string, cut uint16) {
		values := []string{a}
		if b != "" {
			values = append(values, b)
		}
		data, err := chunks(values, int(cut)+1)
		if err != nil {
			return
		}
		var again []string
		for len(data) > 0 {
			n := min(JobChunk, len(data))
			again = append(again, base64.StdEncoding.EncodeToString(data[:n]))
			data = data[n:]
		}
		if strings.Join(again, ",") != strings.Join(values, ",") {
			t.Fatalf("accepted %q, which re-encodes as %q", values, again)
		}
	})
}

// Whatever a guest reports, a reason is printable text, INVALID carries no data, and RAN names
// systemd's result.
func FuzzExecReport(f *testing.F) {
	f.Add("aGk=", "e30=", "success", "0", "no", TargetKernel)
	f.Add("%%%\x1b[31m", "", "signal", "", "garbage", "x\" y")
	f.Fuzz(func(t *testing.T, out, laurel, result, exit, cut, kernel string) {
		facts := execFacts(func(m map[string]string) {
			m[FactJobResult], m[FactJobExit], m[FactJobOutCut], m[FactKernel] = result, exit, cut, kernel
		}, []string{out}, []string{laurel})
		got := ExecReport(facts, testProgram)
		if strings.ContainsFunc(got.Reason, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			t.Fatalf("reason is not printable: %q", got.Reason)
		}
		switch got.Verdict {
		case Invalid:
			if got.Out != nil || got.Laurel != nil || got.Result != "" {
				t.Fatalf("INVALID carries data: %+v", got)
			}
		case Ran, Unknown:
			if got.Result == "" {
				t.Fatalf("%s without a result", got.Verdict)
			}
		default:
			t.Fatalf("verdict %q", got.Verdict)
		}
	})
}
