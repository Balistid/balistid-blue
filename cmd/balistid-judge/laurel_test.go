package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func hashedName(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "x-" + hex.EncodeToString(sum[:4])
}

// TestNamesStayInTheAlphabet is acceptance names_outside_alphabet for the judge's side: a base name outside
// [A-Za-z0-9._+-]{1,64}, after Laurel's quoting is decoded, leaves only as x- and 8 hex of its SHA-256.
func TestNamesStayInTheAlphabet(t *testing.T) {
	long := strings.Repeat("a", 65)
	cases := map[string]string{
		"/usr/bin/git":                    "git",
		"/usr/bin/g++":                    "g++",
		"/usr/bin/g%2b%2b":                "g++", // Laurel's quoting of +
		"/tmp/a b":                        hashedName("a b"),
		"/tmp/a%20b":                      hashedName("a%20b"), // Laurel writes a space as it is: not its quoting
		"/tmp/" + strings.Repeat("a", 64): strings.Repeat("a", 64),
		"/tmp/" + long:                    hashedName(long),
		"/tmp/café":                       hashedName("café"),
		"/tmp/x%0ay":                      hashedName("x\ny"),
		"/tmp/":                           hashedName(""),
		"/tmp/a\"b":                       hashedName("a\"b"),
	}
	for exe, want := range cases {
		e := execSpec{serial: 1, pid: 2, ppid: 1, uid: 1000, exe: exe, ok: true}
		rec, err := decodeLine(e.line())
		if err != nil || !rec.Exec {
			t.Fatalf("%q: not an exec: %v", exe, err)
		}
		if rec.Run.Name != want || !nameAlphabet.MatchString(rec.Run.Name) {
			t.Errorf("%q: name %q, want %q", exe, rec.Run.Name, want)
		}
		if strings.Contains(rec.Run.Name, "/") {
			t.Errorf("%q: a directory left", exe)
		}
	}
}

func TestDecodeAnExec(t *testing.T) {
	e := execSpec{serial: 42, pid: 300, ppid: 299, uid: 1000, exe: "/usr/bin/true", ok: true,
		spawner: `"EVENT_ID":"` + eventOf(41) + `"`, spawnPID: 299, spawnExe: agentExe}
	rec, err := decodeLine(e.line())
	if err != nil || !rec.Exec || !rec.Whole || rec.Key != "balistid-exec" {
		t.Fatalf("%+v, %v", rec, err)
	}
	r := rec.Run
	if r.PID != 300 || r.PPID != 299 || r.UID != 1000 || r.Process.EventID != eventOf(42) || r.Name != "true" ||
		r.Agent || !r.SpawnerAgent || r.SpawnedBy == nil || r.SpawnedBy.EventID != eventOf(41) || r.SpawnedBy.PID != 299 {
		t.Errorf("%+v", r)
	}
	e.exe = agentExe
	if rec, _ := decodeLine(e.line()); !rec.Run.Agent || rec.Run.Name != "2.0.14" {
		t.Errorf("the agent's binary: %+v", rec.Run)
	}
	e.ok = false
	if rec, _ := decodeLine(e.line()); rec.Exec {
		t.Error("a failed execve counted")
	}
}

// TestKeysAsDetectReadsThem: a key repeated with another value, or spelled in another case, makes the line no exec,
// as internal/detect would refuse or not see it; the same value twice is Laurel's own SPAWNED_BY pid.
func TestKeysAsDetectReadsThem(t *testing.T) {
	base := execSpec{serial: 7, pid: 8, ppid: 1, uid: 1000, exe: "/usr/bin/id", ok: true,
		spawner: `"START_TIME":"1795340216.325"`, spawnPID: 1, spawnExe: "/usr/bin/bash"}.line()
	if rec, err := decodeLine(base); err != nil || !rec.Exec || !rec.Whole {
		t.Fatalf("the base line: %+v %v", rec, err)
	}
	for name, edit := range map[string][2]string{
		"uid twice":         {`"uid":1000,`, `"uid":1000,"uid":0,`},
		"exe twice":         {`"comm":"c",`, `"comm":"c","exe":"/usr/bin/other",`},
		"Success":           {`"success":"yes"`, `"Success":"yes"`},
		"spawner pid twice": {`"comm":"x","exe":"/usr/bin/bash","pid":1}`, `"comm":"x","exe":"/usr/bin/bash","pid":2}`},
		"invalid utf-8":     {`"tty":"(none)"`, "\"tty\":\"\xff\""},
		"syscall a string":  {`"syscall":59`, `"syscall":"59"`},
		"exit -0":           {`"exit":0`, `"exit":-0`},
		"success no":        {`"success":"yes"`, `"success":"no"`},
		"Arch":              {`"arch":"0xc000003e"`, `"Arch":"0xc000003e"`},
	} {
		line := bytes.Replace(base, []byte(edit[0]), []byte(edit[1]), 1)
		if bytes.Equal(line, base) {
			t.Fatalf("%s: the edit does not apply", name)
		}
		if rec, _ := decodeLine(line); rec.Exec {
			t.Errorf("%s: counted as an exec", name)
		}
	}
	twice := bytes.Replace(base, []byte(`"uid":1000,`), []byte(`"uid":1000,"uid":1000,`), 1)
	if rec, _ := decodeLine(twice); !rec.Exec {
		t.Error("the same value twice refused")
	}
}

func TestBadFieldsAreNotExported(t *testing.T) {
	base := execSpec{serial: 7, pid: 8, ppid: 1, uid: 1000, exe: "/usr/bin/id", ok: true}.line()
	for name, edit := range map[string][2]string{
		"uid over 32 bits": {`"uid":1000,`, `"uid":4294967296,`},
		"pid negative":     {`"pid":8,`, `"pid":-8,`},
		"no process key":   {`"PID":{"EVENT_ID":"` + eventOf(7) + `"}`, `"PID":{}`},
		"two process keys": {`"PID":{"EVENT_ID":"` + eventOf(7) + `"}`, `"PID":{"EVENT_ID":"` + eventOf(7) + `","START_TIME":"1.000"}`},
		"bad event id":     {`"PID":{"EVENT_ID":"` + eventOf(7) + `"}`, `"PID":{"EVENT_ID":"x"}`},
		"no exe":           {`"exe":"/usr/bin/id",`, ``},
	} {
		line := bytes.Replace(base, []byte(edit[0]), []byte(edit[1]), 1)
		if bytes.Equal(line, base) {
			t.Fatalf("%s: the edit does not apply", name)
		}
		if rec, _ := decodeLine(line); !rec.Exec || rec.Whole {
			t.Errorf("%s: %+v", name, rec)
		}
	}
}

func FuzzDecodeLine(f *testing.F) {
	f.Add(execSpec{serial: 1, pid: 2, ppid: 1, uid: 1000, exe: "/usr/bin/x", ok: true,
		spawner: `"EVENT_ID":"1.000:1"`, spawnPID: 1, spawnExe: agentExe}.line())
	f.Add(otherLine(3, "k"))
	f.Add([]byte(`{"ID":"1.000:1","DAEMON_START":{}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := decodeLine(data)
		if err != nil {
			return
		}
		if rec.Key != "" && !nameAlphabet.MatchString(rec.Key) {
			t.Fatalf("key %q", rec.Key)
		}
		if rec.Exec && rec.Whole && !nameAlphabet.MatchString(rec.Run.Name) {
			t.Fatalf("name %q", rec.Run.Name)
		}
		_ = auditdOwn(data)
	})
}
