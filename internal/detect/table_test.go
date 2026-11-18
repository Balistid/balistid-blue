package detect

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// fourWindows is pair fix with a window for each run: the techniques run uname, the twins' records have it
// renamed, so the reference rule gives CAUGHT twice and QUIET twice. Stamps order tech-a, tech-b, twin-a, twin-b.
func fourWindows(t *testing.T, f *fixture) *fixture {
	t.Helper()
	f.window = f.windowFor(t, "tech-a", baseRecords(t))
	f.extra = map[string]map[string][]byte{}
	for i, run := range RunNames[1:] {
		raw := baseRecords(t)
		if !technique(run) {
			raw = bytes.ReplaceAll(raw, []byte(`"uname"`), []byte(`"unamf"`))
		}
		files := f.windowFor(t, run, raw)
		r, err := decodeResult(files[ResultFile])
		if err != nil {
			t.Fatal(err)
		}
		stamp := "T12000" + string(rune('1'+i)) + "Z"
		files[ResultFile] = bytes.Replace(files[ResultFile], []byte("T120000Z"), []byte(stamp), 1)
		f.extra[strings.ToLower(strings.Replace(r.ID, "T120000Z", stamp, 1))] = files
	}
	return f
}

func TestAPairCountsOnlyWithAllFourRuns(t *testing.T) {
	out := load(t, fourWindows(t, baseFixture(t)).write(t)).Table()
	if len(out.Pairs) != 1 || !out.Pairs[0].Counted || out.Judge != Version {
		t.Fatalf("pairs: %+v (windows %+v)", out.Pairs, out.Windows)
	}
	if got := out.Rules[0].Verdicts; got["tech-a"] != Caught || got["tech-b"] != Caught || got["twin-a"] != Quiet || got["twin-b"] != Quiet {
		t.Fatalf("rule verdicts: %v", got)
	}
	for _, c := range out.Controls {
		if c.Windows != 4 || c.Wrong != 0 {
			t.Fatalf("control %+v, want 4 windows and none wrong", c)
		}
	}
	g := fourWindows(t, baseFixture(t))
	for dir := range g.extra {
		if strings.Contains(dir, "-twin-b-") {
			delete(g.extra, dir)
		}
	}
	out = load(t, g.write(t)).Table()
	if out.Pairs[0].Counted || out.Pairs[0].Reason != "twin-b has no valid window" || out.Rules[0].Verdicts != nil ||
		out.Pairs[0].Windows["twin-b"] != "no-window" {
		t.Fatalf("pair with three runs: %+v %+v", out.Pairs[0], out.Rules[0])
	}
}

func TestAReferenceRuleThatMissesExcludesThePair(t *testing.T) {
	for _, c := range []struct{ name, rule, reason string }{
		{"it misses the techniques", `{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"nothing"}]}`, "MISSED on tech-a"},
		{"it fires on the twins", `{"any":[{"field":["EXECVE","ARGV"],"op":"eq","value":"id"}]}`, "NOISY on twin-a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := baseFixture(t)
			f.pair = pairJSON(c.rule, programsFor())
			out := load(t, fourWindows(t, f).write(t)).Table()
			if out.Pairs[0].Counted || !strings.Contains(out.Pairs[0].Reason, c.reason) {
				t.Fatalf("pair: %+v", out.Pairs[0])
			}
			for _, w := range out.Windows {
				if !w.Valid {
					t.Fatalf("window %s INVALID: %s", w.Window, w.Reason)
				}
			}
		})
	}
}

// TestAWindowOfOtherContentExcludesThePair: after a run, the pair's rules change and it runs again; the old
// window proves the new rules came after a window of the pair (T39), so the pair does not count.
func TestAWindowOfOtherContentExcludesThePair(t *testing.T) {
	f := fourWindows(t, baseFixture(t))
	old := f.window
	oldDir := strings.Replace(f.dir, "120000z", "110000z", 1)
	old[ResultFile] = bytes.Replace(old[ResultFile], []byte("T120000Z"), []byte("T110000Z"), 1)
	f.rules[fixtureRuleFile] += " " // the rules change: a new hash
	f.pair = strings.Replace(f.pair, "uname -r;", "uname -r ;", 1)
	fourWindows(t, f)
	f.extra[oldDir] = old
	out := load(t, f.write(t)).Table()
	if out.Pairs[0].Counted || !strings.Contains(out.Pairs[0].Reason, "ran other content") {
		t.Fatalf("pair: %+v", out.Pairs[0])
	}
}

func TestCrossRows(t *testing.T) {
	f := fourWindows(t, baseFixture(t))
	lab := f.write(t)
	// A second pair whose rule matches uname: its windows come after fix's first, fix's rule is scored on its.
	gPair := pairJSON(reference, map[string]string{
		"tech-a": baseProgram + "# g\n", "tech-b": "#!/bin/sh\nuname -m\n", "twin-a": "#!/bin/sh\nid -n\n", "twin-b": "#!/bin/sh\nid -G\n",
	})
	put(t, lab, "pairs/fiy.json", []byte(gPair))
	put(t, lab, "rules/fiy/opus-1.json", []byte(fixtureRule))
	p, err := decodePair("fiy", []byte(gPair))
	if err != nil {
		t.Fatal(err)
	}
	hash := contentHash(map[string][]byte{"pairs/fiy.json": []byte(gPair), "rules/fiy/opus-1.json": []byte(fixtureRule)})
	for i, run := range RunNames {
		raw := baseRecords(t)
		if !technique(run) {
			raw = bytes.ReplaceAll(raw, []byte(`"uname"`), []byte(`"unamf"`))
		}
		name := jobName("fiy", run, hash)
		id := "20261118T13000" + string(rune('0'+i)) + "Z-0123abcd-" + name
		r := p.Runs[run]
		put(t, lab, "windows/"+strings.ToLower(id)+"/"+ResultFile, resultFor(id, name, r.Program, r.TimeoutS, r.Text, len(raw)))
		put(t, lab, "windows/"+strings.ToLower(id)+"/"+LaurelFile, escape(raw))
	}
	out := load(t, lab).Table()
	if len(out.Pairs) != 2 || !out.Pairs[0].Counted || !out.Pairs[1].Counted {
		t.Fatalf("pairs: %+v", out.Pairs)
	}
	byRule := map[string][]CrossRow{}
	for _, c := range out.Cross {
		byRule[c.Rule] = append(byRule[c.Rule], c)
	}
	// fix's rule on fiy's four windows: all later than fix's first; uname on the techniques is NOISY.
	fixRows := byRule[fixtureRuleFile]
	if len(fixRows) != 4 {
		t.Fatalf("fix's cross rows: %+v", fixRows)
	}
	noisy := 0
	for _, c := range fixRows {
		if !strings.Contains(c.Window, "fiy-") {
			t.Fatalf("a rule scored on its own pair: %+v", c)
		}
		if c.Verdict == Noisy {
			noisy++
		}
	}
	if noisy != 2 {
		t.Fatalf("fix's rule NOISY on %d of fiy's windows, want the two techniques", noisy)
	}
	// fiy's rule: fix's windows all came before fiy's first, so none is scored.
	if rows := byRule["rules/fiy/opus-1.json"]; len(rows) != 0 {
		t.Fatalf("a rule scored on windows made before its pair's first: %+v", rows)
	}
}

func TestControlsCountWrongWindows(t *testing.T) {
	w := Window{Run: "tech-a", Dir: "d"}
	rows := controls([]Window{w, {Run: "twin-a", Dir: "e"}})
	if rows[0].Windows != 2 || rows[0].Wrong != 0 {
		t.Fatalf("empty any on windows without events: %+v", rows[0])
	}
	if rows[1].Wrong != 2 {
		t.Fatalf("empty all on windows without job events must go wrong: %+v", rows[1])
	}
}

func TestTableIsReproducible(t *testing.T) {
	f := fourWindows(t, baseFixture(t))
	a := load(t, f.write(t)).Table().Encode()
	b := load(t, f.write(t)).Table().Encode()
	if !bytes.Equal(a, b) || bytes.Contains(a, []byte(os.TempDir())) || !bytes.HasSuffix(a, []byte("}\n")) {
		t.Fatal("table differs between two runs over the same lab, names a path, or lacks its final LF")
	}
	var back TableOutput
	if err := json.Unmarshal(a, &back); err != nil || back.NotMeasured != NotMeasured {
		t.Fatalf("table does not decode back: %v", err)
	}
}
