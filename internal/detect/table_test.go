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

func TestCrossRows(t *testing.T) { crossRows(t, false) }

// TestCrossRowsStartAtTheCurrentContent: fiy ran other content at 11:00, before fix's windows; its current rule
// was bound after them, so it is scored on none of them (ADR 0079 point 8).
func TestCrossRowsStartAtTheCurrentContent(t *testing.T) { crossRows(t, true) }

func crossRows(t *testing.T, oldRun bool) {
	t.Helper()
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
	if oldRun {
		name := jobName("fiy", "tech-a", strings.Repeat("0", 32))
		old := "20261118T110000Z-0123abcd-" + name
		put(t, lab, "windows/"+strings.ToLower(old)+"/"+ResultFile, resultFor(old, name, "x.sh", 60, []byte("#!/bin/sh\n"), 1))
	}
	out := load(t, lab).Table()
	counted := map[string]bool{}
	for _, p := range out.Pairs {
		counted[p.Pair] = p.Counted
	}
	if len(out.Pairs) != 2 || !counted["fix"] || counted["fiy"] == oldRun {
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

// TestEveryRowNamesItsFields: each row of a lab of four valid windows and an invalid one, field by field.
func TestEveryRowNamesItsFields(t *testing.T) {
	f := fourWindows(t, baseFixture(t))
	f.extra["20261118t110000z-0123abcd-junk"] = map[string][]byte{ResultFile: []byte("{}\n")}
	out := load(t, f.write(t)).Table()
	if len(out.Windows) != 5 {
		t.Fatalf("windows %+v", out.Windows)
	}
	if w := out.Windows[0]; w != (WindowRow{Window: "20261118t110000z-0123abcd-junk", Reason: ReasonResultDecode}) {
		t.Fatalf("the invalid window's row %+v", w)
	}
	base := out.Windows[1]
	if base.Window != f.dir || base.Pair != fixturePair || base.Run != "tech-a" || !base.Valid || base.Reason != "" {
		t.Fatalf("the base window's row %+v", base)
	}
	p := out.Pairs[0]
	if p.Pair != fixturePair || !p.Counted || p.Reason != "" || p.Windows["tech-a"] != f.dir || len(p.Windows) != 4 {
		t.Fatalf("the pair's row %+v", p)
	}
	for run, dir := range p.Windows {
		if !strings.Contains(dir, "-"+run+"-") {
			t.Fatalf("%s's window %s", run, dir)
		}
	}
	if r := out.Rules[0]; r.Rule != fixtureRuleFile || r.Pair != fixturePair || !r.Counted || len(r.Verdicts) != 4 {
		t.Fatalf("the rule's row %+v", r)
	}
	if len(out.Controls) != 2 || out.Controls[0] != (ControlRow{Control: "empty any", Windows: 4}) ||
		out.Controls[1] != (ControlRow{Control: "empty all", Windows: 4}) {
		t.Fatalf("controls over the valid windows only: %+v", out.Controls)
	}
	empty := string((&Lab{}).Table().Encode())
	for _, key := range []string{`"windows": []`, `"pairs": []`, `"rules": []`, `"cross": []`, `"control": "empty any"`} {
		if !strings.Contains(empty, key) {
			t.Fatalf("an empty lab's table lacks %s:\n%s", key, empty)
		}
	}
}

// TestABrokenPairOrRuleHasNoCrossRows: only a rule of a pair that decodes with all its rules is scored on others.
func TestABrokenPairOrRuleHasNoCrossRows(t *testing.T) {
	for _, broken := range []string{"pair", "rule"} {
		t.Run(broken, func(t *testing.T) {
			f := fourWindows(t, baseFixture(t))
			lab := f.write(t)
			gPair := pairJSON(reference, map[string]string{
				"tech-a": baseProgram + "# g\n", "tech-b": "#!/bin/sh\nuname -m\n", "twin-a": "#!/bin/sh\nid -n\n", "twin-b": "#!/bin/sh\nid -G\n",
			})
			files := map[string][]byte{"pairs/fiy.json": []byte(gPair), "rules/fiy/opus-1.json": []byte(fixtureRule)}
			switch broken {
			case "pair":
				files["pairs/fiy.json"] = []byte(strings.Replace(gPair, `"attack":"T0000"`, `"attack":1`, 1))
			case "rule":
				files["rules/fiy/opus-2.json"] = []byte(strings.Replace(fixtureRule, `"op":"eq"`, `"op":"regex"`, 1))
			}
			for path, data := range files {
				put(t, lab, path, data)
			}
			// fiy's first window of its current content: before fix's, so fiy's good rule would be scored on all
			// four of fix's.
			name := jobName("fiy", "tech-a", contentHash(files))
			id := "20261118T110000Z-0123abcd-" + name
			put(t, lab, "windows/"+strings.ToLower(id)+"/"+ResultFile, resultFor(id, name, "x.sh", 60, []byte("#!/bin/sh\n"), 1))
			out := load(t, lab).Table()
			if out.Windows[0].Pair != "fiy" {
				t.Fatalf("fiy's window is not first: %+v", out.Windows[0])
			}
			for _, c := range out.Cross {
				if strings.HasPrefix(c.Rule, "rules/fiy/") {
					t.Fatalf("a rule of a broken %s scored: %+v", broken, c)
				}
			}
		})
	}
}

// TestCrossRowsStartAtThePairsFirstWindow: another pair's window made between this pair's first and last windows
// is scored; the first of the current content, not the last, starts the rule's cross rows.
func TestCrossRowsStartAtThePairsFirstWindow(t *testing.T) {
	f := fourWindows(t, baseFixture(t))
	lab := f.write(t)
	gPair := pairJSON(reference, map[string]string{
		"tech-a": baseProgram + "# g\n", "tech-b": "#!/bin/sh\nuname -m\n", "twin-a": "#!/bin/sh\nid -n\n", "twin-b": "#!/bin/sh\nid -G\n",
	})
	put(t, lab, "pairs/fiy.json", []byte(gPair))
	p, err := decodePair("fiy", []byte(gPair))
	if err != nil {
		t.Fatal(err)
	}
	name := jobName("fiy", "tech-a", contentHash(map[string][]byte{"pairs/fiy.json": []byte(gPair)}))
	id := "20261118T120002Z-0123abcd-" + name // between fix's first (12:00:00) and last (12:00:03)
	r := p.Runs["tech-a"]
	raw := baseRecords(t)
	put(t, lab, "windows/"+strings.ToLower(id)+"/"+ResultFile, resultFor(id, name, r.Program, r.TimeoutS, r.Text, len(raw)))
	put(t, lab, "windows/"+strings.ToLower(id)+"/"+LaurelFile, escape(raw))
	out := load(t, lab).Table()
	var rows []CrossRow
	for _, c := range out.Cross {
		if c.Rule == fixtureRuleFile {
			rows = append(rows, c)
		}
	}
	if len(rows) != 1 || rows[0].Window != strings.ToLower(id) || rows[0].Verdict != Noisy {
		t.Fatalf("fix's cross rows %+v (windows %+v)", rows, out.Windows)
	}
}

// TestABrokenPairOrRuleSaysSo: the pair's row names what does not decode.
func TestABrokenPairOrRuleSaysSo(t *testing.T) {
	f := fourWindows(t, baseFixture(t))
	f.pair = strings.Replace(f.pair, `"attack":"T0000"`, `"attack":1`, 1)
	if p := load(t, f.write(t)).Table().Pairs[0]; p.Counted || p.Reason != "the pair does not decode" {
		t.Fatalf("a broken pair: %+v", p)
	}
	g := fourWindows(t, baseFixture(t))
	g.rules["rules/fix/b.json"] = strings.Replace(fixtureRule, `"op":"eq"`, `"op":"regex"`, 1)
	if p := load(t, g.write(t)).Table().Pairs[0]; p.Counted || p.Reason != "a rule does not decode" {
		t.Fatalf("a broken rule: %+v", p)
	}
}
