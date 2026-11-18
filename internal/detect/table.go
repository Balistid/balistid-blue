package detect

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Verdict is a rule's outcome on one valid window (ADR 0076).
type Verdict string

// Verdicts: a technique's window caught or missed, a twin's left quiet or noisy.
const (
	Caught Verdict = "CAUGHT"
	Missed Verdict = "MISSED"
	Quiet  Verdict = "QUIET"
	Noisy  Verdict = "NOISY"
)

// NotMeasured is said in every report (ADR 0077 point 8, ADR 0078 point 6).
const NotMeasured = "Not closed: a window made outside the runner can inform a rule, so blindness is procedure, " +
	"not proof; loss during a run (2c09799 reports none); host root and its clock; a shell running what an agent " +
	"prepared; an extra run excluding a pair; any 24 results from any inbox job drop the anchor. It measures whether " +
	"a rule tells a technique from its twin and stays quiet on other windows, not daily false alarms nor general skill."

func verdict(r Rule, w Window) Verdict {
	m := r.matches(w.events)
	switch {
	case technique(w.Run) && m:
		return Caught
	case technique(w.Run):
		return Missed
	case m:
		return Noisy
	}
	return Quiet
}

// TableOutput is `balistid-lab table`'s document: fixed order, no time, no absolute path.
type TableOutput struct {
	Judge       string       `json:"judge"`
	NotMeasured string       `json:"not_measured"`
	Windows     []WindowRow  `json:"windows"`
	Pairs       []PairRow    `json:"pairs"`
	Controls    []ControlRow `json:"controls"`
	Rules       []RuleRow    `json:"rules"`
	Cross       []CrossRow   `json:"cross"`
}

// WindowRow says whether a window is valid, and why not.
type WindowRow struct {
	Window string `json:"window"`
	Pair   string `json:"pair"`
	Run    string `json:"run"`
	Valid  bool   `json:"valid"`
	Reason Reason `json:"reason,omitempty"`
}

// PairRow says whether a pair counts: its reference rule CAUGHT both techniques and left both twins QUIET.
type PairRow struct {
	Pair    string            `json:"pair"`
	Counted bool              `json:"counted"`
	Reason  string            `json:"reason,omitempty"`
	Windows map[string]string `json:"windows"`
}

// ControlRow is a built-in control over every valid window: how many it saw and how many went wrong.
type ControlRow struct {
	Control string `json:"control"`
	Windows int    `json:"windows"`
	Wrong   int    `json:"wrong"`
}

// RuleRow is one rule's verdicts on its own counted pair.
type RuleRow struct {
	Rule     string             `json:"rule"`
	Pair     string             `json:"pair"`
	Counted  bool               `json:"counted"`
	Verdicts map[string]Verdict `json:"verdicts,omitempty"`
}

// CrossRow is a rule's verdict on another pair's valid window made after its current content's first: QUIET or NOISY.
type CrossRow struct {
	Rule    string  `json:"rule"`
	Window  string  `json:"window"`
	Verdict Verdict `json:"verdict"`
}

// Table judges lab: windows, pairs, controls, each rule on its pair and on the others.
func (lab *Lab) Table() TableOutput {
	out := TableOutput{Judge: Version, NotMeasured: NotMeasured, Windows: []WindowRow{}, Pairs: []PairRow{},
		Rules: []RuleRow{}, Cross: []CrossRow{}} // controls always has its two rows
	valid := map[string]map[string]Window{} // pair -> run -> the run's one valid window
	first := map[string]string{}            // pair -> its first window of any content, by id
	var all []Window
	for _, w := range lab.Windows {
		out.Windows = append(out.Windows, WindowRow{Window: w.Dir, Pair: w.Pair, Run: w.Run, Valid: w.Valid(), Reason: w.Reason})
		// lab.Windows is in id order, so the first seen is the first made; a window whose name names no pair has
		// no hash, which no pair's content has either, and no rules read first[""].
		if _, seen := first[w.Pair]; !seen && w.Hash == lab.pairs[w.Pair].hash {
			first[w.Pair] = w.Dir // the first window of the pair's current content
		}
		if !w.Valid() {
			continue
		}
		if valid[w.Pair] == nil {
			valid[w.Pair] = map[string]Window{}
		}
		valid[w.Pair][w.Run] = w // one per run: another has the same program (ReasonProgramRepeated) or hash (ReasonName)
		all = append(all, w)
	}
	counted := map[string]bool{}
	for _, name := range sortedKeys(lab.pairs) {
		row := PairRow{Pair: name, Windows: map[string]string{}}
		row.Counted, row.Reason = lab.counts(name, valid[name], row.Windows)
		counted[name] = row.Counted
		out.Pairs = append(out.Pairs, row)
	}
	out.Controls = controls(all)
	for _, pair := range sortedKeys(lab.rules) {
		for _, rf := range lab.rules[pair] {
			row := RuleRow{Rule: rf.Path, Pair: pair, Counted: counted[pair]}
			if row.Counted {
				row.Verdicts = map[string]Verdict{}
				for _, run := range RunNames {
					row.Verdicts[run] = verdict(rf.Rule, valid[pair][run])
				}
			}
			out.Rules = append(out.Rules, row)
			if e := lab.pairs[pair]; e.pairErr == nil && e.ruleErr == nil {
				out.Cross = append(out.Cross, cross(rf, pair, first[pair], all)...)
			}
		}
	}
	return out
}

// cross scores a rule on every valid window of another pair made after the first window of its own pair's
// current content, so the rule was bound before those windows existed (ADR 0079 point 8); none without one.
func cross(rf RuleFile, pair, since string, all []Window) []CrossRow {
	var rows []CrossRow
	if since == "" {
		return rows
	}
	for _, w := range all {
		if w.Pair == pair || w.Dir <= since {
			continue
		}
		v := Quiet
		if rf.Rule.matches(w.events) {
			v = Noisy
		}
		rows = append(rows, CrossRow{Rule: rf.Path, Window: w.Dir, Verdict: v})
	}
	return rows
}

// controls runs the built-in rules over every valid window: how many it saw and how many went wrong.
func controls(all []Window) []ControlRow {
	var rows []ControlRow
	for _, c := range []struct {
		name            string
		rule            Rule
		technique, twin Verdict
	}{
		{"empty any", ControlEmpty, Missed, Quiet},
		{"empty all", ControlAll, Caught, Noisy},
	} {
		row := ControlRow{Control: c.name, Windows: len(all)}
		for _, w := range all {
			want := c.twin
			if technique(w.Run) {
				want = c.technique
			}
			if verdict(c.rule, w) != want {
				row.Wrong++
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// counts reports whether a pair counts (ADR 0077 point 5) and, if not, why; windows gets each run's window.
func (lab *Lab) counts(name string, runs map[string]Window, windows map[string]string) (bool, string) {
	entry := lab.pairs[name]
	for _, run := range RunNames {
		windows[run] = "no-window"
		if w, ok := runs[run]; ok {
			windows[run] = w.Dir
		}
	}
	switch {
	case entry.pairErr != nil:
		return false, "the pair does not decode"
	case entry.ruleErr != nil:
		return false, "a rule does not decode"
	}
	for _, w := range lab.Windows {
		if w.Pair == name && w.Hash != entry.hash {
			return false, "window " + w.Dir + " ran other content of the pair"
		}
	}
	for _, run := range RunNames {
		w, ok := runs[run]
		if !ok {
			return false, run + " has no valid window"
		}
		want := Caught
		if !technique(run) {
			want = Quiet
		}
		if got := verdict(entry.pair.Reference, w); got != want {
			return false, fmt.Sprintf("the reference rule gives %s on %s", got, run)
		}
	}
	return true, ""
}

// Encode is the table as indented JSON with a final LF; the same lab gives the same bytes.
func (t TableOutput) Encode() []byte {
	data, _ := json.MarshalIndent(t, "", "  ") // strings, ints, bools and maps of string keys always encode
	return append(data, '\n')
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
