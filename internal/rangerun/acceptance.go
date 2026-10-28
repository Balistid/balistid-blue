package rangerun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// MaxAcceptanceBytes caps the acceptance file; one entry per table trial is well under a KiB.
const MaxAcceptanceBytes = 64 << 10

// maxInvalid caps a trial's INVALID count: past the metric's runs it is a MISS, so more is never needed.
const maxInvalid = 1000

const acceptanceSchema = 1

// Acceptance is the suite of the runner's own commit (ADR 0018, point 6): what the runs of each
// trial of the compiled table gave. Only the runner schedules these runs, for its own image; it is
// never evidence and never stops the runner.
//
// BatchTurn says the next slot runs a batch before it offers an agent job (ADR 0018, point 5); a
// new suite offers an agent job first, so agents do not wait a batch after every install.
type Acceptance struct {
	Commit    string               `json:"commit"`
	Trials    map[string]TrialRuns `json:"trials"`
	BatchTurn bool                 `json:"batch_turn"`
}

// TrialRuns counts a trial's runs. Valid runs gave a verdict that counts: PASS or MISS of a trial, the
// expected verdict of a control. Passed are valid PASS runs that may pass a metric (not baseline).
// Invalid counts INVALID runs, a control's other verdict included. Miss is the result id of the
// MISS that stands for the commit. Baseline says the trial's runs were baseline: they decide nothing.
type TrialRuns struct {
	Valid    int    `json:"valid"`
	Passed   int    `json:"passed"`
	Invalid  int    `json:"invalid"`
	Miss     string `json:"miss,omitempty"`
	Baseline bool   `json:"baseline,omitempty"`
}

type acceptanceFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Commit        string                `json:"commit"`
	Trials        *map[string]TrialRuns `json:"trials"`
	BatchTurn     bool                  `json:"batch_turn"`
}

// ForCommit is a's suite if it is commit's, else an empty one: a new commit restarts the suite.
func (a Acceptance) ForCommit(commit string) Acceptance {
	if a.Commit == commit {
		return a
	}
	return Acceptance{Commit: commit, Trials: map[string]TrialRuns{}}
}

// Record adds a run of tr with its label and verdict, stored as result id. A control that does not
// give its expected verdict means the measurement is broken (ADR 0019, point 2): it counts as
// INVALID. A baseline run measures the sensor, never the collector (ADR 0018, point 4), and a trend
// never decides its metric (ADR 0025): the PASS of either passes nothing and its MISS does not stand.
func (a Acceptance) Record(tr rangejob.Trial, label, verdict, id string) Acceptance {
	out := Acceptance{Commit: a.Commit, Trials: make(map[string]TrialRuns, len(a.Trials)+1), BatchTurn: a.BatchTurn}
	for k, v := range a.Trials {
		out.Trials[k] = v
	}
	r := out.Trials[tr.Name]
	r.Baseline = r.Baseline || tr.Expect == "" && label == rangevm.LabelBaseline
	counts := label != rangevm.LabelBaseline && !tr.Trend
	switch {
	case tr.Expect != "" && verdict == tr.Expect:
		r.Valid = min(r.Valid+1, tr.Count)
	case tr.Expect != "" || verdict != rangevm.Pass && verdict != rangevm.Miss:
		r.Invalid = min(r.Invalid+1, maxInvalid)
	case verdict == rangevm.Pass:
		r.Valid = min(r.Valid+1, tr.Count)
		if counts {
			r.Passed = min(r.Passed+1, r.Valid)
		}
	default: // MISS
		r.Valid = min(r.Valid+1, tr.Count)
		if counts && r.Miss == "" {
			r.Miss = id
		}
	}
	out.Trials[tr.Name] = r
	return out
}

// decides says whether runs of tr, recorded as r, may decide its metric: neither a control, a trend nor
// baseline.
func decides(tr rangejob.Trial, r TrialRuns) bool {
	return tr.Expect == "" && !tr.Trend && !r.Baseline
}

// Verdict is metric's verdict so far (ADR 0021): MISS once a run that may decide it missed; INVALID
// once such a trial or one of its controls had more INVALID runs than its Count; PASS when every run
// that may decide it passed and every control gave its verdict; else "" (still open, or measured only
// by baseline runs). INVALID runs never make a MISS.
func (a Acceptance) Verdict(metric string) string {
	deciding, passed, complete, invalid := 0, true, true, false
	for _, tr := range rangejob.Trials() {
		if tr.Metric != metric {
			continue
		}
		r := a.Trials[tr.Name]
		switch {
		case decides(tr, r) && r.Miss != "":
			return rangevm.Miss
		case tr.Expect != "":
			complete = complete && r.Valid >= tr.Count
			invalid = invalid || r.Invalid > tr.Count
		case decides(tr, r):
			deciding++
			passed = passed && r.Passed >= tr.Count
			invalid = invalid || r.Invalid > tr.Count
		}
	}
	switch {
	case invalid:
		return rangevm.Invalid
	case deciding > 0 && passed && complete:
		return rangevm.Pass
	}
	return ""
}

// Metrics are the metrics the trial table decides, in table order: a metric with only trend trials is
// decided outside the range (ADR 0025).
func Metrics() []string {
	var out []string
	for _, tr := range rangejob.Trials() {
		if !tr.Trend && !slices.Contains(out, tr.Metric) {
			out = append(out, tr.Metric)
		}
	}
	return out
}

// Next is the next trial of the suite to run: the first in table order whose metric is undecided,
// that has fewer valid runs than its Count and no more INVALID runs than its Count, so a trial that
// cannot measure gives up instead of holding every batch. ok is false when nothing is left to run.
func (a Acceptance) Next() (tr rangejob.Trial, ok bool) {
	for _, t := range rangejob.Trials() {
		if r := a.Trials[t.Name]; a.Verdict(t.Metric) == "" && r.Valid < t.Count && r.Invalid <= t.Count {
			return t, true
		}
	}
	return rangejob.Trial{}, false
}

// LoadAcceptance reads commit's suite from path as LoadLedger reads the ledger. A missing file, or
// a well-formed one of another commit, starts a new suite: another commit's trials are not checked
// against this table, which may have renamed them. Anything else wrong is an error whose text never
// quotes the file.
func LoadAcceptance(path, commit string) (Acceptance, error) {
	data, err := readFile(path, MaxAcceptanceBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return Acceptance{}.ForCommit(commit), nil
	}
	if err != nil {
		return Acceptance{}, fmt.Errorf("acceptance: %w", err)
	}
	a, err := decodeAcceptance(data, commit)
	if err != nil {
		return Acceptance{}, fmt.Errorf("acceptance %s is corrupt: %w", path, err)
	}
	return a, nil
}

// SaveAcceptance replaces the file at path through wholefile.Write (mode 0600). It refuses,
// leaving the old file, a suite LoadAcceptance would refuse.
func SaveAcceptance(path string, a Acceptance) error {
	trials := a.Trials
	if trials == nil {
		trials = map[string]TrialRuns{}
	}
	data, err := json.MarshalIndent(acceptanceFile{SchemaVersion: acceptanceSchema, Commit: a.Commit, Trials: &trials, BatchTurn: a.BatchTurn}, "", "  ")
	if err != nil {
		return fmt.Errorf("save acceptance: %w", err)
	}
	if _, err := decodeAcceptance(data, a.Commit); err != nil {
		return fmt.Errorf("save acceptance %s: %w", path, err)
	}
	if err := wholefile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("save acceptance: %w", err)
	}
	return nil
}

// decodeAcceptance returns commit's suite in data: a new one if data names another full commit id,
// else data must be one object of this schema naming only trials of the table, each within its
// counts. Errors are fixed text.
func decodeAcceptance(data []byte, commit string) (Acceptance, error) {
	if len(data) > MaxAcceptanceBytes {
		return Acceptance{}, fmt.Errorf("over %d bytes", MaxAcceptanceBytes)
	}
	// Another commit's suite, of any schema a later runner may write, only restarts the suite.
	var owner struct {
		Commit string `json:"commit"`
	}
	if err := json.Unmarshal(data, &owner); err == nil && buildinfo.IsCommitID(owner.Commit) && owner.Commit != commit {
		return Acceptance{}.ForCommit(commit), nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f acceptanceFile
	if err := dec.Decode(&f); err != nil {
		return Acceptance{}, errors.New("not an acceptance object, or a field is unknown or of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Acceptance{}, errors.New("data after the acceptance object")
	}
	if f.SchemaVersion != acceptanceSchema {
		return Acceptance{}, fmt.Errorf("schema_version must be %d", acceptanceSchema)
	}
	if !buildinfo.IsCommitID(f.Commit) || f.Trials == nil {
		return Acceptance{}, errors.New("a full commit id and trials are required")
	}
	if f.Commit != commit {
		return Acceptance{}, errors.New("the suite is of another commit")
	}
	for name, r := range *f.Trials {
		tr, ok := rangejob.Lookup(name)
		switch {
		case !ok:
			return Acceptance{}, errors.New("a trial is not in the table")
		case r.Valid < 0 || r.Valid > tr.Count || r.Passed < 0 || r.Passed > r.Valid || r.Invalid < 0 || r.Invalid > maxInvalid:
			return Acceptance{}, errors.New("a trial's counts are out of range")
		case (tr.Expect != "" || tr.Trend || r.Baseline) && (r.Passed != 0 || r.Miss != ""):
			return Acceptance{}, errors.New("a control, trend or baseline passed or missed a metric")
		case tr.Expect != "" && r.Baseline:
			return Acceptance{}, errors.New("a control is baseline")
		case r.Miss != "" && !resultName.MatchString(r.Miss):
			return Acceptance{}, errors.New("a miss is not a result id")
		}
	}
	return Acceptance{Commit: f.Commit, Trials: *f.Trials, BatchTurn: f.BatchTurn}, nil
}
