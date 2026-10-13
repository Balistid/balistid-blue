package rangerun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
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
// Miss is the result id of the MISS that stands for the commit.
type TrialRuns struct {
	Valid   int    `json:"valid"`
	Passed  int    `json:"passed"`
	Invalid int    `json:"invalid"`
	Miss    string `json:"miss,omitempty"`
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
// INVALID. A baseline run measures the sensor, never the collector (ADR 0018, point 4): its PASS
// passes nothing and its MISS does not stand.
func (a Acceptance) Record(tr rangejob.Trial, label, verdict, id string) Acceptance {
	out := Acceptance{Commit: a.Commit, Trials: make(map[string]TrialRuns, len(a.Trials)+1), BatchTurn: a.BatchTurn}
	for k, v := range a.Trials {
		out.Trials[k] = v
	}
	r := out.Trials[tr.Name]
	switch {
	case tr.Expect != "" && verdict == tr.Expect:
		r.Valid = min(r.Valid+1, tr.Count)
	case tr.Expect != "" || verdict != rangevm.Pass && verdict != rangevm.Miss:
		r.Invalid = min(r.Invalid+1, maxInvalid)
	case verdict == rangevm.Pass:
		r.Valid = min(r.Valid+1, tr.Count)
		if label != rangevm.LabelBaseline {
			r.Passed = min(r.Passed+1, r.Valid)
		}
	default: // MISS
		r.Valid = min(r.Valid+1, tr.Count)
		if label != rangevm.LabelBaseline && r.Miss == "" {
			r.Miss = id
		}
	}
	out.Trials[tr.Name] = r
	return out
}

// Verdict is metric's verdict so far: MISS once a counting run missed or its INVALID runs outnumber
// its runs, PASS when every run of its trials is a valid PASS that may pass it and every control gave
// its verdict, else "" (still open, or measured only by baseline runs).
func (a Acceptance) Verdict(metric string) string {
	runs, invalid, passed, complete := 0, 0, true, true
	for _, tr := range rangejob.Trials() {
		if tr.Metric != metric {
			continue
		}
		r := a.Trials[tr.Name]
		invalid += r.Invalid
		if tr.Expect != "" {
			complete = complete && r.Valid >= tr.Count
			continue
		}
		runs += tr.Count
		if r.Miss != "" {
			return rangevm.Miss
		}
		passed = passed && r.Passed >= tr.Count
	}
	switch {
	case runs == 0:
		return ""
	case invalid > runs:
		return rangevm.Miss
	case passed && complete:
		return rangevm.Pass
	}
	return ""
}

// Next is the next trial of the suite to run: the first in table order whose metric is undecided and
// that has fewer valid runs than its Count. ok is false when the suite has nothing left to run.
func (a Acceptance) Next() (tr rangejob.Trial, ok bool) {
	for _, t := range rangejob.Trials() {
		if a.Verdict(t.Metric) == "" && a.Trials[t.Name].Valid < t.Count {
			return t, true
		}
	}
	return rangejob.Trial{}, false
}

// LoadAcceptance reads path as LoadLedger reads the ledger. A missing file is an empty suite of no
// commit, so ForCommit starts one; anything else wrong is an error whose text never quotes the file.
func LoadAcceptance(path string) (Acceptance, error) {
	data, err := readFile(path, MaxAcceptanceBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return Acceptance{Trials: map[string]TrialRuns{}}, nil
	}
	if err != nil {
		return Acceptance{}, fmt.Errorf("acceptance: %w", err)
	}
	a, err := decodeAcceptance(data)
	if err != nil {
		return Acceptance{}, fmt.Errorf("acceptance %s is corrupt: %w", path, err)
	}
	return a, nil
}

// SaveAcceptance replaces the file at path through rangevm.WriteFileAtomic (mode 0600). It refuses,
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
	if _, err := decodeAcceptance(data); err != nil {
		return fmt.Errorf("save acceptance %s: %w", path, err)
	}
	if err := rangevm.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("save acceptance: %w", err)
	}
	return nil
}

// decodeAcceptance returns the suite in data only if it is one object of this schema, of a full
// commit id, naming only trials of the table, each within its counts. Errors are fixed text.
func decodeAcceptance(data []byte) (Acceptance, error) {
	if len(data) > MaxAcceptanceBytes {
		return Acceptance{}, fmt.Errorf("over %d bytes", MaxAcceptanceBytes)
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
	for name, r := range *f.Trials {
		tr, ok := rangejob.Lookup(name)
		switch {
		case !ok:
			return Acceptance{}, errors.New("a trial is not in the table")
		case r.Valid < 0 || r.Valid > tr.Count || r.Passed < 0 || r.Passed > r.Valid || r.Invalid < 0 || r.Invalid > maxInvalid:
			return Acceptance{}, errors.New("a trial's counts are out of range")
		case tr.Expect != "" && (r.Passed != 0 || r.Miss != ""):
			return Acceptance{}, errors.New("a control passed or missed a metric")
		case r.Miss != "" && !resultName.MatchString(r.Miss):
			return Acceptance{}, errors.New("a miss is not a result id")
		}
	}
	return Acceptance{Commit: f.Commit, Trials: *f.Trials, BatchTurn: f.BatchTurn}, nil
}
