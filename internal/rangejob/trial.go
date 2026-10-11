package rangejob

import "time"

// Generators a trial's guest runs (ADR 0018, point 4): every event carries its sequence number, in
// exec argv or as the address of ptrace(PEEKDATA) of no process.
const (
	LoadExec   = "exec"
	LoadPtrace = "ptrace"
)

// Load is what a trial's guest generates: Rate numbered events per second for Seconds, a whole
// number of 10 s windows; Drop makes the reader skip one number, a control that only passes when
// the loss is seen.
type Load struct {
	Kind    string
	Rate    int
	Seconds int
	Drop    bool
}

// Trial is one entry of the closed table of acceptance trials (ADR 0018, point 1). Metric is the
// acceptance metric it measures, or, for a control whose load drops a number, the one whose loss
// it must show as a MISS. Wall
// bounds all its boots, Serial each boot's output; Count trials of it fit one batch.
type Trial struct {
	Name    string
	Metric  string
	Wall    time.Duration
	Serial  int64
	Boots   int
	Scratch int64
	Count   int
	Load    Load
}

// Batch bounds one acceptance batch and Setup what each trial adds to its wall clock (ADR 0018,
// points 1 and 5).
const (
	Batch = 30 * time.Minute
	Setup = time.Minute
)

var trials = []Trial{
	{Name: "rate-sustained", Metric: "sustained_rate", Wall: 14 * time.Minute, Serial: 1 << 20, Boots: 1, Count: 2,
		Load: Load{Kind: LoadExec, Rate: 2000, Seconds: 600}},
	{Name: "rate-burst", Metric: "burst_rate", Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1, Count: 3,
		Load: Load{Kind: LoadPtrace, Rate: 10000, Seconds: 10}},
	{Name: "rate-control-drop", Metric: "sustained_rate", Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1, Count: 1,
		Load: Load{Kind: LoadExec, Rate: 1000, Seconds: 30, Drop: true}},
}

// Trials returns a copy of the table.
func Trials() []Trial { return append([]Trial(nil), trials...) }

// Lookup returns the trial called name; nothing outside the table runs (T37).
func Lookup(name string) (Trial, bool) {
	for _, t := range trials {
		if t.Name == name {
			return t, true
		}
	}
	return Trial{}, false
}
