package rangejob

import "time"

// Generators a trial's guest runs (ADR 0018, point 4): every event carries its sequence number, in
// exec argv or as the address of ptrace(PEEKDATA) of no process, or is handed to the measured writer
// of a failure control.
const (
	LoadExec   = "exec"
	LoadPtrace = "ptrace"
	LoadWrite  = "write"
)

// Failure trials (ADR 0018, point 3): a reset by sysrq b, which boots the run again, or SIGKILL of
// the measured writer.
const (
	FailReset = "reset"
	FailKill  = "kill"
)

// Verdicts a control must give; they are rangevm's PASS and MISS.
const (
	ExpectPass = "PASS"
	ExpectMiss = "MISS"
)

// Load is what a trial's guest generates: Rate numbered events per second for Seconds, a whole
// number of 10 s windows; Drop makes the reader skip one number. A write load fails at a random
// moment in its second half, and Writer is how its measured writer stores what it is handed.
type Load struct {
	Kind    string
	Rate    int
	Seconds int
	Drop    bool
	Writer  WriterPolicy
}

// WriterPolicy is the measured writer of a failure control: it holds each number Hold before
// write(), fsyncs every Sync, and stops syncing LastSync before the failure (0: syncs to the end).
type WriterPolicy struct {
	Hold     time.Duration
	Sync     time.Duration
	LastSync time.Duration
}

// Trial is one entry of the closed table of acceptance trials (ADR 0018, point 1). Metric is the
// acceptance metric it measures; a control instead checks the measurement of that metric and must
// give Expect, never counting for the metric. Wall bounds all its boots, Serial each boot's output;
// Count trials of it fit one batch. Failure is FailReset or FailKill for a failure trial.
type Trial struct {
	Name    string
	Metric  string
	Expect  string
	Wall    time.Duration
	Serial  int64
	Boots   int
	Scratch int64
	Count   int
	Failure string
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
	{Name: "rate-control-drop", Metric: "sustained_rate", Expect: ExpectMiss, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1,
		Count: 1, Load: Load{Kind: LoadExec, Rate: 1000, Seconds: 30, Drop: true}},
	// Failure controls of crash_loss_ms (ADR 0018, point 4): syncing every 250 ms must keep every
	// number up to H, a last sync 1500 ms before the reset and records held 2 s before write() under
	// a kill must lose some.
	{Name: "reset-control-sync250", Metric: "crash_loss_ms", Expect: ExpectPass, Wall: 5 * time.Minute, Serial: 1 << 20,
		Boots: 2, Scratch: scratch, Count: 1, Failure: FailReset,
		Load: Load{Kind: LoadWrite, Rate: 2000, Seconds: 20, Writer: WriterPolicy{Sync: 250 * time.Millisecond}}},
	{Name: "reset-control-lastsync1500", Metric: "crash_loss_ms", Expect: ExpectMiss, Wall: 5 * time.Minute, Serial: 1 << 20,
		Boots: 2, Scratch: scratch, Count: 1, Failure: FailReset,
		Load: Load{Kind: LoadWrite, Rate: 2000, Seconds: 20, Writer: WriterPolicy{Sync: 250 * time.Millisecond, LastSync: 1500 * time.Millisecond}}},
	{Name: "kill-control-buffer2s", Metric: "crash_loss_ms", Expect: ExpectMiss, Wall: 5 * time.Minute, Serial: 1 << 20,
		Boots: 1, Scratch: scratch, Count: 1, Failure: FailKill,
		Load: Load{Kind: LoadWrite, Rate: 2000, Seconds: 20, Writer: WriterPolicy{Hold: 2 * time.Second}}},
}

// scratch is a failure control's scratch disk: room for ext4, its journal and 40000 records.
const scratch = 64 << 20

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
