package rangejob

import (
	"fmt"
	"slices"
	"time"
)

// Generators a trial's guest runs (ADR 0018, point 4): every event carries its sequence number, in
// exec argv or as the address of ptrace(PEEKDATA) of no process, or is handed to the measured writer
// of a failure control.
const (
	LoadExec   = "exec"
	LoadPtrace = "ptrace"
	LoadWrite  = "write"
	// LoadConnect connects to the collector's socket from peers it must refuse (refusal_summary_s).
	LoadConnect = "connect"
)

// Failure trials (ADR 0018, point 3): a reset by sysrq b, which boots the run again, or SIGKILL of
// the measured writer.
const (
	FailReset = "reset"
	FailKill  = "kill"
)

// Metrics of acceptance/0.toml the table measures.
const (
	MetricSustained = "sustained_rate"
	MetricBurst     = "burst_rate"
	MetricCrashLoss = "crash_loss_ms"
	MetricRecordMax = "record_max_kib"
	MetricRefusal   = "refusal_summary_s"
	MetricReady     = "ready_s"
	MetricExposure  = "systemd_exposure"
	MetricCPU       = "cpu_cores"
	MetricSilence   = "silence_alarm_s"
	MetricQuiet     = "announced_quiet_max_h"
)

// Injections of an alarm trial (ADR 0036): the host side of the tunnel down, the ledger killed and kept
// stopped, or a hard stop of the host's units and links, each without an announcement; or an announcement
// and then the host off, the ledger masked while the rest returns, or a brief return and a second one.
const (
	InjectWireGuard   = "wireguard"
	InjectLedger      = "ledger"
	InjectHardStop    = "hard-stop"
	InjectQuietOff    = "quiet-off"
	InjectQuietMasked = "quiet-masked"
	InjectQuietAgain  = "quiet-again"
)

// Methods: how the guest runs a trial and the host judges it, one per trial. A rate trial counts
// numbered events in the store; a writer failure kills or resets the measured writer of a control; a
// collector failure kills or resets the collector under load; a record trial stores oversized and
// malformed records, a refusal trial floods the socket from refused peers, a ready trial times a boot to
// health OK, an exposure trial scores the recorder's units and a CPU trial times the collector's processes under
// exec load (ADR 0023), an alarm trial times the Pi's alert at the range's ntfy sink after an injection
// (ADR 0036).
const (
	MethodRate             = "rate"
	MethodWriterFailure    = "writer-failure"
	MethodCollectorFailure = "collector-failure"
	MethodRecord           = "record"
	MethodRefusal          = "refusal"
	MethodReady            = "ready"
	MethodExposure         = "exposure"
	MethodCPU              = "cpu"
	MethodAlarm            = "alarm"
)

// Method is how tr is run and judged, "" for none: the guest reports it cannot run it and the host
// judges the run INVALID.
func (tr Trial) Method() string {
	switch {
	case tr.Inject != "":
		return alarmMethod(tr)
	case tr.Failure != "" && tr.Metric != MetricCrashLoss:
		return ""
	case tr.Failure != "" && tr.Load.Kind == LoadWrite:
		return MethodWriterFailure
	case tr.Failure != "" && tr.Load.Kind == LoadExec:
		return MethodCollectorFailure
	case tr.Failure != "":
		return ""
	}
	switch {
	case tr.Metric == MetricSustained || tr.Metric == MetricBurst:
		return MethodRate
	case tr.Metric == MetricRecordMax && tr.Load == (Load{}):
		return MethodRecord
	case tr.Metric == MetricRefusal && tr.Load.Kind == LoadConnect:
		return MethodRefusal
	case tr.Metric == MetricReady && tr.Load == (Load{}):
		return MethodReady
	case tr.Metric == MetricExposure && tr.Load == (Load{}):
		return MethodExposure
	case tr.Metric == MetricCPU && tr.Load.Kind == LoadExec && !tr.Load.Drop:
		return MethodCPU
	}
	return ""
}

// alarmMethod is MethodAlarm for an injection of tr's metric and nothing else, else "".
func alarmMethod(tr Trial) string {
	silence := tr.Inject == InjectWireGuard || tr.Inject == InjectLedger || tr.Inject == InjectHardStop
	quiet := tr.Inject == InjectQuietOff || tr.Inject == InjectQuietMasked || tr.Inject == InjectQuietAgain
	if tr.Load == (Load{}) && tr.Failure == "" && (tr.Metric == MetricSilence && silence || tr.Metric == MetricQuiet && quiet) {
		return MethodAlarm
	}
	return ""
}

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
// Count trials of it fit one batch. Failure is FailReset or FailKill for a failure trial, Inject what an
// alarm trial does to the host. A Trend
// trial measures its metric for comparison between commits and never decides it: that metric is
// decided outside the range (ADR 0025).
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
	Inject  string
	Trend   bool
}

// Batch bounds one acceptance batch and Setup what each trial adds to its wall clock (ADR 0018,
// points 1 and 5).
const (
	Batch = 30 * time.Minute
	Setup = time.Minute
)

var trials = slices.Concat([]Trial{
	{Name: "rate-sustained", Metric: MetricSustained, Wall: 14 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: sustainedScratch,
		Count: 2, Load: Load{Kind: LoadExec, Rate: 2000, Seconds: 600}},
	{Name: "rate-burst", Metric: MetricBurst, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 3,
		Load: Load{Kind: LoadPtrace, Rate: 10000, Seconds: 10}},
	{Name: "rate-control-drop", Metric: MetricSustained, Expect: ExpectMiss, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1,
		Scratch: StoreScratch, Count: 1, Load: Load{Kind: LoadExec, Rate: 1000, Seconds: 30, Drop: true}},
	// Failure controls of crash_loss_ms (ADR 0018, point 4): syncing every 250 ms must keep every
	// number up to H, a last sync 1500 ms before the reset and records held 2 s before write() under
	// a kill must lose some.
	{Name: "reset-control-sync250", Metric: MetricCrashLoss, Expect: ExpectPass, Wall: 5 * time.Minute, Serial: 1 << 20,
		Boots: 2, Scratch: StoreScratch, Count: 1, Failure: FailReset,
		Load: Load{Kind: LoadWrite, Rate: 2000, Seconds: 20, Writer: WriterPolicy{Sync: 250 * time.Millisecond}}},
	{Name: "reset-control-lastsync1500", Metric: MetricCrashLoss, Expect: ExpectMiss, Wall: 5 * time.Minute, Serial: 1 << 20,
		Boots: 2, Scratch: StoreScratch, Count: 1, Failure: FailReset,
		Load: Load{Kind: LoadWrite, Rate: 2000, Seconds: 20, Writer: WriterPolicy{Sync: 250 * time.Millisecond, LastSync: 1500 * time.Millisecond}}},
	{Name: "kill-control-buffer2s", Metric: MetricCrashLoss, Expect: ExpectMiss, Wall: 5 * time.Minute, Serial: 1 << 20,
		Boots: 1, Scratch: StoreScratch, Count: 1, Failure: FailKill,
		Load: Load{Kind: LoadWrite, Rate: 2000, Seconds: 20, Writer: WriterPolicy{Hold: 2 * time.Second}}},
},
	// crash_loss_ms (ADR 0023): 20 trials each of kill -9 and a reset of the collector under exec load at
	// sustained_rate, as rows of at most MaxTrials runs.
	repeated(Trial{Name: "kill-collector", Metric: MetricCrashLoss, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1,
		Scratch: StoreScratch, Count: 3, Failure: FailKill, Load: Load{Kind: LoadExec, Rate: 2000, Seconds: 20}}, 7),
	repeated(Trial{Name: "reset-collector", Metric: MetricCrashLoss, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 2,
		Scratch: StoreScratch, Count: 3, Failure: FailReset, Load: Load{Kind: LoadExec, Rate: 2000, Seconds: 20}}, 7),
	// record_max_kib and refusal_summary_s (ADR 0023, points 3 and 4).
	[]Trial{
		{Name: "record-max", Metric: MetricRecordMax, Wall: 6 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 3},
		{Name: "refusal-flood", Metric: MetricRefusal, Wall: 6 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 1,
			Load: Load{Kind: LoadConnect, Rate: 100, Seconds: 150}},
	},
	// ready_s, systemd_exposure and cpu_cores (ADR 0023, point 5): ready_s asks for 10 boots. cpu_cores
	// follows the guest's vCPUs, so the range keeps only its trend (ADR 0025).
	repeated(Trial{Name: "ready", Metric: MetricReady, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 3}, 4),
	[]Trial{
		{Name: "exposure", Metric: MetricExposure, Wall: 5 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 1},
		{Name: "cpu-1000", Metric: MetricCPU, Wall: 14 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: sustainedScratch, Count: 2,
			Load: Load{Kind: LoadExec, Rate: 1000, Seconds: 600}, Trend: true},
	},
	// silence_alarm_s at its real limit, one trial per cause; announced_quiet_max_h with the range's 20 min
	// cap, a trend, as its 24 h are decided on the Pi (ADR 0036, points 2 and 3).
	[]Trial{
		{Name: "silence-wireguard", Metric: MetricSilence, Wall: 20 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch,
			Count: 1, Inject: InjectWireGuard},
		{Name: "silence-ledger", Metric: MetricSilence, Wall: 20 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch,
			Count: 1, Inject: InjectLedger},
		{Name: "silence-hard-stop", Metric: MetricSilence, Wall: 20 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch,
			Count: 1, Inject: InjectHardStop},
		{Name: "quiet-off", Metric: MetricQuiet, Wall: 28 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 1,
			Inject: InjectQuietOff, Trend: true},
		{Name: "quiet-masked", Metric: MetricQuiet, Wall: 28 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 1,
			Inject: InjectQuietMasked, Trend: true},
		{Name: "quiet-again", Metric: MetricQuiet, Wall: 28 * time.Minute, Serial: 1 << 20, Boots: 1, Scratch: StoreScratch, Count: 1,
			Inject: InjectQuietAgain, Trend: true},
	},
)

// repeated returns n rows of tr named tr.Name-1 to tr.Name-n: a metric needs more trials than one row
// may run in a batch (MaxTrials).
func repeated(tr Trial, n int) []Trial {
	rows := make([]Trial, n)
	for i := range rows {
		rows[i] = tr
		rows[i].Name = fmt.Sprintf("%s-%d", tr.Name, i+1)
	}
	return rows
}

// Scratch disks for the collector's store (ADR 0022, point 2). StoreScratch holds ext4, the store's
// 64 MiB reserve, its shards and a failure control's 40000 numbers; a sustained trial stores 1.2
// million exec records, so it gets rangevm.MaxScratch until a range run measures the bytes per record.
const (
	StoreScratch     = 512 << 20
	sustainedScratch = 4 << 30
)

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
