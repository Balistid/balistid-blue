package rangerun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

var testCommit = strings.Repeat("a", 40)

// fakeVM stands in for rangevm.Run: it records each call with the ledger on disk at that moment.
type fakeVM struct {
	disks   [][]byte
	ledgers []Ledger
	verdict string // what the self-test judge says
	facts   func(disk []byte) []rangevm.Record
}

type testRunner struct {
	*Runner
	vm   *fakeVM
	root string
}

func newTestRunner(t *testing.T, now time.Time, l Ledger) testRunner {
	t.Helper()
	root := t.TempDir()
	state, inbox, results := filepath.Join(root, "state"), filepath.Join(root, "inbox"), resultsRoot(t)
	images := filepath.Join(state, "cache", "images", "x")
	for _, d := range []string{inbox, images} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(state, 0o700); err != nil { //nolint:gosec // a directory needs its x bit
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(images, "image.raw"):      "image",
		filepath.Join(images, "image.manifest"): `{"manifest_version":1,"packages":[{"name":"linux","version":"7.2.8"}]}`,
		filepath.Join(images, "commit"):         testCommit + "\n",
		filepath.Join(state, "image"):           filepath.Join(images, "image.raw") + "\n",
	}
	for p, data := range files {
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := SaveLedger(filepath.Join(state, "ledger.json"), l); err != nil {
		t.Fatal(err)
	}
	vm := &fakeVM{verdict: rangevm.Pass}
	r := &Runner{
		State: state, Inbox: inbox, Results: results, Commit: testCommit,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		run: func(_ context.Context, base, _ string, serial io.Writer, disk []byte) (rangevm.Outcome, error) {
			if base != filepath.Join(images, "image.raw") {
				t.Errorf("ran %s", base)
			}
			got, err := LoadLedger(filepath.Join(state, "ledger.json"))
			if err != nil {
				t.Errorf("ledger at run time: %v", err)
			}
			vm.disks, vm.ledgers = append(vm.disks, disk), append(vm.ledgers, got)
			_, _ = serial.Write([]byte("boot\x1b[0m\n"))
			if vm.facts != nil {
				return rangevm.Outcome{Facts: vm.facts(disk)}, nil
			}
			return rangevm.Outcome{}, nil
		},
		selftest: func(rangevm.Outcome, string, string) (string, string) { return vm.verdict, "judged" },
		admit:    func(context.Context, []DiskNeed) error { return nil },
		watch:    func(ctx context.Context) (context.Context, func()) { return context.WithCancel(ctx) },
		now:      func() time.Time { return now },
		owner:    owner,
	}
	return testRunner{Runner: r, vm: vm, root: root}
}

// evidenceDone is a ledger whose evidence for testCommit is fresh, so a tick takes an agent job.
func evidenceDone(now time.Time) Ledger {
	return Ledger{Evidence: Evidence{Commit: testCommit, LastPass: now}}
}

func (tr testRunner) addJob(t *testing.T, name, request string, program []byte) {
	t.Helper()
	dir := filepath.Join(tr.Inbox, name)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, rangejob.RequestFile), []byte(request), 0o600); err != nil {
		t.Fatal(err)
	}
	if program != nil {
		if err := os.WriteFile(filepath.Join(dir, "probe.sh"), program, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (tr testRunner) results(t *testing.T, label string) []Result {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(tr.Results, label))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []Result
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(tr.Results, label, e.Name(), "result.json")) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		var r Result
		if err := json.Unmarshal(data, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (tr testRunner) ledger(t *testing.T) Ledger {
	t.Helper()
	l, err := LoadLedger(tr.ledgerPath())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

const execRequest = `{"schema_version":1,"kind":"exec","program":"probe.sh","timeout_s":7}`

var program = []byte("#!/bin/sh\necho hi\n")

// execFacts is a complete exec report of program that printed "hi".
func execFacts(sha [32]byte) func([]byte) []rangevm.Record {
	return func([]byte) []rangevm.Record {
		fact := func(n, v string) rangevm.Record {
			return rangevm.Record{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindFact, Name: n, Value: v}
		}
		return []rangevm.Record{
			fact(rangevm.FactKernel, rangevm.TargetKernel), fact(rangevm.FactJobSHA256, hex.EncodeToString(sha[:])),
			fact(rangevm.FactJobResult, "success"), fact(rangevm.FactJobExit, "0"), fact(rangevm.FactJobOutCut, "no"),
			fact(rangevm.FactJobOut, "aGkK"), fact("canary", "seen"), fact(rangevm.FactJobLaurelCut, "no"),
		}
	}
}

// Evidence goes first: a fresh ledger runs the runner's own image with no job disk, and the inbox
// job waits untouched.
func TestTickRunsEvidenceFirst(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, Ledger{})
	tr.addJob(t, "job-1", execRequest, program)
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(tr.vm.disks) != 1 || tr.vm.disks[0] != nil {
		t.Fatalf("runs %d, first with a job disk: %v", len(tr.vm.disks), tr.vm.disks)
	}
	ev := tr.results(t, LabelEvidence)
	if len(ev) != 1 || ev[0].Verdict != rangevm.Pass || ev[0].Job != nil || ev[0].RunnerCommit != testCommit {
		t.Fatalf("evidence results %+v", ev)
	}
	l := tr.ledger(t)
	if l.Evidence.Commit != testCommit || !l.Evidence.LastPass.Equal(now) || len(l.Entries) != 0 || ev[0].Label != LabelEvidence {
		t.Fatalf("ledger after evidence: %+v", l)
	}
	if tr.results(t, LabelAgent) != nil {
		t.Fatal("an agent job ran in the evidence tick")
	}
}

// The exec job's program goes on a job disk with its time limit; the ledger on disk already holds
// the job when the VM starts; the report is judged against the program's own sha256.
func TestTickRunsAnExecJob(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	tr.addJob(t, "job-1", execRequest, program)
	tr.vm.facts = execFacts(sha256.Sum256(program))
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(tr.vm.disks) != 1 {
		t.Fatalf("%d runs", len(tr.vm.disks))
	}
	disk, err := rangejob.DecodeDisk(tr.vm.disks[0])
	if err != nil || !bytes.Equal(disk.Program, program) || disk.TimeoutS != 7 {
		t.Fatalf("job disk: %d s, %v", disk.TimeoutS, err)
	}
	if got := tr.vm.ledgers[0]; len(got.Entries) != 1 || got.Entries[0].Status != Taken {
		t.Fatalf("ledger on disk when the VM started: %+v", got)
	}
	res := tr.results(t, LabelAgent)
	if len(res) != 1 || res[0].Verdict != rangevm.Ran || res[0].Job == nil || res[0].Job.TimeoutS != 7 || res[0].Runs[0].OutBytes != 3 {
		t.Fatalf("agent results %+v", res)
	}
	dir := filepath.Join(tr.Results, LabelAgent, res[0].ID)
	if out, err := os.ReadFile(filepath.Join(dir, "job-out.txt")); err != nil || string(out) != `hi\x0a` { //nolint:gosec // test temp dir
		t.Fatalf("job-out.txt = %q, %v", out, err)
	}
	if serial, err := os.ReadFile(filepath.Join(dir, "serial.txt")); err != nil || strings.ContainsRune(string(serial), 0x1b) { //nolint:gosec // test temp dir
		t.Fatalf("serial.txt = %q, %v", serial, err)
	}
}

func TestTickJudgesAnotherProgramInvalid(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	tr.addJob(t, "job-1", execRequest, program)
	tr.vm.facts = execFacts(sha256.Sum256([]byte("other")))
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	res := tr.results(t, LabelAgent)
	if len(res) != 1 || res[0].Verdict != rangevm.Invalid {
		t.Fatalf("agent results %+v", res)
	}
	if res[0].Runs[0].JobExit != nil {
		t.Fatalf("an INVALID report carries an exit: %d", *res[0].Runs[0].JobExit)
	}
	if _, err := os.Stat(filepath.Join(tr.Results, LabelAgent, res[0].ID, "job-out.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an INVALID report kept output: %v", err)
	}
}

// A run job is the self-test, once per trial, with no job disk, and never evidence.
func TestTickRunsARunJobPerTrial(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	tr.addJob(t, "job-1", `{"schema_version":1,"kind":"run","trials":2}`, nil)
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(tr.vm.disks) != 2 || tr.vm.disks[0] != nil || tr.vm.disks[1] != nil {
		t.Fatalf("runs %v", tr.vm.disks)
	}
	if res := tr.results(t, LabelAgent); len(res) != 1 || len(res[0].Runs) != 2 || res[0].Label != LabelAgent {
		t.Fatalf("agent results %+v", res)
	}
	if ev := tr.results(t, LabelEvidence); ev != nil {
		t.Fatalf("an agent run became evidence: %+v", ev)
	}
}

// Nothing runs when the ledger cannot be written first, is missing or is corrupt, when there is no
// image of the runner's commit, or after a failed evidence run.
func TestTickRunsNothingItCannotAccountFor(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		ledger Ledger
		break_ func(t *testing.T, tr testRunner)
	}{
		"ledger not writable": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			if err := os.Chmod(tr.State, 0o500); err != nil { //nolint:gosec // a state directory made read-only for the test
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(tr.State, 0o700) }) //nolint:gosec // restores the test directory
		}},
		"ledger missing": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			if err := os.Remove(tr.ledgerPath()); err != nil {
				t.Fatal(err)
			}
		}},
		"ledger corrupt": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			if err := os.WriteFile(tr.ledgerPath(), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		"no image recorded": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			if err := os.Remove(tr.imagePath()); err != nil {
				t.Fatal(err)
			}
		}},
		"image of another commit": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			tr.Commit = strings.Repeat("b", 40)
		}},
		"commit failed evidence": {Ledger{Evidence: Evidence{Commit: testCommit, LastPass: now, Failed: []FailedRun{{Commit: testCommit, ID: "20261006T090000Z-00000001"}}}}, func(*testing.T, testRunner) {}},
		"state others can write": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			if err := os.Chmod(tr.State, 0o770); err != nil { //nolint:gosec // a misinstalled state directory for the test
				t.Fatal(err)
			}
		}},
		"admission cannot read the host": {evidenceDone(now), func(t *testing.T, tr testRunner) {
			tr.admit = func(context.Context, []DiskNeed) error { return errors.New("meminfo unreadable") }
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tr := newTestRunner(t, now, c.ledger)
			tr.addJob(t, "job-1", execRequest, program)
			c.break_(t, tr)
			if err := tr.Tick(t.Context()); err == nil {
				t.Fatal("Tick succeeded")
			}
			if len(tr.vm.disks) != 0 {
				t.Fatalf("%d runs", len(tr.vm.disks))
			}
		})
	}
}

// A refused admission runs nothing and leaves the ledger byte for byte: no quota is used.
func TestRefusedAdmissionCostsNoQuota(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	tr.addJob(t, "job-1", execRequest, program)
	before, err := os.ReadFile(tr.ledgerPath())
	if err != nil {
		t.Fatal(err)
	}
	tr.admit = func(context.Context, []DiskNeed) error { return fmt.Errorf("%w: short of memory", ErrNotAdmitted) }
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(tr.ledgerPath())
	if err != nil || !bytes.Equal(before, after) || len(tr.vm.disks) != 0 {
		t.Fatalf("ledger changed %v or %d runs", !bytes.Equal(before, after), len(tr.vm.disks))
	}
}

// A run the memory watch stopped is INVALID, whatever the judge would have said.
func TestAStoppedRunIsInvalid(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, Ledger{})
	tr.watch = func(ctx context.Context) (context.Context, func()) {
		c, cancel := context.WithCancelCause(ctx)
		cancel(ErrMemoryReserve)
		return c, func() {}
	}
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	ev := tr.results(t, LabelEvidence)
	if len(ev) != 1 || ev[0].Verdict != rangevm.Invalid || !strings.Contains(ev[0].Reason, "stopped") {
		t.Fatalf("evidence results %+v", ev)
	}
}

// One FAIL fails the commit: it is recorded, and the next tick refuses to run anything.
func TestAFailedEvidenceRunStopsTheRunner(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, Ledger{})
	tr.vm.verdict = rangevm.Fail
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	ev := tr.results(t, LabelEvidence)
	if l := tr.ledger(t); len(ev) != 1 || len(l.Evidence.Failed) != 1 || l.Evidence.Failed[0] != (FailedRun{testCommit, ev[0].ID}) {
		t.Fatalf("failed %+v, results %+v", l.Evidence.Failed, ev)
	}
	tr.now = func() time.Time { return now.Add(2 * EvidenceEvery) }
	if err := tr.Tick(t.Context()); err == nil || len(tr.vm.disks) != 1 {
		t.Fatalf("second tick: %v, %d runs", err, len(tr.vm.disks))
	}
}

// Only a PASS counts as evidence: after INVALID or UNKNOWN, which agents can cause, the next tick
// tries again and the inbox job waits.
func TestOnlyAPassCountsAsEvidence(t *testing.T) {
	for _, v := range []string{rangevm.Invalid, rangevm.Unknown} {
		now := time.Now()
		tr := newTestRunner(t, now, Ledger{})
		tr.addJob(t, "job-1", execRequest, program)
		tr.vm.verdict = v
		for range 2 {
			if err := tr.Tick(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if l := tr.ledger(t); len(tr.vm.disks) != 2 || tr.vm.disks[1] != nil || !l.Evidence.LastPass.IsZero() || tr.results(t, LabelAgent) != nil {
			t.Fatalf("%s: %d runs, evidence %+v", v, len(tr.vm.disks), l.Evidence)
		}
	}
}

// Evidence is due again for another commit, a day after the last PASS, or when the last PASS is in
// the future; otherwise the agent job runs.
func TestEvidenceIsDue(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		ev       Evidence
		evidence bool
	}{
		"fresh pass":     {Evidence{Commit: testCommit, LastPass: now.Add(-time.Hour)}, false},
		"a day old":      {Evidence{Commit: testCommit, LastPass: now.Add(-EvidenceEvery)}, true},
		"in the future":  {Evidence{Commit: testCommit, LastPass: now.Add(time.Hour)}, true},
		"another commit": {Evidence{Commit: strings.Repeat("b", 40), LastPass: now}, true},
	} {
		tr := newTestRunner(t, now, Ledger{Evidence: c.ev})
		tr.addJob(t, "job-1", execRequest, program)
		tr.vm.facts = execFacts(sha256.Sum256(program))
		if err := tr.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := tr.vm.disks[0] == nil; got != c.evidence {
			t.Errorf("%s: evidence run %v, want %v", name, got, c.evidence)
		}
	}
}

// A job of several runs is as bad as its worst run.
func TestARunJobIsItsWorstTrial(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	tr.addJob(t, "job-1", `{"schema_version":1,"kind":"run","trials":3}`, nil)
	verdicts := []string{rangevm.Pass, rangevm.Fail, rangevm.Invalid}
	tr.selftest = func(rangevm.Outcome, string, string) (string, string) {
		v := verdicts[0]
		verdicts = verdicts[1:]
		return v, "judged"
	}
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if res := tr.results(t, LabelAgent); len(res) != 1 || res[0].Verdict != rangevm.Fail {
		t.Fatalf("agent results %+v", res)
	}
}

// While the VM runs, the result on disk already says INVALID, so a killed runner leaves no gap.
func TestAnInvalidResultStandsWhileTheVMRuns(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, Ledger{})
	run := tr.run
	tr.run = func(ctx context.Context, base, parent string, serial io.Writer, disk []byte) (rangevm.Outcome, error) {
		if res := tr.results(t, LabelEvidence); len(res) != 1 || res[0].Verdict != rangevm.Invalid {
			t.Errorf("result during the run: %+v", res)
		}
		return run(ctx, base, parent, serial, disk)
	}
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// Admission is asked for the worst case of any job before one is taken.
func TestAdmissionIsAskedForTheWorstCase(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	var got []DiskNeed
	tr.admit = func(_ context.Context, needs []DiskNeed) error { got = needs; return nil }
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	want := []DiskNeed{
		{filepath.Join(tr.State, "cache", "runs"), 3*uint64(rangevm.WriteCap(int64(len("image")))) + rangejob.DiskBytes}, //nolint:gosec // a small constant
		{tr.Results, maxKeptBytes},
		{tr.State, 2 * MaxLedgerBytes},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("needs %+v, want %+v", got, want)
	}
}

// A failed evidence run's result outlives retention, also after another commit is installed.
func TestFailedRunsOutliveRetention(t *testing.T) {
	now := time.Now()
	failed := "20200101T000000Z-0000000f"
	tr := newTestRunner(t, now, Ledger{Evidence: Evidence{Failed: []FailedRun{{strings.Repeat("b", 40), failed}}}})
	names := []string{failed}
	for i := range KeepEvidence + 2 {
		names = append(names, fmt.Sprintf("20210101T%06dZ-00000000", i))
	}
	for _, n := range names {
		if err := os.Mkdir(filepath.Join(tr.Results, LabelEvidence, n), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tr.Results, LabelEvidence, failed)); err != nil {
		t.Fatalf("the failed run's result was pruned: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tr.Results, LabelEvidence, names[1])); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retention kept the oldest plain result: %v", err)
	}
}

// Build records the image and creates a missing ledger; an existing ledger, valid or not, is left
// byte for byte; a build with no image records nothing.
func TestBuildRecordsTheImageAndKeepsTheLedger(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		ledger  []byte // nil: no ledger
		image   string
		err     error
		wantErr bool
	}{
		"first install":   {nil, "/img/image.raw", nil, false},
		"ledger kept":     {[]byte("keep"), "/img/image.raw", nil, true},
		"retention error": {nil, "/img/image.raw", errors.New("retention"), true},
		"build failed":    {nil, "", errors.New("mkosi"), true},
	} {
		tr := newTestRunner(t, now, Ledger{})
		if err := os.Remove(tr.ledgerPath()); err != nil {
			t.Fatal(err)
		}
		if c.ledger != nil {
			if err := os.WriteFile(tr.ledgerPath(), c.ledger, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Remove(tr.imagePath()); err != nil {
			t.Fatal(err)
		}
		tr.build = func(_ context.Context, _, _ string, _ io.Writer, commit string) (string, error) {
			if commit != testCommit {
				t.Errorf("built %s", commit)
			}
			return c.image, c.err
		}
		err := tr.Build(t.Context(), "/objects", io.Discard)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Build = %v", name, err)
		}
		recorded, _ := os.ReadFile(tr.imagePath())
		if want := c.image; (want == "") != (recorded == nil) || (want != "" && string(recorded) != want+"\n") {
			t.Errorf("%s: recorded image %q", name, recorded)
		}
		got, _ := os.ReadFile(tr.ledgerPath())
		switch {
		case c.ledger != nil && !bytes.Equal(got, c.ledger):
			t.Errorf("%s: an existing ledger was rewritten", name)
		case c.ledger == nil && c.image != "":
			if _, err := LoadLedger(tr.ledgerPath()); err != nil {
				t.Errorf("%s: no ledger created: %v", name, err)
			}
		}
	}
}

// The evidence run is pending in the ledger while the VM runs.
func TestEvidenceIsPendingWhileTheVMRuns(t *testing.T) {
	tr := newTestRunner(t, time.Now(), Ledger{})
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	ev := tr.results(t, LabelEvidence)
	if len(ev) != 1 || tr.vm.ledgers[0].Evidence.Pending != ev[0].ID || tr.ledger(t).Evidence.Pending != "" {
		t.Fatalf("pending at run %q, after %q, results %+v", tr.vm.ledgers[0].Evidence.Pending, tr.ledger(t).Evidence.Pending, ev)
	}
}

// A FAIL whose ledger save failed is found by the next tick, which records it and runs nothing.
func TestAFailIsNotLostWhenTheLedgerCannotBeSaved(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, Ledger{})
	tr.vm.verdict = rangevm.Fail
	run := tr.run
	tr.run = func(ctx context.Context, base, parent string, serial io.Writer, disk []byte) (rangevm.Outcome, error) {
		if err := os.Chmod(tr.State, 0o500); err != nil { //nolint:gosec // a state directory made read-only for the test
			t.Fatal(err)
		}
		return run(ctx, base, parent, serial, disk)
	}
	if err := tr.Tick(t.Context()); err == nil {
		t.Fatal("a failed save went unreported")
	}
	if err := os.Chmod(tr.State, 0o700); err != nil { //nolint:gosec // a directory needs its x bit
		t.Fatal(err)
	}
	tr.run = run
	if err := tr.Tick(t.Context()); err == nil || len(tr.vm.disks) != 1 {
		t.Fatalf("after the lost save: %v, %d runs", err, len(tr.vm.disks))
	}
	if l := tr.ledger(t); len(l.Evidence.Failed) != 1 || l.Evidence.Pending != "" {
		t.Fatalf("evidence %+v", l.Evidence)
	}
}

// A pending run whose result is still the pessimistic INVALID (the runner died mid-run) counts for
// nothing: the next tick runs evidence again.
func TestAnUnfinishedPendingRunIsRunAgain(t *testing.T) {
	tr := newTestRunner(t, time.Now(), Ledger{})
	dir, id, err := NewResultDir(tr.Results, LabelEvidence, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteResult(dir, Result{ID: id, Label: LabelEvidence, RunnerCommit: testCommit, Verdict: rangevm.Invalid, Runs: []Run{{Verdict: rangevm.Invalid}}}); err != nil {
		t.Fatal(err)
	}
	if err := SaveLedger(tr.ledgerPath(), Ledger{Evidence: Evidence{Pending: id, Failed: []FailedRun{}}}); err != nil {
		t.Fatal(err)
	}
	if err := tr.Tick(t.Context()); err != nil || len(tr.vm.disks) != 1 || len(tr.ledger(t).Evidence.Failed) != 0 {
		t.Fatalf("tick %v, %d runs, evidence %+v", err, len(tr.vm.disks), tr.ledger(t).Evidence)
	}
}

// Every result is logged with its decision, an escaped reason and the rule version.
func TestResultsAreLoggedWithReasonAndRule(t *testing.T) {
	tr := newTestRunner(t, time.Now(), Ledger{})
	var log bytes.Buffer
	tr.Log = slog.New(slog.NewTextHandler(&log, nil))
	tr.selftest = func(rangevm.Outcome, string, string) (string, string) { return rangevm.Pass, "ok\x1b[2J" }
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	line := log.String()
	if !strings.Contains(line, "verdict=PASS") || !strings.Contains(line, `ok\x1b[2J`) || !strings.Contains(line, RuleVersion) || strings.ContainsRune(line, 0x1b) {
		t.Fatalf("log: %q", line)
	}
}

// Fail-closed branches each have their case: a VM that cannot start or reports INVALID, a stop
// between trials, an UNKNOWN trial, state someone else owns, a pending run without its result.
func TestRunnerFailsClosed(t *testing.T) {
	now := time.Now()
	t.Run("vm error", func(t *testing.T) {
		tr := newTestRunner(t, now, Ledger{})
		tr.run = func(context.Context, string, string, io.Writer, []byte) (rangevm.Outcome, error) {
			return rangevm.Outcome{}, errors.New("no kvm")
		}
		if err := tr.Tick(t.Context()); err == nil {
			t.Fatal("a VM that could not start was not an error")
		}
		if ev := tr.results(t, LabelEvidence); len(ev) != 1 || ev[0].Verdict != rangevm.Invalid {
			t.Fatalf("results %+v", ev)
		}
	})
	t.Run("vm invalid", func(t *testing.T) {
		tr := newTestRunner(t, now, Ledger{})
		tr.run = func(context.Context, string, string, io.Writer, []byte) (rangevm.Outcome, error) {
			return rangevm.Outcome{Invalid: "vm: exit 1"}, nil
		}
		if err := tr.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		if ev := tr.results(t, LabelEvidence); len(ev) != 1 || ev[0].Verdict != rangevm.Invalid || !tr.ledger(t).Evidence.LastPass.IsZero() {
			t.Fatalf("results %+v", ev)
		}
	})
	t.Run("stopped between trials", func(t *testing.T) {
		tr := newTestRunner(t, now, evidenceDone(now))
		tr.addJob(t, "job-1", `{"schema_version":1,"kind":"run","trials":3}`, nil)
		ctx, cancel := context.WithCancel(t.Context())
		run := tr.run
		tr.run = func(c context.Context, base, parent string, serial io.Writer, disk []byte) (rangevm.Outcome, error) {
			cancel()
			return run(c, base, parent, serial, disk)
		}
		_ = tr.Tick(ctx)
		if res := tr.results(t, LabelAgent); len(tr.vm.disks) != 1 || len(res) != 1 || res[0].Verdict != rangevm.Invalid {
			t.Fatalf("%d runs, results %+v", len(tr.vm.disks), res)
		}
	})
	t.Run("unknown trial", func(t *testing.T) {
		tr := newTestRunner(t, now, evidenceDone(now))
		tr.addJob(t, "job-1", `{"schema_version":1,"kind":"run","trials":2}`, nil)
		verdicts := []string{rangevm.Pass, rangevm.Unknown}
		tr.selftest = func(rangevm.Outcome, string, string) (string, string) {
			v := verdicts[0]
			verdicts = verdicts[1:]
			return v, "judged"
		}
		if err := tr.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		if res := tr.results(t, LabelAgent); len(res) != 1 || res[0].Verdict != rangevm.Unknown {
			t.Fatalf("results %+v", res)
		}
	})
	t.Run("state of another owner", func(t *testing.T) {
		tr := newTestRunner(t, now, Ledger{})
		tr.owner = func(os.FileInfo) int { return os.Geteuid() + 1 }
		if err := tr.Tick(t.Context()); err == nil || len(tr.vm.disks) != 0 {
			t.Fatalf("tick %v, %d runs", err, len(tr.vm.disks))
		}
		if err := tr.Build(t.Context(), "/objects", io.Discard); err == nil {
			t.Fatal("build in state of another owner")
		}
	})
	t.Run("build in writable state", func(t *testing.T) {
		tr := newTestRunner(t, now, Ledger{})
		if err := os.Chmod(tr.State, 0o770); err != nil { //nolint:gosec // a misinstalled state directory for the test
			t.Fatal(err)
		}
		tr.build = func(context.Context, string, string, io.Writer, string) (string, error) {
			t.Error("built in a state directory others can write")
			return "", nil
		}
		if err := tr.Build(t.Context(), "/objects", io.Discard); err == nil {
			t.Fatal("build accepted the state directory")
		}
	})
	for name, write := range map[string]func(dir, id string) error{
		"pending without a result": func(string, string) error { return nil },
		"pending with another id": func(dir, _ string) error {
			return WriteResult(dir, Result{ID: "20200101T000000Z-00000000", Label: LabelEvidence, Verdict: rangevm.Fail, Runs: []Run{{}}})
		},
		"pending with another label": func(dir, id string) error {
			return WriteResult(dir, Result{ID: id, Label: LabelAgent, Verdict: rangevm.Fail, Runs: []Run{{Verdict: rangevm.Fail}}, RunnerCommit: testCommit})
		},
		"pending with data after the result": func(dir, id string) error {
			if err := WriteResult(dir, Result{ID: id, Label: LabelEvidence, Verdict: rangevm.Fail, Runs: []Run{{Verdict: rangevm.Fail}}, RunnerCommit: testCommit}); err != nil {
				return err
			}
			f, err := os.OpenFile(filepath.Join(dir, "result.json"), os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // test temp dir
			if err != nil {
				return err
			}
			_, err = f.WriteString("{}")
			return errors.Join(err, f.Close())
		},
		"pending without its runs": func(dir, id string) error {
			return WriteResult(dir, Result{ID: id, Label: LabelEvidence, Verdict: rangevm.Fail, RunnerCommit: testCommit})
		},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTestRunner(t, now, Ledger{})
			dir, id, err := NewResultDir(tr.Results, LabelEvidence, "", now)
			if err != nil {
				t.Fatal(err)
			}
			if err := write(dir, id); err != nil {
				t.Fatal(err)
			}
			if err := SaveLedger(tr.ledgerPath(), Ledger{Evidence: Evidence{Pending: id, Failed: []FailedRun{}}}); err != nil {
				t.Fatal(err)
			}
			if err := tr.Tick(t.Context()); err == nil || len(tr.vm.disks) != 0 || tr.ledger(t).Evidence.Pending != id {
				t.Fatalf("tick %v, %d runs, pending %q", err, len(tr.vm.disks), tr.ledger(t).Evidence.Pending)
			}
		})
	}
}

// No failed run is ever dropped: a ledger past MaxFailed is one SaveLedger refuses, so the runner
// stops loudly instead.
func TestAFailedRunIsNeverDropped(t *testing.T) {
	var l Ledger
	for i := range MaxFailed + 1 {
		l.Evidence.fail(testCommit, fmt.Sprintf("20261006T0900%02dZ-00000000", i))
	}
	if len(l.Evidence.Failed) != MaxFailed+1 || l.Evidence.Failed[0].ID != "20261006T090000Z-00000000" {
		t.Fatalf("failed %+v", l.Evidence.Failed)
	}
	if err := SaveLedger(filepath.Join(t.TempDir(), "ledger.json"), l); err == nil {
		t.Fatal("a ledger over MaxFailed was saved")
	}
}

func TestTheRunnerStopsAtMaxFailed(t *testing.T) {
	failed := make([]FailedRun, MaxFailed)
	for i := range failed {
		failed[i] = FailedRun{Commit: strings.Repeat("b", 40), ID: fmt.Sprintf("20261006T0900%02dZ-00000000", i)}
	}
	tr := newTestRunner(t, time.Now(), Ledger{Evidence: Evidence{Failed: failed}})
	if err := tr.Tick(t.Context()); err == nil || len(tr.vm.disks) != 0 {
		t.Fatalf("tick %v, %d runs", err, len(tr.vm.disks))
	}
}

// Once evidence is due, setting the clock back does not make the old PASS fresh again: the
// latch in the ledger holds until a new PASS.
func TestDueEvidenceSurvivesAClockSetBack(t *testing.T) {
	pass := time.Now().Add(-25 * time.Hour)
	tr := newTestRunner(t, time.Now(), Ledger{Evidence: Evidence{Commit: testCommit, LastPass: pass}})
	tr.addJob(t, "job-1", execRequest, program)
	tr.admit = func(context.Context, []DiskNeed) error { return ErrNotAdmitted }
	if err := tr.Tick(t.Context()); err != nil || !tr.ledger(t).Evidence.Due {
		t.Fatalf("tick %v, due %v", err, tr.ledger(t).Evidence.Due)
	}
	tr.admit = func(context.Context, []DiskNeed) error { return nil }
	tr.now = func() time.Time { return pass.Add(time.Hour) }
	if err := tr.Tick(t.Context()); err != nil || len(tr.vm.disks) != 1 || tr.vm.disks[0] != nil {
		t.Fatalf("after the clock went back: %v, runs %v", err, tr.vm.disks)
	}
	if l := tr.ledger(t); l.Evidence.Due || !l.Evidence.LastPass.Equal(pass.Add(time.Hour)) {
		t.Fatalf("evidence after the PASS %+v", l.Evidence)
	}
}

// A PASS counts only once its result is on disk; until then the run stays pending, and the next
// tick finds the INVALID it left and runs evidence again. A FAIL counts even then.
func TestAPassCountsOnlyWithItsResult(t *testing.T) {
	for _, verdict := range []string{rangevm.Pass, rangevm.Fail} {
		tr := newTestRunner(t, time.Now(), Ledger{})
		tr.vm.verdict = verdict
		run := tr.run
		var dir string
		tr.run = func(ctx context.Context, base, parent string, serial io.Writer, disk []byte) (rangevm.Outcome, error) {
			ev := tr.results(t, LabelEvidence)
			dir = filepath.Join(tr.Results, LabelEvidence, ev[0].ID)
			if err := os.Chmod(dir, 0o550|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
			return run(ctx, base, parent, serial, disk)
		}
		if err := tr.Tick(t.Context()); err == nil {
			t.Fatalf("%s: a lost result went unreported", verdict)
		}
		if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		l := tr.ledger(t)
		switch verdict {
		case rangevm.Pass:
			if !l.Evidence.LastPass.IsZero() || l.Evidence.Pending == "" || !l.Evidence.Due {
				t.Fatalf("PASS without its result: %+v", l.Evidence)
			}
			tr.run = run
			if err := tr.Tick(t.Context()); err != nil || len(tr.vm.disks) != 2 || tr.ledger(t).Evidence.LastPass.IsZero() {
				t.Fatalf("rerun: %v, %d runs, %+v", err, len(tr.vm.disks), tr.ledger(t).Evidence)
			}
		case rangevm.Fail:
			if len(l.Evidence.Failed) != 1 || l.Evidence.Pending != "" {
				t.Fatalf("FAIL without its result: %+v", l.Evidence)
			}
		}
	}
}

// A job whose program cannot go on a job disk (empty) is INVALID without a run, and retention still
// applies.
func TestAnUnencodableJobIsInvalidAndPruned(t *testing.T) {
	now := time.Now()
	tr := newTestRunner(t, now, evidenceDone(now))
	for i := range KeepAgent + 2 {
		if err := os.Mkdir(filepath.Join(tr.Results, LabelAgent, fmt.Sprintf("20200101T%06dZ-00000000", i)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	tr.addJob(t, "job-1", execRequest, []byte{})
	if err := tr.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(tr.Results, LabelAgent))
	if err != nil || len(entries) != KeepAgent || len(tr.vm.disks) != 0 {
		t.Fatalf("%d agent results, %d runs, %v", len(entries), len(tr.vm.disks), err)
	}
}

// A PASS whose result was not written is never logged as a result.
func TestAnUnwrittenPassIsNotLoggedAsAResult(t *testing.T) {
	tr := newTestRunner(t, time.Now(), Ledger{})
	var log bytes.Buffer
	tr.Log = slog.New(slog.NewTextHandler(&log, nil))
	run := tr.run
	tr.run = func(ctx context.Context, base, parent string, serial io.Writer, disk []byte) (rangevm.Outcome, error) {
		dir := filepath.Join(tr.Results, LabelEvidence, tr.results(t, LabelEvidence)[0].ID)
		if err := os.Chmod(dir, 0o550|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o750|os.ModeSetgid) })
		return run(ctx, base, parent, serial, disk)
	}
	if err := tr.Tick(t.Context()); err == nil {
		t.Fatal("an unwritten result went unreported")
	}
	if line := log.String(); strings.Contains(line, "verdict=PASS") || !strings.Contains(line, "result not written") {
		t.Fatalf("log: %q", line)
	}
}
