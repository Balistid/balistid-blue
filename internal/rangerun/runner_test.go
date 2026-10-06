package rangerun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
	}
	return testRunner{Runner: r, vm: vm, root: root}
}

// evidenceDone is a ledger whose evidence for testCommit is fresh, so a tick takes an agent job.
func evidenceDone(now time.Time) Ledger {
	return Ledger{Evidence: Evidence{Commit: testCommit, LastRun: now}}
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
	if l.Evidence.Commit != testCommit || !l.Evidence.LastRun.Equal(now) || len(l.Entries) != 0 {
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
		"commit failed evidence": {Ledger{Evidence: Evidence{Commit: testCommit, LastRun: now, Failed: "20261006T090000Z-00000001"}}, func(*testing.T, testRunner) {}},
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
	tr.admit = func(context.Context, []DiskNeed) error { return errors.New("short of memory") }
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
	if l := tr.ledger(t); len(ev) != 1 || l.Evidence.Failed != ev[0].ID {
		t.Fatalf("failed id %q, results %+v", l.Evidence.Failed, ev)
	}
	tr.now = func() time.Time { return now.Add(2 * EvidenceEvery) }
	if err := tr.Tick(t.Context()); err == nil || len(tr.vm.disks) != 1 {
		t.Fatalf("second tick: %v, %d runs", err, len(tr.vm.disks))
	}
}
