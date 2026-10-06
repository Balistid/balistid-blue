package rangerun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// EvidenceEvery is how often the runner proves its own image (ADR 0011, point 5).
const EvidenceEvery = 24 * time.Hour

// maxKeptBytes bounds what one job keeps in its result directory: escaping at most quadruples the
// serial log, output and Laurel records of the worst job, plus result.json.
const maxKeptBytes = 4*(rangejob.MaxTrials*rangevm.SerialBudget+rangevm.JobOutCap+rangevm.JobLaurelCap) + 1<<20

// Runner runs one range job per tick as its own user (ADR 0011). State holds its ledger, its
// cache (images, runs, lock) and the path of its image; Results is where agents read results.
type Runner struct {
	State, Inbox, Results, Commit string
	Log                           *slog.Logger

	run      func(ctx context.Context, base, parent string, serial io.Writer, job []byte) (rangevm.Outcome, error)
	selftest func(o rangevm.Outcome, launcher, image string) (verdict, reason string)
	admit    func(ctx context.Context, needs []DiskNeed) error
	watch    func(ctx context.Context) (context.Context, func())
	now      func() time.Time
}

// New returns a runner with the real VM, admission and memory watch.
func New(state, inbox, results, commit string, log *slog.Logger) *Runner {
	return &Runner{State: state, Inbox: inbox, Results: results, Commit: commit, Log: log,
		run: rangevm.Run, selftest: rangevm.JudgeSelftest, admit: Admit, watch: Watch, now: time.Now}
}

func (r *Runner) cache() string      { return filepath.Join(r.State, "cache") }
func (r *Runner) ledgerPath() string { return filepath.Join(r.State, "ledger.json") }
func (r *Runner) imagePath() string  { return filepath.Join(r.State, "image") }

// Build builds the image of the runner's own commit from the object files in objects (ADR 0011,
// point 2), records its path, and creates the ledger if there is none; an unreadable ledger stays
// an error. It runs at install, never from a tick.
func (r *Runner) Build(ctx context.Context, objects string, log io.Writer) error {
	image, err := rangevm.BuildCommit(ctx, objects, r.cache(), log, r.Commit)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if err := rangevm.WriteFileAtomic(r.imagePath(), []byte(image+"\n"), 0o600); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if _, err := LoadLedger(r.ledgerPath()); errors.Is(err, ErrNoLedger) {
		return SaveLedger(r.ledgerPath(), Ledger{})
	} else if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	return nil
}

// Tick runs at most one VM: an evidence run of the runner's own image when one is due, else the
// next agent job. It returns nil when there is nothing to do or admission refuses (logged), and an
// error for anything that stops the runner: no image, an unreadable ledger, a failed commit.
func (r *Runner) Tick(ctx context.Context) error {
	held, err := rangevm.Lock(r.cache())
	if err != nil {
		return fmt.Errorf("tick: %w", err)
	}
	defer held.Close() //nolint:errcheck // releasing a flock cannot fail in a way that matters here
	l, err := LoadLedger(r.ledgerPath())
	if err != nil {
		return fmt.Errorf("tick: %w", err)
	}
	img, err := r.image(ctx)
	if err != nil {
		return err
	}
	if l.Evidence.Commit == r.Commit && l.Evidence.Failed != "" {
		return fmt.Errorf("tick: commit %s failed evidence run %s; reinstall", r.Commit, l.Evidence.Failed)
	}
	st, err := os.Stat(img.Path)
	if err != nil {
		return fmt.Errorf("tick: image: %w", err)
	}
	needs := []DiskNeed{
		{filepath.Join(r.cache(), "runs"), 3*uint64(rangevm.WriteCap(st.Size())) + rangejob.DiskBytes}, //nolint:gosec // a file size is not negative
		{r.Results, maxKeptBytes},
		{r.State, 2 * MaxLedgerBytes},
	}
	if err := r.admit(ctx, needs); err != nil {
		r.Log.Info("not admitted", "reason", err.Error())
		return nil
	}
	now := r.now()
	if l.Evidence.Commit != r.Commit || now.Sub(l.Evidence.LastRun) >= EvidenceEvery {
		return r.evidence(ctx, &l, img, now)
	}
	return r.agentJob(ctx, &l, img, now)
}

// image is a base image and where it is.
type image struct {
	rangevm.Image
	Path string
}

// image is the image Build recorded, if it is still the runner's own commit's.
func (r *Runner) image(ctx context.Context) (image, error) {
	data, err := os.ReadFile(r.imagePath())
	if err != nil {
		return image{}, fmt.Errorf("tick: no image recorded; run build: %w", err)
	}
	path := string(bytes.TrimSuffix(data, []byte("\n")))
	img, err := rangevm.OpenImage(ctx, path)
	if err != nil {
		return image{}, fmt.Errorf("tick: %w", err)
	}
	if img.Commit != r.Commit {
		return image{}, fmt.Errorf("tick: image is of commit %s, the runner of %s", img.Commit, r.Commit)
	}
	return image{Image: img, Path: path}, nil
}

func (r *Runner) evidence(ctx context.Context, l *Ledger, img image, now time.Time) error {
	dir, id, err := r.begin(LabelEvidence, "", img, nil)
	if err != nil {
		return err
	}
	run, serial, err := r.vm(ctx, img, nil, func(o rangevm.Outcome) Run {
		v, why := r.selftest(o, r.Commit, img.Commit)
		return Run{Verdict: v, Reason: why, GuestKernel: kernel(o)}
	})
	res := r.result(id, LabelEvidence, img, nil, []Run{run})
	l.Evidence = Evidence{Commit: r.Commit, LastRun: now}
	if run.Verdict == rangevm.Fail {
		l.Evidence.Failed = id
	}
	return errors.Join(err, r.finish(dir, res, map[string][]byte{"serial.txt": serial}), SaveLedger(r.ledgerPath(), *l),
		Prune(filepath.Join(r.Results, LabelEvidence), KeepEvidence, l.Evidence.Failed))
}

func (r *Runner) agentJob(ctx context.Context, l *Ledger, img image, now time.Time) error {
	inbox, err := OpenInbox(r.Inbox)
	if err != nil {
		return fmt.Errorf("tick: %w", err)
	}
	defer inbox.Close() //nolint:errcheck // read-only
	job, ok, nextErr := Next(inbox, l, now)
	// The ledger is on disk before the job runs: a crash or kill after this point never gives the
	// job a second run or the agents their quota back.
	if err := errors.Join(nextErr, SaveLedger(r.ledgerPath(), *l)); err != nil || !ok {
		return err
	}
	info := &JobInfo{Name: job.Name, Kind: job.Request.Kind, Trials: job.Request.Trials, Program: job.Request.Program,
		TimeoutS: job.Request.TimeoutS, ContentKey: ContentKey(job)}
	switch job.Request.Kind {
	case rangejob.KindRun:
		return r.runJob(ctx, img, info, job.Request.Trials)
	case rangejob.KindExec:
		return r.execJob(ctx, img, info, job)
	}
	return fmt.Errorf("tick: job %s has no kind the runner knows", job.Name)
}

func (r *Runner) runJob(ctx context.Context, img image, info *JobInfo, trials int) error {
	dir, id, err := r.begin(LabelAgent, info.Name, img, info)
	if err != nil {
		return err
	}
	var runs []Run
	files := map[string][]byte{}
	var errs []error
	for i := range trials {
		run, serial, err := r.vm(ctx, img, nil, func(o rangevm.Outcome) Run {
			v, why := r.selftest(o, r.Commit, img.Commit)
			return Run{Verdict: v, Reason: why, GuestKernel: kernel(o)}
		})
		runs, errs = append(runs, run), append(errs, err)
		files[fmt.Sprintf("serial-%d.txt", i+1)] = serial
	}
	res := r.result(id, LabelAgent, img, info, runs)
	return errors.Join(errors.Join(errs...), r.finish(dir, res, files), Prune(filepath.Join(r.Results, LabelAgent), KeepAgent, ""))
}

func (r *Runner) execJob(ctx context.Context, img image, info *JobInfo, job rangejob.Job) error {
	sum := sha256.Sum256(job.Program)
	info.ProgramSHA256 = hex.EncodeToString(sum[:])
	disk, diskErr := rangejob.EncodeDisk(job.Program, job.Request.TimeoutS)
	if diskErr == nil {
		d := sha256.Sum256(disk)
		info.DiskSHA256 = hex.EncodeToString(d[:])
	}
	dir, id, err := r.begin(LabelAgent, info.Name, img, info)
	if err != nil {
		return err
	}
	if diskErr != nil {
		res := r.result(id, LabelAgent, img, info, []Run{{Verdict: rangevm.Invalid, Reason: "job disk: " + diskErr.Error()}})
		return r.finish(dir, res, nil)
	}
	var x rangevm.ExecResult
	run, serial, err := r.vm(ctx, img, disk, func(o rangevm.Outcome) Run {
		x = rangevm.ExecReport(o.Facts, sum)
		run := Run{Verdict: x.Verdict, Reason: x.Reason, GuestKernel: kernel(o), JobResult: x.Result,
			OutBytes: len(x.Out), OutTruncated: x.OutCut, LaurelBytes: len(x.Laurel)}
		if x.Verdict != rangevm.Invalid {
			exit := x.Exit
			run.JobExit = &exit
		}
		return run
	})
	files := map[string][]byte{"serial.txt": serial}
	if run.Verdict == rangevm.Ran || run.Verdict == rangevm.Unknown {
		files["job-out.txt"], files["job-laurel.txt"] = x.Out, x.Laurel
	}
	res := r.result(id, LabelAgent, img, info, []Run{run})
	return errors.Join(err, r.finish(dir, res, files), Prune(filepath.Join(r.Results, LabelAgent), KeepAgent, ""))
}

// vm runs img once under the memory watch and judges the outcome with judge. A run the watch
// stopped, or one the VM could not start, is INVALID whatever the guest wrote.
func (r *Runner) vm(ctx context.Context, img image, disk []byte, judge func(rangevm.Outcome) Run) (Run, []byte, error) {
	var serial bytes.Buffer
	watched, stop := r.watch(ctx)
	o, err := r.run(watched, img.Path, filepath.Join(r.cache(), "runs"), &serial, disk)
	stop()
	cause := context.Cause(watched)
	switch {
	case err != nil:
		return Run{Verdict: rangevm.Invalid, Reason: "runner: " + err.Error()}, serial.Bytes(), fmt.Errorf("run: %w", err)
	case errors.Is(cause, ErrMemoryReserve), errors.Is(cause, ErrMemoryUnknown):
		return Run{Verdict: rangevm.Invalid, Reason: "stopped: " + cause.Error()}, serial.Bytes(), nil
	case o.Invalid != "":
		return Run{Verdict: rangevm.Invalid, Reason: o.Invalid}, serial.Bytes(), nil
	}
	return judge(o), serial.Bytes(), nil
}

// begin creates the result directory and writes an INVALID result into it, which stands if the
// runner is killed before the run ends (R6).
func (r *Runner) begin(label, job string, img image, info *JobInfo) (dir, id string, err error) {
	dir, id, err = NewResultDir(r.Results, label, job, r.now())
	if err != nil {
		return "", "", fmt.Errorf("tick: %w", err)
	}
	stopped := []Run{{Verdict: rangevm.Invalid, Reason: "the runner stopped before the run ended"}}
	if err := WriteResult(dir, r.result(id, label, img, info, stopped)); err != nil {
		return "", "", fmt.Errorf("tick: %w", err)
	}
	return dir, id, nil
}

func (r *Runner) finish(dir string, res Result, files map[string][]byte) error {
	var errs []error
	for name, data := range files {
		errs = append(errs, WriteText(dir, name, data))
	}
	errs = append(errs, WriteResult(dir, res))
	r.Log.Info("result", "label", res.Label, "id", res.ID, "verdict", res.Verdict)
	return errors.Join(errs...)
}

// result is a Result whose verdict is its runs' if they all agree, else the first that differs
// from the first run's.
func (r *Runner) result(id, label string, img image, info *JobInfo, runs []Run) Result {
	res := Result{ID: id, Label: label, RunnerCommit: r.Commit, ImageCommit: img.Commit, ImageSHA256: img.SHA256,
		Job: info, Limits: CurrentLimits(), Runs: runs, Verdict: runs[0].Verdict, Reason: runs[0].Reason}
	for _, run := range runs[1:] {
		if run.Verdict != res.Verdict {
			res.Verdict, res.Reason = run.Verdict, run.Reason
			break
		}
	}
	return res
}

func kernel(o rangevm.Outcome) string {
	for _, f := range o.Facts {
		if f.Name == rangevm.FactKernel {
			return f.Value
		}
	}
	return ""
}
