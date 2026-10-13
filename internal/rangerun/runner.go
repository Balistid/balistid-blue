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
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// EvidenceEvery is how often the runner proves its own image (ADR 0011, point 5).
const EvidenceEvery = 24 * time.Hour

// RuleVersion names the rules the runner's decisions follow, for its log (ENGINEERING.md 3).
const RuleVersion = "adr-0011 v2.4"

// maxKeptBytes bounds what one job keeps in its result directory: escaping at most quadruples the
// serial log, output and Laurel records of the worst job, plus result.json. A trial's serial budget
// is at most SerialBudget, so a trial job keeps no more than a run job (TestTrialJobsFitTheKeptBytes).
const maxKeptBytes = 4*(rangejob.MaxTrials*rangevm.SerialBudget+rangevm.JobOutCap+rangevm.JobLaurelCap) + 1<<20

// Runner runs one range job per tick as its own user (ADR 0011). State holds its ledger, its
// cache (images, runs, lock) and the path of its image; Results is where agents read results.
type Runner struct {
	State, Inbox, Results, Commit string
	Log                           *slog.Logger

	build    func(ctx context.Context, root, cache string, log io.Writer, commit string) (string, error)
	run      func(ctx context.Context, base, parent string, serial io.Writer, job []byte) (rangevm.Outcome, error)
	trial    func(ctx context.Context, base, parent string, serial io.Writer, lim rangevm.Limits) (rangevm.Outcome, error)
	selftest func(o rangevm.Outcome, launcher, image string) (verdict, reason string)
	admit    func(ctx context.Context, needs []DiskNeed) error
	watch    func(ctx context.Context) (context.Context, func())
	now      func() time.Time
	owner    func(os.FileInfo) int
	confined func() error
}

// New returns a runner with the real VM, admission and memory watch.
func New(state, inbox, results, commit string, log *slog.Logger) *Runner {
	return &Runner{State: state, Inbox: inbox, Results: results, Commit: commit, Log: log,
		build: rangevm.BuildCommit, run: rangevm.Run, trial: rangevm.RunTrial, selftest: rangevm.JudgeSelftest, admit: Admit, watch: Watch, now: time.Now, owner: owner,
		confined: filterInForce}
}

func (r *Runner) cache() string          { return filepath.Join(r.State, "cache") }
func (r *Runner) ledgerPath() string     { return filepath.Join(r.State, "ledger.json") }
func (r *Runner) acceptancePath() string { return filepath.Join(r.State, "acceptance.json") }
func (r *Runner) imagePath() string      { return filepath.Join(r.State, "image") }

// Build builds the image of the runner's own commit from the object files in objects (ADR 0011,
// point 2), records its path, and creates the ledger if there is none; an unreadable ledger stays
// an error. It runs at install, never from a tick.
func (r *Runner) Build(ctx context.Context, objects string, log io.Writer) error {
	if err := r.checkState(); err != nil {
		return err
	}
	image, buildErr := r.build(ctx, objects, r.cache(), log, r.Commit)
	if image == "" {
		return fmt.Errorf("build: %w", buildErr)
	}
	// A retention error comes with a stored image, which is recorded all the same.
	if err := rangevm.WriteFileAtomic(r.imagePath(), []byte(image+"\n"), 0o600); err != nil {
		return fmt.Errorf("build: %w", errors.Join(buildErr, err))
	}
	if _, err := LoadLedger(r.ledgerPath()); errors.Is(err, ErrNoLedger) {
		err = SaveLedger(r.ledgerPath(), Ledger{})
		return errors.Join(buildErr, err)
	} else if err != nil {
		return fmt.Errorf("build: %w", errors.Join(buildErr, err))
	}
	return buildErr
}

// Tick runs at most one VM: an evidence run of the runner's own image while evidence is due (until
// one PASSes, and again a day later), else the next agent job. It returns nil when there is nothing
// to do or the reserves are short (logged), and an error for anything that stops the runner: no
// syscall filter, state others can write, no image, an unreadable ledger, a failed commit,
// admission that cannot read the host.
func (r *Runner) Tick(ctx context.Context) error {
	if err := r.confined(); err != nil {
		return fmt.Errorf("tick: confinement missing: %w", err)
	}
	if err := r.checkState(); err != nil {
		return err
	}
	held, err := rangevm.Lock(r.cache())
	if err != nil {
		return fmt.Errorf("tick: %w", err)
	}
	defer held.Close() //nolint:errcheck // releasing a flock cannot fail in a way that matters here
	l, err := LoadLedger(r.ledgerPath())
	if err != nil {
		return fmt.Errorf("tick: %w", err)
	}
	if err := r.settle(&l); err != nil {
		return err
	}
	img, err := r.image(ctx)
	if err != nil {
		return err
	}
	if len(l.Evidence.Failed) >= MaxFailed {
		return fmt.Errorf("tick: the ledger holds %d failed evidence runs; the maintainer reviews it", MaxFailed)
	}
	for _, f := range l.Evidence.Failed {
		if f.Commit == r.Commit {
			return fmt.Errorf("tick: commit %s failed evidence run %s; install another", r.Commit, f.ID)
		}
	}
	now := r.now()
	if ev := l.Evidence; !ev.Due && (ev.Commit != r.Commit || ev.LastPass.After(now) || now.Sub(ev.LastPass) >= EvidenceEvery) {
		l.Evidence.Due = true
		r.Log.Info("evidence due", "commit", ev.Commit, "last_pass", ev.LastPass, "rule", RuleVersion)
		if err := SaveLedger(r.ledgerPath(), l); err != nil {
			return fmt.Errorf("tick: %w", err)
		}
	}
	st, err := os.Stat(img.Path)
	if err != nil {
		return fmt.Errorf("tick: image: %w", err)
	}
	runs := 3*rangevm.WriteCap(st.Size()) + rangejob.DiskBytes
	for _, tr := range rangejob.Trials() {
		runs = max(runs, rangevm.TrialLimits(tr).DiskNeed(st.Size()))
	}
	needs := []DiskNeed{
		{filepath.Join(r.cache(), "runs"), uint64(runs)}, //nolint:gosec // a file size is not negative
		{r.Results, maxKeptBytes},
		{r.State, 2 * MaxLedgerBytes},
	}
	if err := r.admit(ctx, needs); errors.Is(err, ErrNotAdmitted) {
		r.Log.Info("not admitted", "reason", err.Error(), "rule", RuleVersion)
		return nil
	} else if err != nil {
		return fmt.Errorf("tick: %w", err)
	}
	if l.Evidence.Due {
		return r.evidence(ctx, &l, img, now)
	}
	return r.slot(ctx, &l, img, now)
}

// slot runs an acceptance batch and an agent job in turn; a batch also runs when no agent job is
// admissible (ADR 0018, point 5). Acceptance never stops the runner: a suite it cannot read is
// logged and skipped, and agent jobs run on.
func (r *Runner) slot(ctx context.Context, l *Ledger, img image, now time.Time) error {
	acc, err := LoadAcceptance(r.acceptancePath(), r.Commit)
	if err != nil {
		r.Log.Error("acceptance skipped", "reason", rangevm.Printable(err.Error(), 300), "rule", RuleVersion)
		_, err := r.agentJob(ctx, l, img, now)
		return err
	}
	_, pending := acc.Next()
	if !acc.BatchTurn || !pending {
		ran, err := r.agentJob(ctx, l, img, now)
		if ran && pending {
			// A job that failed still took its slot; the next one is the batch's.
			acc.BatchTurn = true
			return errors.Join(err, SaveAcceptance(r.acceptancePath(), acc))
		}
		if err != nil || !pending {
			return err
		}
	}
	return r.batch(ctx, acc, img)
}

// batch runs the suite's next trials while their walls and setup fit one batch (ADR 0018, point 5),
// then hands the next slot to an agent job. Each run is recorded in the suite and saved before its
// result is written, so a MISS stands even if the result never reaches the disk. A run the runner
// stopped, or one the host stopped or could not start (memory watch, VM start), is not recorded:
// it shows nothing about the commit and runs again; its result says INVALID.
func (r *Runner) batch(ctx context.Context, acc Acceptance, img image) error {
	acc.BatchTurn = false
	var errs []error
	var planned time.Duration
	var ids []string
	for ctx.Err() == nil {
		tr, ok := acc.Next()
		if !ok || planned+tr.Wall+rangejob.Setup > rangejob.Batch {
			break
		}
		planned += tr.Wall + rangejob.Setup
		info := &JobInfo{Name: tr.Name, Kind: rangejob.KindTrial, Trials: 1, Trial: tr.Name}
		dir, id, err := r.begin(LabelAcceptance, tr.Name, img, info)
		if err != nil {
			errs = append(errs, err)
			break
		}
		ids = append(ids, id)
		run, serial, runErr := r.trialRun(ctx, img, tr)
		run.Label = rangevm.TrialLabel(tr)
		switch {
		case ctx.Err() != nil:
			run.Verdict, run.Reason = rangevm.Invalid, "the runner was stopped"
		case !run.host:
			next := acc.Record(tr, run.Label, run.Verdict, id)
			if err := SaveAcceptance(r.acceptancePath(), next); err != nil {
				// Unsaved, the run did not happen for the suite: its result says so and it runs again.
				run.Verdict, run.Reason = rangevm.Invalid, "the acceptance suite could not be saved"
				runErr = errors.Join(runErr, err)
				break
			}
			acc = next
		}
		errs = append(errs, runErr, r.finish(dir, r.result(id, LabelAcceptance, img, info, []Run{run}), map[string][]byte{"serial.txt": serial}))
		if runErr != nil {
			break
		}
	}
	errs = append(errs, SaveAcceptance(r.acceptancePath(), acc))
	if len(ids) > 0 {
		// Every result of this batch is kept whatever its name says (T22), and every MISS that stands.
		pins := ids[:len(ids)-1]
		for _, t := range acc.Trials {
			if t.Miss != "" {
				pins = append(pins, t.Miss)
			}
		}
		errs = append(errs, prune(filepath.Join(r.Results, LabelAcceptance), KeepAcceptance, ids[len(ids)-1], pins...))
	}
	for _, m := range []string{"sustained_rate", "burst_rate", "crash_loss_ms"} {
		r.Log.Info("acceptance", "commit", acc.Commit, "metric", m, "verdict", acc.Verdict(m), "rule", RuleVersion)
	}
	return errors.Join(errs...)
}

// trialRun runs tr once with its table limits, judges it as a trial and keeps its measures.
func (r *Runner) trialRun(ctx context.Context, img image, tr rangejob.Trial) (Run, []byte, error) {
	lim := rangevm.TrialLimits(tr)
	return r.boot(ctx, func(ctx context.Context, serial io.Writer) (rangevm.Outcome, error) {
		return r.trial(ctx, img.Path, filepath.Join(r.cache(), "runs"), serial, lim)
	}, func(o rangevm.Outcome) Run {
		v, why := rangevm.JudgeTrial(tr, o, r.Commit, img.Commit)
		return Run{Verdict: v, Reason: why, GuestKernel: kernel(o)}
	}, func(o rangevm.Outcome) map[string]uint64 { return rangevm.Measures(tr, o) })
}

// checkState refuses a state directory anyone but the runner could change: a build there runs the
// commit's PKGBUILD and mkosi, and a tick trusts its ledger.
func (r *Runner) checkState() error {
	st, err := os.Lstat(r.State)
	if err != nil || !st.IsDir() || r.owner(st) != os.Geteuid() || st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not a state directory only the runner writes", r.State)
	}
	return nil
}

// filterInForce is a tripwire, not a proof (ADR 0011, point 1): each tick, calls the tick unit's filter
// answers with EPERM must get it, so the runner under a unit with no filter or a deny-list, such as the
// old unit after a cut install, runs nothing. Probes cannot show the whole filter; that comes from the
// unit's text, pinned by test_runner_deploy.py and installed by hash. One probe per clause the unit
// takes out of its allowlist, and ptrace, which no allowed group holds; with these arguments the
// kernel alone never answers EPERM.
func filterInForce() error {
	probes := []struct {
		name string
		args [7]uintptr // trap number, then its arguments
	}{
		{"keyctl", [7]uintptr{syscall.SYS_KEYCTL, 0, 0xfffffffd}},                  // GET_KEYRING_ID of the session keyring (-3)
		{"io_setup", [7]uintptr{syscall.SYS_IO_SETUP, 1, 0}},                       // EFAULT alone
		{"process_vm_readv", [7]uintptr{310, uintptr(os.Getpid()), 0, 0, 0, 0, 1}}, // x86-64; EINVAL alone (flags)
		{"ptrace", [7]uintptr{syscall.SYS_PTRACE, 2, 0x7fffffff}},                  // PEEKDATA of no process: ESRCH alone
	}
	for _, p := range probes {
		a := p.args
		_, _, errno := syscall.Syscall6(a[0], a[1], a[2], a[3], a[4], a[5], a[6])
		if err := deniedByFilter(p.name, errno); err != nil {
			return err
		}
	}
	return nil
}

// deniedByFilter accepts only EPERM, which none of the probes gets from the kernel alone.
func deniedByFilter(name string, errno syscall.Errno) error {
	if errno != syscall.EPERM {
		return fmt.Errorf("%s answered errno %d, not EPERM: the unit's syscall filter is not in force", name, int(errno))
	}
	return nil
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

// settle finishes an evidence run a crash or a failed save left pending: its result says FAIL
// only if the run finished, and then the FAIL is recorded; otherwise the run counts for nothing.
func (r *Runner) settle(l *Ledger) error {
	id := l.Evidence.Pending
	if id == "" {
		return nil
	}
	data, err := readFile(filepath.Join(r.Results, LabelEvidence, id, "result.json"), 1<<20)
	if err != nil {
		return fmt.Errorf("tick: pending evidence run %s: %w", id, err)
	}
	// Only the runner writes this file, but it is read as strictly as any record (ENGINEERING.md 3).
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var res Result
	err = dec.Decode(&res)
	if _, tail := dec.Token(); err == nil && !errors.Is(tail, io.EOF) {
		err = errors.New("data after the result")
	}
	verdicts := []string{rangevm.Pass, rangevm.Fail, rangevm.Invalid, rangevm.Unknown}
	if err != nil || res.SchemaVersion != resultSchema || res.ID != id || res.Label != LabelEvidence ||
		!buildinfo.IsCommitID(res.RunnerCommit) || len(res.Runs) != 1 || res.Runs[0].Verdict != res.Verdict ||
		!slices.Contains(verdicts, res.Verdict) {
		return fmt.Errorf("tick: pending evidence run %s has no well-formed result", id)
	}
	if res.Verdict == rangevm.Fail {
		l.Evidence.fail(res.RunnerCommit, id) // SaveLedger refuses a malformed commit
	}
	r.Log.Info("pending evidence settled", "id", id, "verdict", rangevm.Printable(res.Verdict, 16), "rule", RuleVersion)
	l.Evidence.Pending = ""
	return SaveLedger(r.ledgerPath(), *l)
}

// fail records a failed evidence run. None is ever dropped: Tick stops at MaxFailed, and a ledger
// over it is one SaveLedger refuses.
func (e *Evidence) fail(commit, id string) {
	e.Failed = append(e.Failed, FailedRun{Commit: commit, ID: id})
}

// evidence runs the runner's own image with no job disk. The ledger names the run as pending
// before the VM starts. A FAIL is saved to the ledger before its result is written, so the ledger
// record goes before serial.txt can use up the disk; if that save fails, a FAIL result.json lets
// settle record it. A FAIL is lost when neither reaches the disk: both writes fail before their
// rename (WriteFileAtomic can also fail after it), or the runner dies after the VM's end and before
// the save, or after a failed save and before result.json. settle then finds the INVALID that begin
// left, and as evidence is still due a later Tick runs it again. After the save, the recorded
// FAIL's result may still say INVALID: result.json failed before its rename, or the runner died first.
func (r *Runner) evidence(ctx context.Context, l *Ledger, img image, now time.Time) error {
	dir, id, err := r.begin(LabelEvidence, "", img, nil)
	if err != nil {
		return err
	}
	l.Evidence.Pending = id
	if err := SaveLedger(r.ledgerPath(), *l); err != nil {
		return err
	}
	run, serial, err := r.vm(ctx, img, nil, func(o rangevm.Outcome) Run {
		v, why := r.selftest(o, r.Commit, img.Commit)
		return Run{Verdict: v, Reason: why, GuestKernel: kernel(o)}
	})
	var saveErr error
	if run.Verdict == rangevm.Fail {
		l.Evidence.fail(r.Commit, id)
		l.Evidence.Pending = ""
		saveErr = SaveLedger(r.ledgerPath(), *l)
	}
	finishErr := r.finish(dir, r.result(id, LabelEvidence, img, nil, []Run{run}), map[string][]byte{"serial.txt": serial})
	// Only a PASS with its result on disk counts; INVALID or UNKNOWN, which agents can cause, leave
	// evidence due. A FAIL counts even without its final result, and stays pinned by its id.
	switch {
	case run.Verdict == rangevm.Pass && finishErr == nil:
		l.Evidence.Commit, l.Evidence.LastPass, l.Evidence.Due = r.Commit, now, false
	case run.Verdict == rangevm.Pass:
		return errors.Join(err, finishErr) // still pending: settle finds the INVALID it left
	}
	if run.Verdict != rangevm.Fail {
		l.Evidence.Pending = ""
		saveErr = SaveLedger(r.ledgerPath(), *l)
	}
	if saveErr != nil {
		return errors.Join(err, finishErr, saveErr)
	}
	r.Log.Info("evidence recorded", "id", id, "verdict", run.Verdict, "due", l.Evidence.Due, "rule", RuleVersion)
	pins := make([]string, 0, len(l.Evidence.Failed))
	for _, f := range l.Evidence.Failed {
		pins = append(pins, f.ID)
	}
	return errors.Join(err, finishErr, prune(filepath.Join(r.Results, LabelEvidence), KeepEvidence, id, pins...))
}

// prune keeps the newest keep results in dir counting fresh, the result this tick wrote, which it
// keeps whatever its name says: the name's stamp is the wall clock, and once the clock is set back
// it sorts as the oldest (T22), so its PASS would be in the ledger with its result deleted.
func prune(dir string, keep int, fresh string, pins ...string) error {
	return Prune(dir, keep-1, append(pins, fresh)...)
}

// agentJob runs the next admissible inbox job; ran says whether one was taken.
func (r *Runner) agentJob(ctx context.Context, l *Ledger, img image, now time.Time) (ran bool, err error) {
	inbox, err := OpenInbox(r.Inbox)
	if err != nil {
		return false, fmt.Errorf("tick: %w", err)
	}
	defer inbox.Close() //nolint:errcheck // read-only
	job, ok, rejected, nextErr := Next(inbox, l, now)
	for _, rej := range rejected {
		r.logRejection(rej)
	}
	// The ledger is on disk before the job runs: a crash or kill after this point never gives the
	// job a second run or the agents their quota back.
	if err := errors.Join(nextErr, SaveLedger(r.ledgerPath(), *l)); err != nil || !ok {
		return false, err
	}
	info := &JobInfo{Name: job.Name, Kind: job.Request.Kind, Trials: job.Request.Trials, Trial: job.Request.Trial,
		Program: job.Request.Program, TimeoutS: job.Request.TimeoutS, ContentKey: ContentKey(job)}
	switch job.Request.Kind {
	case rangejob.KindRun:
		return true, r.runJob(ctx, img, info, job.Request.Trials, func(ctx context.Context) (Run, []byte, error) {
			return r.vm(ctx, img, nil, func(o rangevm.Outcome) Run {
				v, why := r.selftest(o, r.Commit, img.Commit)
				return Run{Verdict: v, Reason: why, GuestKernel: kernel(o)}
			})
		})
	case rangejob.KindTrial:
		// An agent's trial is labelled agent like any inbox job; it never counts for acceptance.
		tr, ok := rangejob.Lookup(job.Request.Trial)
		if !ok {
			return true, fmt.Errorf("tick: job %s names no trial of the table", job.Name)
		}
		return true, r.runJob(ctx, img, info, job.Request.Trials, func(ctx context.Context) (Run, []byte, error) {
			return r.trialRun(ctx, img, tr)
		})
	case rangejob.KindExec:
		return true, r.execJob(ctx, img, info, job)
	}
	return true, fmt.Errorf("tick: job %s has no kind the runner knows", job.Name)
}

// logRejection logs a rejection once, as the ledger records it. The name is the agent's bytes; the
// reason is ReadJob's fixed text, which never quotes what the job holds, escaped all the same.
func (r *Runner) logRejection(rej Rejection) {
	r.Log.Info("inbox job", "decision", Rejected, "job", rangevm.Printable(rej.Name, 80),
		"reason", rangevm.Printable(rej.Reason, 200), "rule", RuleVersion)
}

// runJob runs a job of n runs, each by once, and keeps every run's serial log.
func (r *Runner) runJob(ctx context.Context, img image, info *JobInfo, trials int, once func(context.Context) (Run, []byte, error)) error {
	dir, id, err := r.begin(LabelAgent, info.Name, img, info)
	if err != nil {
		return err
	}
	var runs []Run
	files := map[string][]byte{}
	var errs []error
	for i := range trials {
		if ctx.Err() != nil {
			runs = append(runs, Run{Verdict: rangevm.Invalid, Reason: "the runner was stopped"})
			break
		}
		run, serial, err := once(ctx)
		runs, errs = append(runs, run), append(errs, err)
		files[fmt.Sprintf("serial-%d.txt", i+1)] = serial
	}
	res := r.result(id, LabelAgent, img, info, runs)
	return errors.Join(errors.Join(errs...), r.finish(dir, res, files), prune(filepath.Join(r.Results, LabelAgent), KeepAgent, id))
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
		return errors.Join(r.finish(dir, res, nil), prune(filepath.Join(r.Results, LabelAgent), KeepAgent, id))
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
	return errors.Join(err, r.finish(dir, res, files), prune(filepath.Join(r.Results, LabelAgent), KeepAgent, id))
}

// vm runs img once under the memory watch and judges the outcome with judge. A run the watch
// stopped, or one the VM could not start, is INVALID whatever the guest wrote.
func (r *Runner) vm(ctx context.Context, img image, disk []byte, judge func(rangevm.Outcome) Run) (Run, []byte, error) {
	return r.boot(ctx, func(ctx context.Context, serial io.Writer) (rangevm.Outcome, error) {
		return r.run(ctx, img.Path, filepath.Join(r.cache(), "runs"), serial, disk)
	}, judge, nil)
}

// boot is vm for any way of booting the image: a run with an optional job disk, or a trial. measure
// (nil for none) reads a run's measures whatever its verdict: an INVALID trial keeps the timings
// that show why.
func (r *Runner) boot(ctx context.Context, start func(context.Context, io.Writer) (rangevm.Outcome, error),
	judge func(rangevm.Outcome) Run, measure func(rangevm.Outcome) map[string]uint64) (Run, []byte, error) {
	var serial bytes.Buffer
	watched, stop := r.watch(ctx)
	o, err := start(watched, &serial)
	stop()
	cause := context.Cause(watched)
	// A run directory left behind does not change what the run showed; it is still returned.
	var cleanup error
	if errors.Is(err, rangevm.ErrCleanup) {
		cleanup, err = fmt.Errorf("run: %w", err), nil
	}
	if err != nil {
		return Run{Verdict: rangevm.Invalid, Reason: "runner: " + err.Error(), host: true}, serial.Bytes(), fmt.Errorf("run: %w", err)
	}
	var run Run
	switch {
	case errors.Is(cause, ErrMemoryReserve), errors.Is(cause, ErrMemoryUnknown):
		run = Run{Verdict: rangevm.Invalid, Reason: "stopped: " + cause.Error(), host: true}
	case o.Invalid != "":
		run = Run{Verdict: rangevm.Invalid, Reason: o.Invalid}
	default:
		run = judge(o)
	}
	if measure != nil {
		run.Measures = measure(o)
	}
	return run, serial.Bytes(), cleanup
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
	if err := errors.Join(errs...); err != nil {
		r.Log.Error("result not written", "label", res.Label, "id", res.ID, "rule", RuleVersion)
		return err
	}
	r.Log.Info("result", "label", res.Label, "id", res.ID, "verdict", res.Verdict,
		"reason", rangevm.Printable(res.Reason, 300), "rule", RuleVersion)
	return nil
}

// severity orders verdicts for a job of several runs: the job is its worst run.
var severity = map[string]int{rangevm.Fail: 4, rangevm.Miss: 4, rangevm.Invalid: 3, rangevm.Unknown: 2, rangevm.Pass: 1, rangevm.Ran: 1}

// result is a Result whose verdict is its worst run's; a verdict the runner does not know is
// worse than any.
func (r *Runner) result(id, label string, img image, info *JobInfo, runs []Run) Result {
	res := Result{ID: id, Label: label, RunnerCommit: r.Commit, ImageCommit: img.Commit, ImageSHA256: img.SHA256,
		Job: info, Limits: limitsOf(info), Runs: runs, Verdict: rangevm.Invalid, Reason: "no run"}
	worst := -1
	for _, run := range runs {
		rank, known := severity[run.Verdict]
		if !known {
			rank = 5
		}
		if rank > worst {
			worst, res.Verdict, res.Reason = rank, run.Verdict, run.Reason
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
