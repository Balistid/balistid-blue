package rangerun

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// Labels of a result (ADR 0011, point 7): an agent job's verdict is advisory; evidence is only a
// run of the runner's own image with no job disk, started by the runner itself.
const (
	LabelAgent    = "agent"
	LabelEvidence = "evidence"
	// LabelAcceptance marks a run of the acceptance suite, scheduled only by the runner for its own
	// image (ADR 0018, point 6); each run carries its trial's label, baseline or control.
	LabelAcceptance = "acceptance"
)

// Retention (R5): escaping can make a result up to 4x its caps, maxKeptBytes, about 45 MiB. KeepAgent
// holds a day of quota, so a result outlives the window it was made in (about 1.05 GiB, 1.1 GiB while
// a fresh result is written).
const (
	KeepAgent = 24
	// KeepAcceptance holds four suites of the table's runs; a MISS that stands is pinned.
	KeepAcceptance = 40
	KeepEvidence   = 50
	resultSchema   = 1
	// Results are read by the maintainer's group, the group of the directories they are in.
	resultPerm = 0o640
)

var textName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)

var resultName = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}(-[a-z0-9][a-z0-9-]{0,63})?$`)

// Result is what the runner stores for one job or evidence run. Every free-text string is passed
// through rangevm.Printable when it is written.
type Result struct {
	SchemaVersion int      `json:"schema_version"`
	ID            string   `json:"id"`
	Label         string   `json:"label"`
	RunnerCommit  string   `json:"runner_commit"`
	ImageCommit   string   `json:"image_commit"`
	ImageSHA256   string   `json:"image_sha256"`
	Job           *JobInfo `json:"job,omitempty"`
	Limits        Limits   `json:"limits"`
	Verdict       string   `json:"verdict"`
	Reason        string   `json:"reason"`
	Runs          []Run    `json:"runs"`
}

// JobInfo names the agent job a result belongs to.
type JobInfo struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Trials        int    `json:"trials,omitempty"`
	Trial         string `json:"trial,omitempty"`
	Program       string `json:"program,omitempty"`
	TimeoutS      int    `json:"timeout_s,omitempty"`
	ContentKey    string `json:"content_key"`
	ProgramSHA256 string `json:"program_sha256,omitempty"`
	DiskSHA256    string `json:"job_disk_sha256,omitempty"`
}

// Limits are the limits a run had, so a result can be compared with another.
type Limits struct {
	RunTimeoutS  int    `json:"run_timeout_s"`
	SerialBudget int    `json:"serial_budget"`
	JobOutCap    int    `json:"job_out_cap"`
	JobLaurelCap int    `json:"job_laurel_cap"`
	MemReserve   uint64 `json:"mem_reserve"`
	JobMemory    uint64 `json:"job_memory"`
	DiskReserve  uint64 `json:"disk_reserve"`
}

// Run is one VM run of a job: one trial of a run job, or the exec job.
type Run struct {
	Verdict      string `json:"verdict"`
	Reason       string `json:"reason"`
	GuestKernel  string `json:"guest_kernel,omitempty"`
	JobResult    string `json:"job_result,omitempty"`
	JobExit      *int   `json:"job_exit,omitempty"`
	OutBytes     int    `json:"out_bytes,omitempty"`
	OutTruncated bool   `json:"out_truncated,omitempty"`
	LaurelBytes  int    `json:"laurel_bytes,omitempty"`
	// Label is an acceptance run's trial label, baseline or control; Measures are a trial run's
	// counts and timings (rangevm.Measures).
	Label    string            `json:"label,omitempty"`
	Measures map[string]uint64 `json:"measures,omitempty"`
	// host marks an INVALID the host caused (the memory watch, a process it could not start), not the run.
	host bool
}

// limitsOf are the limits of info's runs: a trial job's wall clock and serial budget are its
// trial's, every other run has CurrentLimits.
func limitsOf(info *JobInfo) Limits {
	l := CurrentLimits()
	if info == nil || info.Kind != rangejob.KindTrial {
		return l
	}
	if tr, ok := rangejob.Lookup(info.Trial); ok {
		l.RunTimeoutS, l.SerialBudget = int(tr.Wall/time.Second), int(tr.Serial)
	}
	return l
}

// CurrentLimits are the limits of every run of this runner.
func CurrentLimits() Limits {
	return Limits{
		RunTimeoutS: int(rangevm.RunTimeout / time.Second), SerialBudget: rangevm.SerialBudget,
		JobOutCap: rangevm.JobOutCap, JobLaurelCap: rangevm.JobLaurelCap,
		MemReserve: MemReserve, JobMemory: JobMemory, DiskReserve: DiskReserve,
	}
}

// NewResultDir creates an empty result directory under results/label, named by the time, a random
// token and, for an agent job, its name (already a plain job name), and returns its path and id.
func NewResultDir(results, label, job string, now time.Time) (dir, id string, err error) {
	if label != LabelAgent && label != LabelEvidence && label != LabelAcceptance {
		return "", "", fmt.Errorf("unknown result label %q", label)
	}
	var token [4]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", "", fmt.Errorf("result id: %w", err)
	}
	id = now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(token[:])
	if job != "" {
		id += "-" + job
	}
	if !resultName.MatchString(id) {
		return "", "", errors.New("result id is not a plain name")
	}
	// The install creates results/agent and results/evidence owned by the runner, setgid in the
	// maintainer's group, mode 2750, and the unit's umask is 0027; a result directory then inherits
	// the group. Owner, setgid and mode are checked, never repaired (chmod by the runner could drop
	// the setgid bit); the group is whatever the install set.
	parent, dir := filepath.Join(results, label), filepath.Join(results, label, id)
	st, err := os.Lstat(parent)
	if err != nil || st.Mode() != os.ModeDir|os.ModeSetgid|0o750 || owner(st) != os.Geteuid() {
		return "", "", fmt.Errorf("%s is not the runner's 2750 directory the install creates", parent)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("result directory: %w", err)
	}
	if got, err := os.Lstat(dir); err != nil || got.Mode() != os.ModeDir|os.ModeSetgid|0o750 {
		return "", "", errors.Join(fmt.Errorf("result directory %s is not 2750; check the umask", id), os.Remove(dir))
	}
	return dir, id, nil
}

func owner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// WriteResult replaces dir/result.json with r, every free-text field escaped (rangevm.Printable).
func WriteResult(dir string, r Result) error {
	esc := func(limit int, fields ...*string) {
		for _, f := range fields {
			*f = rangevm.Printable(*f, limit)
		}
	}
	r.SchemaVersion = resultSchema
	esc(1024, &r.Reason)
	esc(128, &r.ID, &r.Label, &r.RunnerCommit, &r.ImageCommit, &r.ImageSHA256, &r.Verdict)
	if r.Job != nil {
		job := *r.Job
		esc(128, &job.Name, &job.Kind, &job.Trial, &job.Program, &job.ContentKey, &job.ProgramSHA256, &job.DiskSHA256)
		r.Job = &job
	}
	r.Runs = slices.Clone(r.Runs) // the caller's runs stay as they were
	for i := range r.Runs {
		esc(1024, &r.Runs[i].Reason)
		esc(128, &r.Runs[i].Verdict, &r.Runs[i].GuestKernel, &r.Runs[i].JobResult)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if err := rangevm.WriteFileAtomic(filepath.Join(dir, "result.json"), data, resultPerm); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

// WriteText stores bytes a guest or job chose (serial log, output, Laurel records) as dir/name,
// escaped by rangevm.Printable so no reader meets a terminal escape or a forged line.
func WriteText(dir, name string, data []byte) error {
	if !textName.MatchString(name) || name == "result.json" {
		return fmt.Errorf("%q is not a result text file name", name)
	}
	text := rangevm.Printable(string(data), 4*len(data))
	if err := rangevm.WriteFileAtomic(filepath.Join(dir, name), []byte(text), resultPerm); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// Prune keeps the newest keep results in dir, and those named in pins whatever their age, so failed
// evidence runs outlive retention (ADR 0011, point 7). Entries not named like a result are
// left alone; they are not the runner's.
func Prune(dir string, keep int, pins ...string) error {
	if keep < 1 {
		return errors.New("retention must keep at least one result")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("retention %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && resultName.MatchString(e.Name()) && !slices.Contains(pins, e.Name()) {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names) // names start with a UTC stamp: age, to the second
	var errs []error
	for len(names) > keep {
		if err := os.RemoveAll(filepath.Join(dir, names[0])); err != nil {
			errs = append(errs, fmt.Errorf("retention: %w", err))
		}
		names = names[1:]
	}
	return errors.Join(errs...)
}
