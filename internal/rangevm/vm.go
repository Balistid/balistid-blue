package rangevm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Host binaries and firmware, by absolute path (ENGINEERING.md 7, Processes).
const (
	prlimitPath = "/usr/bin/prlimit"
	bwrapPath   = "/usr/bin/bwrap"
	qemuPath    = "/usr/bin/qemu-system-x86_64"
	qemuImgPath = "/usr/bin/qemu-img"
	ovmfCode    = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
	ovmfVars    = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
)

// Paths inside the sandbox. The host paths of the base image and run directory never reach QEMU,
// so they cannot inject `-drive` options, and the overlay's backing path names the sandbox view.
const (
	inBase    = "/range/base.raw"
	inRun     = "/range/run"
	overlay   = "overlay.qcow2"
	results   = "results.raw"
	firmVars  = "vars.fd"
	resultsID = "balistid-results"
	jobDisk   = "job.raw"
	jobID     = "balistid-job"
	scratch   = "scratch.raw"
	scratchID = "balistid-scratch"
)

// Limits of one run (ADR 0009, points 3–5).
const (
	ResultsBytes = 16 << 20
	SerialBudget = 1 << 20
	RunTimeout   = 10 * time.Minute
	setupTimeout = time.Minute
	setupShown   = 512 // bytes of the overlay step's output kept in its INVALID reason
)

// Limits of a trial run (ADR 0018, points 1-2): Wall bounds all its boots together, Serial each
// boot's output; Boots is 2 for a reset trial, whose first boot must arm the reset. Scratch is the
// size of a writable disk the boots share for the store a trial measures, or 0 for none.
type Limits struct {
	Trial   string
	Wall    time.Duration
	Serial  int64
	Boots   int
	Scratch int64
}

// Caps of a trial: with its setup it fits an acceptance batch (ADR 0018, point 5), its serial
// budget keeps runCommand's byte counter far from overflow, and its scratch disk fits the runner's
// disk admission.
const (
	MaxTrialWall   = 30*time.Minute - setupTimeout
	MaxTrialSerial = 16 << 20
	MaxScratch     = 4 << 30
)

// runLimits are the self-test's and an exec job's (ADR 0009, point 4).
var runLimits = Limits{Wall: RunTimeout, Serial: SerialBudget, Boots: 1}

// Facts of a trial boot: it opens with the trial and phase it read (ADR 0018, point 1), and a first
// boot of two says reset_armed=yes before it resets itself.
const (
	FactTrial      = "trial"
	FactPhase      = "phase"
	FactResetArmed = "reset_armed"
)

var trialName = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func (l Limits) check() error {
	switch {
	case !trialName.MatchString(l.Trial):
		return errors.New("trial name is not a lowercase word of at most 32 characters")
	case l.Wall <= 0 || l.Wall > MaxTrialWall:
		return fmt.Errorf("trial wall clock must be in (0, %s]", MaxTrialWall)
	case l.Serial <= 0 || l.Serial > MaxTrialSerial:
		return fmt.Errorf("trial serial budget must be in (0, %d] bytes", int64(MaxTrialSerial))
	case l.Boots != 1 && l.Boots != 2:
		return errors.New("a trial boots once or twice")
	case l.Scratch < 0 || l.Scratch > MaxScratch:
		return fmt.Errorf("trial scratch disk must be in [0, %d] bytes", int64(MaxScratch))
	}
	return nil
}

// fileCap is the size limit prlimit gives every file QEMU writes in a run under l.
func (l Limits) fileCap(baseSize int64) int64 { return max(WriteCap(baseSize), l.Scratch) }

// DiskNeed is all a run under l can write in its run directory: a scratch disk is a fourth file and
// raises the one per-file cap for all four (ADR 0011, point 6; ADR 0018, point 2).
func (l Limits) DiskNeed(baseSize int64) int64 {
	if l.Scratch == 0 {
		return 3 * WriteCap(baseSize)
	}
	return 4 * l.fileCap(baseSize)
}

// sandboxArgv wraps prog in prlimit and bwrap (ADR 0009, point 3): no network, no host $HOME,
// read-only /usr, base image and run directory, and only the three run files writable, plus a
// trial's scratch disk (ADR 0018), so the per-file size limit bounds all the disk a compromised
// QEMU can fill; the bwrap root and /dev are remounted read-only, so it has no tmpfs to fill (its
// memory is bounded only by the host). --core=0 because SIGXFSZ dumps core by default, and a QEMU
// core holds guest memory.
func sandboxArgv(base, runDir string, fsize int64, withScratch bool, prog ...string) []string {
	argv := []string{
		prlimitPath, fmt.Sprintf("--fsize=%d", fsize), "--core=0", "--",
		bwrapPath,
		"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--clearenv", "--setenv", "PATH", "/usr/bin",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib", "/lib64",
		"--symlink", "usr/bin", "/bin",
		"--proc", "/proc",
		"--dev", "/dev",
		"--dev-bind", "/dev/kvm", "/dev/kvm",
		"--ro-bind", base, inBase,
		"--ro-bind", runDir, inRun,
		"--bind", filepath.Join(runDir, overlay), inRun + "/" + overlay,
		"--bind", filepath.Join(runDir, results), inRun + "/" + results,
		"--bind", filepath.Join(runDir, firmVars), inRun + "/" + firmVars,
	}
	if withScratch {
		argv = append(argv, "--bind", filepath.Join(runDir, scratch), inRun+"/"+scratch)
	}
	argv = append(argv, "--remount-ro", "/dev", "--remount-ro", "/", "--")
	return append(argv, prog...)
}

// overlayArgv creates the per-run overlay; `-F raw` keeps qemu-img from probing the base's format.
func overlayArgv() []string {
	return []string{qemuImgPath, "create", "-q", "-f", "qcow2", "-b", inBase, "-F", "raw", inRun + "/" + overlay}
}

// qemuArgv is the VM: no default devices, no NIC, no display, and `format=` on every drive so no
// guest-written bytes are ever probed as an image header (ADR 0009, point 2). A trial's name and
// boot phase reach the guest only as systemd credentials over fw_cfg (ADR 0018, point 1).
func qemuArgv(job, withScratch bool, trial string, phase int) []string {
	argv := []string{
		qemuPath,
		"-nodefaults", "-nic", "none", "-display", "none", "-no-reboot",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-enable-kvm", "-machine", "q35", "-cpu", "host", "-m", "2048", "-smp", "2",
		"-drive", "if=pflash,unit=0,format=raw,readonly=on,file=" + ovmfCode,
		"-drive", "if=pflash,unit=1,format=raw,file=" + inRun + "/" + firmVars,
		// Only the root disk may boot: bootindex=0 makes OVMF keep this disk's boot option and delete
		// the other disks' (QemuBootOrderLib), so the job disk, whose bytes an agent chooses, never
		// boots; without the built-in shell, a failed boot cannot fall back to a startup.nsh on it.
		"-fw_cfg", "name=opt/org.tianocore/EFIShellSupport,string=no",
		"-drive", "if=none,id=root,format=qcow2,file=" + inRun + "/" + overlay,
		"-device", "virtio-blk-pci,drive=root,bootindex=0",
		"-drive", "if=none,id=results,format=raw,file=" + inRun + "/" + results,
		"-device", "virtio-blk-pci,drive=results,serial=" + resultsID,
	}
	if job {
		// The run directory is read-only in the sandbox as well, so the guest cannot change its job.
		argv = append(argv,
			"-drive", "if=none,id=job,format=raw,readonly=on,file="+inRun+"/"+jobDisk,
			"-device", "virtio-blk-pci,drive=job,serial="+jobID)
	}
	if withScratch {
		argv = append(argv,
			"-drive", "if=none,id=scratch,format=raw,file="+inRun+"/"+scratch,
			"-device", "virtio-blk-pci,drive=scratch,serial="+scratchID)
	}
	if trial != "" {
		argv = append(argv,
			"-fw_cfg", "name=opt/io.systemd.credentials/balistid.trial,string="+trial,
			"-fw_cfg", fmt.Sprintf("name=opt/io.systemd.credentials/balistid.phase,string=%d", phase))
	}
	return append(argv, "-serial", "stdio")
}

// Outcome of one run. Invalid is empty only when every boot exited cleanly and its results stream
// parsed; Facts are then what the last boot reported, FirstBoot the first of a run that booted twice.
type Outcome struct {
	Facts     []Record
	FirstBoot []Record
	Invalid   string
}

// ErrCleanup marks an error of Run after a run that ended: its Outcome stands, only the run
// directory could not be removed. Run returns no other error with a non-zero Outcome.
var ErrCleanup = errors.New("remove run directory")

// Run boots base once in a fresh run directory under parent, copies at most SerialBudget bytes of
// serial output to serial, and deletes the run directory afterwards (R5).
//
// A non-nil job is a job disk image (rangejob.EncodeDisk) attached read-only for the guest to run.
func Run(ctx context.Context, base, parent string, serial io.Writer, job []byte) (Outcome, error) {
	if job != nil && len(job) != rangejob.DiskBytes {
		return Outcome{}, fmt.Errorf("job disk is %d bytes, want %d", len(job), rangejob.DiskBytes)
	}
	return boot(ctx, base, parent, serial, job, runLimits, runCommand, ovmfVars)
}

// RunTrial boots base for the trial lim names, never with a job disk, and boots the same overlay
// and firmware variables a second time only after a first boot that armed its reset (ADR 0018).
func RunTrial(ctx context.Context, base, parent string, serial io.Writer, lim Limits) (Outcome, error) {
	if err := lim.check(); err != nil {
		return Outcome{}, err
	}
	return boot(ctx, base, parent, serial, nil, lim, runCommand, ovmfVars)
}

// command runs argv as runCommand does; tests replace it to stand in for QEMU.
type command func(ctx context.Context, argv []string, timeout time.Duration, budget int64, out io.Writer) string

// boot runs everything Run and RunTrial share; vars is the firmware variables template it copies.
func boot(ctx context.Context, base, parent string, serial io.Writer, job []byte, lim Limits, run command, vars string) (out Outcome, err error) {
	st, err := os.Stat(base)
	if err != nil {
		return Outcome{}, fmt.Errorf("base image: %w", err)
	}
	runDir, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return Outcome{}, fmt.Errorf("run directory: %w", err)
	}
	defer func() { err = removeRunDir(runDir, err) }()
	if err := prepare(runDir, job, vars, lim.Scratch); err != nil {
		return Outcome{}, err
	}
	fsize := lim.fileCap(st.Size())
	withScratch := lim.Scratch > 0

	var setup bytes.Buffer
	if why := run(ctx, sandboxArgv(base, runDir, WriteCap(st.Size()), false, overlayArgv()...), setupTimeout, SerialBudget, &setup); why != "" {
		return Outcome{Invalid: "overlay: " + why + ": " + Printable(strings.TrimSpace(setup.String()), setupShown)}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Wall)
	defer cancel()
	resultsPath := filepath.Join(runDir, results)
	var first []Record
	for phase := 1; ; phase++ {
		if why := run(ctx, sandboxArgv(base, runDir, fsize, withScratch, qemuArgv(job != nil, withScratch, lim.Trial, phase)...), lim.Wall, lim.Serial, serial); why != "" {
			return Outcome{FirstBoot: first, Invalid: bootName(phase) + why}, nil
		}
		o := readResults(resultsPath)
		switch {
		case o.Invalid != "":
			if phase > 1 {
				o.Invalid = "second boot: " + o.Invalid
			}
		case !echoes(o.Facts, lim.Trial, phase):
			o.Invalid = fmt.Sprintf("boot %d did not echo its trial and phase", phase)
		case phase < lim.Boots && !armed(o.Facts):
			o.Invalid = "first boot did not arm its reset"
		}
		if o.Invalid != "" || phase == lim.Boots {
			o.FirstBoot = first
			return o, nil
		}
		// A new file also undoes whatever boot 1's QEMU did to the old one's mode or size.
		if err := errors.Join(os.Remove(resultsPath), sparseFile(resultsPath, ResultsBytes)); err != nil {
			return Outcome{Facts: o.Facts, Invalid: "results disk: " + err.Error()}, nil
		}
		first = o.Facts
	}
}

func bootName(phase int) string {
	if phase == 1 {
		return "vm: "
	}
	return "second boot: "
}

// echoes reports whether a trial boot opened with the trial and phase the host gave it; a run
// without a trial has nothing to echo.
func echoes(facts []Record, trial string, phase int) bool {
	if trial == "" {
		return true
	}
	return len(facts) >= 2 && facts[0].Name == FactTrial && facts[0].Value == trial &&
		facts[1].Name == FactPhase && facts[1].Value == strconv.Itoa(phase)
}

// armed requires reset_armed=yes and no other value of it, so conflicting facts never arm a reset.
func armed(facts []Record) bool {
	seen := false
	for _, f := range facts {
		if f.Name == FactResetArmed {
			if f.Value != "yes" {
				return false
			}
			seen = true
		}
	}
	return seen
}

// removeRunDir deletes runDir after Run. A failure after a run that ended wraps ErrCleanup, so the
// caller keeps the Outcome; after a failed run it is only joined to runErr.
func removeRunDir(runDir string, runErr error) error {
	err := os.RemoveAll(runDir)
	switch {
	case err == nil:
		return runErr
	case runErr == nil:
		return fmt.Errorf("%w: %w", ErrCleanup, err)
	}
	return errors.Join(runErr, fmt.Errorf("remove run directory: %w", err))
}

// WriteCap is the size limit of each of the three files QEMU can write (overlay, results, firmware
// variables) for a base image of baseSize bytes in a run without a scratch disk; prlimit applies it
// per file, so such a run can write three times this much (Limits.DiskNeed, ADR 0011, point 6).
func WriteCap(baseSize int64) int64 { return baseSize + ResultsBytes }

// readResults treats every problem with the results disk as INVALID: a compromised QEMU can
// chmod, grow or garble the one file it may write, and none of that may pass or vanish.
func readResults(path string) Outcome {
	f, err := openRegular(path)
	if err != nil {
		return Outcome{Invalid: "results disk: " + err.Error()}
	}
	defer f.Close() //nolint:errcheck // read-only file
	st, err := f.Stat()
	if err != nil {
		return Outcome{Invalid: "results disk: " + err.Error()}
	}
	if st.Size() != ResultsBytes {
		return Outcome{Invalid: fmt.Sprintf("results disk is %d bytes, want %d", st.Size(), ResultsBytes)}
	}
	facts, err := Parse(f, ResultsBytes)
	if err != nil {
		return Outcome{Invalid: "results: " + err.Error()}
	}
	return Outcome{Facts: facts}
}

// prepare writes the zeroed results disk, a private copy of the firmware variables, the empty
// overlay file that qemu-img fills and a trial's scratch disk; the sandbox can write only these.
func prepare(runDir string, job []byte, varsTemplate string, scratchBytes int64) error {
	if job != nil {
		if err := os.WriteFile(filepath.Join(runDir, jobDisk), job, 0o400); err != nil {
			return fmt.Errorf("job disk: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, overlay), nil, 0o600); err != nil {
		return fmt.Errorf("overlay: %w", err)
	}
	vars, err := os.ReadFile(varsTemplate) //nolint:gosec // a fixed firmware path, or a test's file
	if err != nil {
		return fmt.Errorf("firmware variables: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, firmVars), vars, 0o600); err != nil { //nolint:gosec // run directory created by Run
		return fmt.Errorf("firmware variables: %w", err)
	}
	if err := sparseFile(filepath.Join(runDir, results), ResultsBytes); err != nil {
		return fmt.Errorf("results disk: %w", err)
	}
	if scratchBytes > 0 {
		if err := sparseFile(filepath.Join(runDir, scratch), scratchBytes); err != nil {
			return fmt.Errorf("scratch disk: %w", err)
		}
	}
	return nil
}

// sparseFile creates path, which must not exist, as size zero bytes.
func sparseFile(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // run directory created by Run
	if err != nil {
		return err //nolint:wrapcheck // callers name the file; Run's error text stays as it was
	}
	return errors.Join(f.Truncate(size), f.Close())
}

// runCommand runs argv with an empty environment and returns why the run is INVALID, or "" for a
// clean exit. Output beyond budget or a run beyond timeout kills the process (ADR 0009, point 4).
func runCommand(ctx context.Context, argv []string, timeout time.Duration, budget int64, out io.Writer) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pr, pw, err := os.Pipe()
	if err != nil {
		return "pipe: " + err.Error()
	}
	defer pr.Close()                                      //nolint:errcheck // read end, closed again only to unblock
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is built from constants and fixed sandbox paths
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return "start: " + err.Error()
	}
	_ = pw.Close()
	// A descendant that keeps the pipe open must not hold us past the deadline.
	stop := context.AfterFunc(ctx, func() { _ = pr.Close() })
	defer stop()

	lr := &io.LimitedReader{R: pr, N: budget + 1}
	_, copyErr := io.Copy(&capped{w: out, left: budget}, lr)
	overBudget := lr.N == 0
	if overBudget {
		cancel()
	}
	waitErr := cmd.Wait()
	switch {
	case overBudget:
		return fmt.Sprintf("output exceeded %d bytes", budget)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Sprintf("no exit within %s", timeout)
	case ctx.Err() != nil:
		return "cancelled"
	case waitErr != nil:
		return "exit: " + waitErr.Error()
	case copyErr != nil:
		return "output: " + copyErr.Error()
	}
	return ""
}

// capped writes at most left bytes to w and reports the rest as written, so the budget, not the
// writer, decides when to stop.
type capped struct {
	w    io.Writer
	left int64
}

func (c *capped) Write(p []byte) (int, error) {
	n := int64(len(p))
	if n > c.left {
		n = c.left
	}
	if n > 0 {
		if _, err := c.w.Write(p[:n]); err != nil {
			return 0, fmt.Errorf("copy output: %w", err)
		}
		c.left -= n
	}
	return len(p), nil
}
