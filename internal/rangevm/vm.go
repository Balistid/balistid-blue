package rangevm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
)

// Limits of one run (ADR 0009, points 3–5).
const (
	ResultsBytes = 16 << 20
	SerialBudget = 1 << 20
	RunTimeout   = 10 * time.Minute
	setupTimeout = time.Minute
)

// sandboxArgv wraps prog in prlimit and bwrap (ADR 0009, point 3): no network, no host $HOME,
// read-only /usr, base image and run directory, and only the three run files writable, so the
// per-file size limit bounds all the disk a compromised QEMU can fill; the bwrap root and /dev are
// remounted read-only, so it has no tmpfs to fill (its memory is bounded only by the host).
// --core=0 because SIGXFSZ dumps core by default, and a QEMU core holds guest memory.
func sandboxArgv(base, runDir string, fsize int64, prog ...string) []string {
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
		"--remount-ro", "/dev",
		"--remount-ro", "/",
		"--",
	}
	return append(argv, prog...)
}

// overlayArgv creates the per-run overlay; `-F raw` keeps qemu-img from probing the base's format.
func overlayArgv() []string {
	return []string{qemuImgPath, "create", "-q", "-f", "qcow2", "-b", inBase, "-F", "raw", inRun + "/" + overlay}
}

// qemuArgv is the VM: no default devices, no NIC, no display, and `format=` on every drive so no
// guest-written bytes are ever probed as an image header (ADR 0009, point 2).
func qemuArgv(job bool) []string {
	argv := []string{
		qemuPath,
		"-nodefaults", "-nic", "none", "-display", "none", "-no-reboot",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-enable-kvm", "-machine", "q35", "-cpu", "host", "-m", "2048", "-smp", "2",
		"-drive", "if=pflash,unit=0,format=raw,readonly=on,file=" + ovmfCode,
		"-drive", "if=pflash,unit=1,format=raw,file=" + inRun + "/" + firmVars,
		"-drive", "if=virtio,format=qcow2,file=" + inRun + "/" + overlay,
		"-drive", "if=none,id=results,format=raw,file=" + inRun + "/" + results,
		"-device", "virtio-blk-pci,drive=results,serial=" + resultsID,
	}
	if job {
		// The run directory is read-only in the sandbox as well, so the guest cannot change its job.
		argv = append(argv,
			"-drive", "if=none,id=job,format=raw,readonly=on,file="+inRun+"/"+jobDisk,
			"-device", "virtio-blk-pci,drive=job,serial="+jobID)
	}
	return append(argv, "-serial", "stdio")
}

// Outcome of one run. Invalid is empty only when the VM exited cleanly and the results stream
// parsed; Facts are then what the guest reported.
type Outcome struct {
	Facts   []Record
	Invalid string
}

// Run boots base once in a fresh run directory under parent, copies at most SerialBudget bytes of
// serial output to serial, and deletes the run directory afterwards (R5).
//
// A non-nil job is a job disk image (rangejob.EncodeDisk) attached read-only for the guest to run.
func Run(ctx context.Context, base, parent string, serial io.Writer, job []byte) (out Outcome, err error) {
	if job != nil && len(job) != rangejob.DiskBytes {
		return Outcome{}, fmt.Errorf("job disk is %d bytes, want %d", len(job), rangejob.DiskBytes)
	}
	st, err := os.Stat(base)
	if err != nil {
		return Outcome{}, fmt.Errorf("base image: %w", err)
	}
	runDir, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return Outcome{}, fmt.Errorf("run directory: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(runDir); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("remove run directory: %w", rmErr))
		}
	}()
	if err := prepare(runDir, job); err != nil {
		return Outcome{}, err
	}
	fsize := WriteCap(st.Size())

	if why := runCommand(ctx, sandboxArgv(base, runDir, fsize, overlayArgv()...), setupTimeout, SerialBudget, io.Discard); why != "" {
		return Outcome{Invalid: "overlay: " + why}, nil
	}
	if why := runCommand(ctx, sandboxArgv(base, runDir, fsize, qemuArgv(job != nil)...), RunTimeout, SerialBudget, serial); why != "" {
		return Outcome{Invalid: "vm: " + why}, nil
	}
	return readResults(filepath.Join(runDir, results)), nil
}

// WriteCap is the size limit of each of the three files QEMU can write (overlay, results, firmware
// variables) for a base image of baseSize bytes; prlimit applies it per file, so a run can write up
// to three times this much (ADR 0011, point 6).
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

// prepare writes the zeroed results disk, a private copy of the firmware variables and the empty
// overlay file that qemu-img fills; the sandbox can write only these three files.
func prepare(runDir string, job []byte) error {
	if job != nil {
		if err := os.WriteFile(filepath.Join(runDir, jobDisk), job, 0o400); err != nil { //nolint:gosec // run directory created by Run
			return fmt.Errorf("job disk: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, overlay), nil, 0o600); err != nil {
		return fmt.Errorf("overlay: %w", err)
	}
	vars, err := os.ReadFile(ovmfVars)
	if err != nil {
		return fmt.Errorf("firmware variables: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, firmVars), vars, 0o600); err != nil { //nolint:gosec // run directory created by Run
		return fmt.Errorf("firmware variables: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(runDir, results), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // run directory created by Run
	if err != nil {
		return fmt.Errorf("results disk: %w", err)
	}
	if err := f.Truncate(ResultsBytes); err != nil {
		_ = f.Close()
		return fmt.Errorf("results disk: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("results disk: %w", err)
	}
	return nil
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
