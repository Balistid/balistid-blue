// Command balistid-range-guest runs inside a range VM, checks the guest's isolation and its floor-0
// sensor (ADR 0004 smoke test), writes the facts to the results disk and exits; its systemd unit
// powers the VM off either way (ADR 0009, point 5). A check that cannot run reports an error value,
// which the host judges as a failure, so the facts are written even when the sensor is broken.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

const (
	resultsDisk   = "/dev/disk/by-id/virtio-balistid-results"
	laurelLog     = "/var/log/laurel/audit.log"
	auditdState   = "/run/audit/auditd.state"
	ioUringSysctl = "/proc/sys/kernel/io_uring_disabled"
	// sysIoUringSetup is io_uring_setup on x86-64; Go's frozen syscall table predates it.
	sysIoUringSetup = 425
	waitLimit       = 30 * time.Second
	// floodMax bounds the overflow experiment: each exec makes several records, so this is far
	// beyond the 16384-entry plugin queue of deploy/auditd/auditd.conf.
	floodMax = 30000
)

type fact struct{ name, value string }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "balistid-range-guest:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	diagnose(ctx)
	if dev, err := rangeguest.JobDevice(os.DirFS("/sys")); err != nil {
		return err
	} else if dev != "" {
		return runJob(ctx, dev)
	}
	var facts []fact
	add := func(name, value string) { facts = append(facts, fact{name, value}) }

	add(rangevm.FactKernel, readTrim("/proc/sys/kernel/osrelease"))
	add(rangevm.FactNet, interfaces())
	add(rangevm.FactPCINet, networkPCIDevices())

	status := rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))
	for _, k := range []string{"enabled", "failure", "backlog_limit", "rate_limit", "lost"} {
		add("audit_"+k, valueOr(status[k]))
	}

	pid := laurelPID()
	add("laurel_user", laurelUser(pid))
	prm, eff, amb := laurelCaps(pid)
	add("laurel_cap_prm", prm)
	add("laurel_cap_eff", eff)
	add("laurel_cap_amb", amb)
	add("canary", canary(ctx))

	disableAudit(ctx)
	add("audit_enabled_after_e0", valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["enabled"]))
	add("e0_recorded", yesNo(waitFor(func() bool { return inLaurelLog(rangeguest.HasRefusedDisable) })))
	printLines(laurelLog, "audit_enabled")

	add("io_uring_sysctl", readTrim(ioUringSysctl))
	add("io_uring_off", ioUringSetup())
	add("io_uring_on", withIoUring("0"))
	_ = withIoUring("2")

	// Last, because it stops Laurel and floods auditd.
	before, after, lost, journal := overflow(ctx, pid)
	add("overflow_before", before)
	add("overflow_after", after)
	add("overflow_journal", journal)
	add("audit_lost_after", lost)
	return write(facts)
}

// Limits of an exec job's report: the results disk holds 16 MiB, and base64 adds a third.
const (
	jobChunk     = 32 << 10
	jobOutCap    = 2 << 20
	jobLaurelCap = 6 << 20
	jobProgram   = "/run/balistid-job/program"
)

// runJob runs the job disk's program instead of the self-test, which would disable audit and flood
// auditd under it. The program runs as the unprivileged balistid-job user in its own transient unit,
// so a timeout or its limits end every process it started; what it did is left to the agent to judge
// from its output and the Laurel records written meanwhile.
func runJob(ctx context.Context, dev string) error {
	var facts []fact
	add := func(name, value string) { facts = append(facts, fact{name, value}) }
	add(rangevm.FactKernel, readTrim("/proc/sys/kernel/osrelease"))
	program, sum, err := readJob(dev)
	if err != nil {
		add(rangevm.FactJobError, err.Error())
		return write(facts)
	}
	add(rangevm.FactJobSHA256, hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(filepath.Dir(jobProgram), 0o755); err != nil { //nolint:gosec // world-readable so the job user can exec it
		return fmt.Errorf("job directory: %w", err)
	}
	if err := os.WriteFile(jobProgram, program, 0o555); err != nil { //nolint:gosec // read-only, executable by the job user
		return fmt.Errorf("job program: %w", err)
	}
	offset := fileSize(laurelLog)

	ctx, cancel := context.WithTimeout(ctx, (rangejob.MaxTimeoutS+30)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet", //nolint:gosec // fixed argv
		"-p", "User=balistid-job", "-p", fmt.Sprintf("RuntimeMaxSec=%d", rangejob.MaxTimeoutS),
		"-p", "MemoryMax=1G", "-p", "TasksMax=256", "--", jobProgram)
	var out cappedBuffer
	out.left = jobOutCap
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	add(rangevm.FactJobExit, exitText(runErr))
	add(rangevm.FactJobOutCut, yesNo(out.cut))
	for _, c := range rangeguest.Chunks(out.buf.Bytes(), jobChunk) {
		add(rangevm.FactJobOut, c)
	}

	add("canary", canary(ctx)) // once seen, Laurel has written everything before it
	window, cut := readFrom(laurelLog, offset, jobLaurelCap)
	add(rangevm.FactJobLaurelCut, cut)
	for _, c := range rangeguest.Chunks(window, jobChunk) {
		add(rangevm.FactJobLaurel, c)
	}
	return write(facts)
}

// readJob reads the whole job disk and returns the program only if every byte is as encoded.
func readJob(dev string) ([]byte, [32]byte, error) {
	f, err := os.Open(dev) //nolint:gosec // the device found by its virtio serial
	if err != nil {
		return nil, [32]byte{}, errors.New("cannot open the job disk")
	}
	defer f.Close() //nolint:errcheck // read-only
	disk := make([]byte, rangejob.DiskBytes+1)
	n, err := io.ReadFull(f, disk)
	if !errors.Is(err, io.ErrUnexpectedEOF) || n != rangejob.DiskBytes {
		return nil, [32]byte{}, errors.New("job disk has the wrong size")
	}
	program, sum, err := rangejob.DecodeDisk(disk[:n])
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("job disk: %w", err)
	}
	return program, sum, nil
}

func exitText(err error) string {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return "0"
	case errors.As(err, &exit):
		return strconv.Itoa(exit.ExitCode())
	default:
		return "error"
	}
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// readFrom returns at most limit bytes of path from offset on, and whether it was cut or the log
// was rotated meanwhile (then it starts again at 0, and earlier lines of the job may be missing).
func readFrom(path string, offset, limit int64) ([]byte, string) {
	f, err := os.Open(path) //nolint:gosec // fixed log path
	if err != nil {
		return nil, "error"
	}
	defer f.Close() //nolint:errcheck // read-only
	cut := "no"
	if st, err := f.Stat(); err != nil || st.Size() < offset {
		offset, cut = 0, "rotated"
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, "error"
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, "error"
	}
	if int64(len(data)) > limit {
		return data[:limit], "yes"
	}
	return data, cut
}

// cappedBuffer keeps the first left bytes written and notes that more came.
type cappedBuffer struct {
	buf  bytes.Buffer
	left int
	cut  bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := min(len(p), c.left)
	c.buf.Write(p[:n])
	c.left -= n
	c.cut = c.cut || n < len(p)
	return len(p), nil
}

func write(facts []fact) error {
	var buf bytes.Buffer
	for _, f := range facts {
		rec := rangevm.Record{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindFact, Name: f.name, Value: f.value}
		if err := rangevm.Append(&buf, rec); err != nil {
			return fmt.Errorf("encode fact: %w", err)
		}
	}
	if err := rangevm.Append(&buf, rangevm.Record{SchemaVersion: rangevm.SchemaVersion, Kind: rangevm.KindEnd, Count: len(facts)}); err != nil {
		return fmt.Errorf("encode end record: %w", err)
	}
	disk, err := os.OpenFile(resultsDisk, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("results disk: %w", err)
	}
	_, werr := disk.Write(buf.Bytes())
	if err := errors.Join(werr, disk.Sync(), disk.Close()); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	return nil
}

func readTrim(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // fixed /proc, /sys and /etc paths
	if err != nil {
		return "error: " + err.Error()
	}
	return strings.TrimSpace(string(data))
}

func valueOr(v string) string {
	if v == "" {
		return "missing"
	}
	return v
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// output runs an absolute binary with a fixed argv and returns its stdout, or "" on failure.
func output(ctx context.Context, name string, args ...string) string {
	out, err := exec.CommandContext(ctx, name, args...).Output() //nolint:gosec // absolute binaries, fixed argv
	if err != nil {
		return ""
	}
	return string(out)
}

func interfaces() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "error: " + err.Error()
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// networkPCIDevices lists PCI devices of class 0x02 (network controller). They exist from PCI
// enumeration on, before a driver binds and an interface appears in /sys/class/net.
func networkPCIDevices() string {
	const dir = "/sys/bus/pci/devices"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "error: " + err.Error()
	}
	var found []string
	for _, e := range entries {
		if strings.HasPrefix(readTrim(filepath.Join(dir, e.Name(), "class")), "0x02") {
			found = append(found, e.Name())
		}
	}
	return strings.Join(found, ",")
}

// laurelPID finds Laurel as the child of auditd, so a process that only calls itself laurel does not count.
func laurelPID() string {
	procs, err := filepath.Glob("/proc/[0-9]*/status")
	if err != nil {
		return ""
	}
	comm := func(status string) string { return rangeguest.StatusField(status, "Name") }
	var auditd string
	statuses := map[string]string{}
	for _, p := range procs {
		pid := filepath.Base(filepath.Dir(p))
		statuses[pid] = readTrim(p)
		if comm(statuses[pid]) == "auditd" {
			auditd = pid
		}
	}
	for pid, s := range statuses {
		if auditd != "" && comm(s) == "laurel" && rangeguest.StatusField(s, "PPid") == auditd {
			return pid
		}
	}
	return ""
}

func laurelUser(pid string) string {
	if pid == "" {
		return "no laurel process"
	}
	uids := strings.Fields(rangeguest.StatusField(readTrim("/proc/"+pid+"/status"), "Uid"))
	if len(uids) != 4 || uids[0] != uids[1] || uids[1] != uids[2] || uids[2] != uids[3] {
		return "uids differ: " + strings.Join(uids, " ")
	}
	return valueOr(rangeguest.UserName(readTrim("/etc/passwd"), uids[0]))
}

// laurelCaps reports each capability set across all of Laurel's threads; differing threads show
// every value, which never matches the expected single value.
func laurelCaps(pid string) (prm, eff, amb string) {
	if pid == "" {
		return "no laurel process", "no laurel process", "no laurel process"
	}
	tasks, err := filepath.Glob("/proc/" + pid + "/task/[0-9]*/status")
	if err != nil || len(tasks) == 0 {
		return "no tasks", "no tasks", "no tasks"
	}
	var ps, es, as []string
	for _, t := range tasks {
		p, e, a := rangeguest.Caps(readTrim(t))
		ps, es, as = appendNew(ps, p), appendNew(es, e), appendNew(as, a)
	}
	return strings.Join(ps, ","), strings.Join(es, ","), strings.Join(as, ",")
}

func appendNew(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func inLaurelLog(match func(io.Reader) bool) bool {
	f, err := os.Open(laurelLog)
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // read-only file
	return match(f)
}

func waitFor(ok func() bool) bool {
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if ok() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// canary execs a binary with a fresh random argument that must come back through kernel, auditd
// and Laurel (acceptance canary_interval_s).
func canary(ctx context.Context) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "error: " + err.Error()
	}
	token := "balistid-canary-" + hex.EncodeToString(b[:])
	if err := exec.CommandContext(ctx, "/usr/bin/true", token).Run(); err != nil { //nolint:gosec // the token is our own random hex
		return "error: " + err.Error()
	}
	if waitFor(func() bool { return inLaurelLog(func(r io.Reader) bool { return rangeguest.HasExecArg(r, token) }) }) {
		return "seen"
	}
	return "missing"
}

// disableAudit tries `auditctl -e 0`. Its exit status and text prove nothing (the errno goes to
// syslog); the proof that the kernel refused is its own CONFIG_CHANGE record with res=0 and the
// state staying at 2, which the caller checks.
func disableAudit(ctx context.Context) {
	_ = exec.CommandContext(ctx, "/usr/bin/auditctl", "-e", "0").Run()
}

// ioUringSetup calls io_uring_setup(1, NULL): the kernel checks io_uring_disabled before it reads
// the parameters, so EPERM means disabled and EFAULT means allowed.
func ioUringSetup() string {
	_, _, errno := syscall.Syscall(sysIoUringSetup, 1, 0, 0)
	switch errno {
	case 0:
		return "created"
	case syscall.EPERM:
		return "EPERM"
	case syscall.EFAULT:
		return "EFAULT"
	default:
		return "errno " + strconv.Itoa(int(errno))
	}
}

// withIoUring sets the sysctl and probes again: the control that the probe can tell both states apart.
func withIoUring(value string) string {
	if err := os.WriteFile(ioUringSysctl, []byte(value), 0o644); err != nil { //nolint:gosec // a sysctl, not a file we create
		return "error: " + err.Error()
	}
	return ioUringSetup()
}

// overflow stops Laurel, floods auditd with exec records until its plugin queue reports an
// overflow, and resumes Laurel. It returns the overflow flag before and after, the kernel lost
// counter after (loss must stay at the plugin layer) and whether the journal names the overflow.
func overflow(ctx context.Context, pid string) (before, after, lost, journal string) {
	// auditd rewrites its state file on this signal; a failed signal leaves an old or no file,
	// which can only read as "no" or "missing", never as the overflow the check waits for.
	state := func() string {
		_ = exec.CommandContext(ctx, "/usr/bin/auditctl", "--signal", "state").Run()
		time.Sleep(200 * time.Millisecond)
		return rangeguest.OverflowDetected(readTrim(auditdState))
	}
	before = state()
	n, err := strconv.Atoi(pid)
	if err != nil {
		return before, "no laurel process", "missing", "no"
	}
	if err := syscall.Kill(n, syscall.SIGSTOP); err != nil {
		return before, "error: " + err.Error(), "missing", "no"
	}
	after = before
	for i := 0; i < floodMax && after != "yes"; i++ {
		_ = exec.CommandContext(ctx, "/usr/bin/true").Run()
		if i%1000 == 999 {
			after = state()
		}
	}
	after = state()
	if err := syscall.Kill(n, syscall.SIGCONT); err != nil {
		after = "error: " + err.Error()
	}
	lost = valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"])
	journal = yesNo(strings.Contains(output(ctx, "/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "cat"), "queue to plugins is full"))
	return before, after, lost, journal
}

// diagnose prints how the sensor came up to the console, which the host keeps as serial.log, so a
// failed check can be explained without the guest's journal, which is gone after the run.
func diagnose(ctx context.Context) {
	for _, argv := range [][]string{
		{"/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "short-monotonic", "-u", "auditd", "-u", "audit-rules", "-u", "systemd-sysctl"},
		{"/usr/bin/auditctl", "-s"},
		{"/usr/bin/auditctl", "-l"},
		{"/usr/bin/findmnt", "-n", "/"},
		{"/usr/bin/ls", "-l", "/etc/audit", "/var/log/laurel"},
	} {
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // absolute binaries, fixed argv
		fmt.Printf("balistid-range-guest: $ %s (err %v)\n%s\n", strings.Join(argv, " "), err, out)
	}
}

// printLines prints the lines of path that contain substr to the console (serial.log), capped,
// so a failed check shows what the sensor actually wrote.
func printLines(path, substr string) {
	data, err := os.ReadFile(path) //nolint:gosec // fixed log path
	if err != nil {
		fmt.Println("balistid-range-guest:", err)
		return
	}
	printed := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, substr) && printed < 8<<10 {
			fmt.Printf("balistid-range-guest: %s: %.2000s\n", path, line)
			printed += len(line)
		}
	}
}
