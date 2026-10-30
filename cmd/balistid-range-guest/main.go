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

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const (
	resultsDisk   = "/dev/disk/by-id/virtio-balistid-results"
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
	if len(os.Args) > 1 && os.Args[1] == writerArg {
		if err := writerMain(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "balistid-range-guest writer:", err)
			os.Exit(1)
		}
		return
	}
	for arg, sub := range map[string]func([]string) error{injectArg: injectMain, floodArg: floodMain, ledgerKeyArg: ledgerKeyMain,
		witnessKeyArg: witnessKeyMain, witnessAgentArg: witnessAgentMain} {
		if len(os.Args) > 1 && os.Args[1] == arg {
			if err := sub(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "balistid-range-guest %s: %v\n", arg, err)
				os.Exit(1)
			}
			return
		}
	}
	if len(os.Args) == 2 && os.Args[1] == storeSetupArg {
		if err := storeSetup(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, "balistid-range-guest store-setup:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "balistid-range-guest:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	diagnose(ctx)
	trial, phase, err := rangeguest.TrialCredentials(credentials())
	if err != nil {
		return fmt.Errorf("trial: %w", err)
	}
	dev, err := rangeguest.JobDevice(os.DirFS("/sys"))
	if err != nil {
		return fmt.Errorf("job disk: %w", err)
	}
	switch m, err := mode(trial, dev); {
	case err != nil:
		return err
	case m == modeTrial:
		return runTrial(ctx, trial, phase)
	case m == modeJob:
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
	add("laurel_user", procUser(pid, "no laurel process"))
	prm, eff, amb := threadCaps(pid, "no laurel process")
	add("laurel_cap_prm", prm)
	add("laurel_cap_eff", eff)
	add("laurel_cap_amb", amb)
	collector := collectorPID(ctx)
	add("collector_user", procUser(collector, "no collector process"))
	prm, eff, amb = threadCaps(collector, "no collector process")
	add("collector_cap_prm", prm)
	add("collector_cap_eff", eff)
	add("collector_cap_amb", amb)

	// The canary and the disable come back in one read of the store: each read restarts the collector.
	canaryToken, err := token("balistid-canary-")
	if err != nil {
		return fmt.Errorf("canary: %w", err)
	}
	canaryErr := exec.CommandContext(ctx, "/usr/bin/true", canaryToken).Run() //nolint:gosec // our own random token
	disableAudit(ctx)
	add("audit_enabled_after_e0", valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["enabled"]))
	lines, readErr := laurelLines(ctx, selfTestLines)
	add("canary", canarySeen(canaryErr, readErr, lines, canaryToken))
	add("e0_recorded", yesNo(readErr == nil && rangeguest.HasRefusedDisable(bytes.NewReader(lines))))
	// The collector's own canary went through the watch rule and Laurel's socket into its store.
	add("collector_canary", yesNo(readErr == nil && rangeguest.HasRuleKey(bytes.NewReader(lines), collectorCanaryKey)))
	printLines(lines, "audit_enabled")

	add("io_uring_sysctl", readTrim(ioUringSysctl))
	add("io_uring_off", ioUringSetup())
	add("io_uring_on", withIoUring("0"))
	_ = withIoUring("2")

	// The ledger anchored what the collector committed, under the range key (ADR 0027).
	add("ledger_anchored", ledgerAnchored(ctx))
	// The witness cosigned it, then refuses a fork and a rollback (T12). Only after a cosignature: a
	// witness that never cosigned would take the probe's checkpoint as its first.
	cos := ledgerCosigned(ctx)
	add("ledger_cosigned", cos)
	if cos != "yes" {
		for line := range strings.SplitSeq(output(ctx, "/usr/bin/journalctl", "-u", "balistid-relay.service", "-u",
			"balistid-range-witness.service", "-o", "cat", "--no-pager", "-n", "40"), "\n") {
			fmt.Printf("balistid-range-guest: witness: %.400q\n", line)
		}
	}
	fork := "skipped: nothing cosigned"
	if cos == "yes" {
		fork = forkRefused(ctx)
	}
	add("fork_refused", fork)
	sc := shardCosigned(ctx)
	add("shard_cosigned", sc)
	if sc != "yes" {
		for line := range strings.SplitSeq(output(ctx, "/usr/bin/journalctl", "-u", "balistid-collector.service", "-u",
			"balistid-ledger.service", "-o", "cat", "--no-pager", "-n", "40"), "\n") {
			fmt.Printf("balistid-range-guest: retention: %.400q\n", line)
		}
	}
	// A clean stop announced through the ledger's control socket and cosigned (ADR 0030): the self-test
	// powers off by force, which runs no unit's stop, so the guest stops the unit itself.
	for _, a := range []struct {
		fact, verb, unit string
		kind             entry.Announcement
	}{
		{"announce_cosigned", "stop", "balistid-announce.service", entry.AnnounceShutdown},
		{"suspend_announced", "start", "balistid-announce-suspend.service", entry.AnnounceSuspend},
	} {
		got := announced(ctx, a.verb, a.unit, a.kind)
		add(a.fact, got)
		if got != "yes" {
			for line := range strings.SplitSeq(output(ctx, "/usr/bin/journalctl", "-u", a.unit, "-u",
				"balistid-ledger.service", "-o", "cat", "--no-pager", "-n", "40"), "\n") {
				fmt.Printf("balistid-range-guest: announce: %.400q\n", line)
			}
		}
	}

	// The Pi's watcher verified what the relay served it, up to the witness's checkpoint (ADR 0031).
	pv := piVerified(ctx)
	add("pi_verified", pv)
	if pv != "yes" {
		for line := range strings.SplitSeq(output(ctx, "/usr/bin/journalctl", "-u", "balistid-pi.service", "-u",
			"balistid-relay.service", "-o", "cat", "--no-pager", "-n", "40"), "\n") {
			fmt.Printf("balistid-range-guest: pi: %.400q\n", line)
		}
	}

	// Last, because it stops Laurel and floods auditd.
	before, after, lost, journal := overflow(ctx, pid)
	add("overflow_before", before)
	add("overflow_after", after)
	add("overflow_journal", journal)
	add("audit_lost_after", lost)
	return write(facts)
}

// What the guest runs.
const (
	modeSelftest = "self-test"
	modeJob      = "job"
	modeTrial    = "trial"
)

// mode is a trial when the host passed one, an exec job when a job disk is attached, else the
// self-test; a trial with a job disk is refused, so agents never choose code a trial runs as root
// (ADR 0018, point 1).
func mode(trial, jobDev string) (string, error) {
	switch {
	case trial != "" && jobDev != "":
		return "", errors.New("a trial never runs with a job disk")
	case trial != "":
		return modeTrial, nil
	case jobDev != "":
		return modeJob, nil
	}
	return modeSelftest, nil
}

// The exec job's program and its transient unit; the report's limits are rangevm's, which the
// host checks.
const (
	jobProgram = "/run/balistid-job/program"
	jobUnit    = "balistid-job-run"
)

// runJob runs the job disk's program instead of the self-test, which would disable audit and flood
// auditd under it. The program runs as the unprivileged balistid-job user in its own transient unit,
// so a timeout or its limits end every process it started; what it did is left to the agent to judge
// from its output and the Laurel records written meanwhile.
func runJob(ctx context.Context, dev string) error {
	var facts []fact
	add := func(name, value string) { facts = append(facts, fact{name, value}) }
	add(rangevm.FactKernel, readTrim("/proc/sys/kernel/osrelease"))
	job, err := readJob(dev)
	if err != nil {
		add(rangevm.FactJobError, err.Error())
		return write(facts)
	}
	add(rangevm.FactJobSHA256, hex.EncodeToString(job.SHA256[:]))
	if err := os.MkdirAll(filepath.Dir(jobProgram), 0o755); err != nil { //nolint:gosec // world-readable so the job user can exec it
		return fmt.Errorf("job directory: %w", err)
	}
	if err := os.WriteFile(jobProgram, job.Program, 0o555); err != nil { //nolint:gosec // read-only, executable by the job user
		return fmt.Errorf("job program: %w", err)
	}
	// The store's clock is this guest's: what it received from here on is the job's window.
	sample := func() lossSample {
		overflow := freshOverflow(ctx) // first: its auditctl signal is not the job's
		return lossSample{lost: rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["lost"], overflow: overflow}
	}
	before := sample()
	t0 := time.Now().UnixNano()
	cmd, jobCtx, cancel := jobCommand(ctx, job)
	defer cancel()
	var out cappedBuffer
	out.left = rangevm.JobOutCap
	cmd.Stdout, cmd.Stderr = &out, &out
	result, status := unitResult(jobCtx, cmd.Run())
	add(rangevm.FactJobResult, result)
	add(rangevm.FactJobExit, status)
	add(rangevm.FactJobOutCut, yesNo(out.cut))
	for _, c := range rangeguest.Chunks(out.buf.Bytes(), rangevm.JobChunk) {
		add(rangevm.FactJobOut, c)
	}

	window, cut, why, err := jobEvidence(time.Sleep, func(b, a func(rawrecord.Record) error) error { return readStore(ctx, b, a) },
		t0, rangevm.JobLaurelCap, before, sample)
	reportWindow(os.Stdout, cut, why)
	add("canary", readStatus(err))
	add(rangevm.FactJobLaurelCut, cut)
	for _, c := range rangeguest.Chunks(window, rangevm.JobChunk) {
		add(rangevm.FactJobLaurel, c)
	}
	return write(facts)
}

// jobStopSec is the unit's TimeoutStopSec: how long systemd waits after SIGTERM before SIGKILL.
const jobStopSec = 10

// jobCommand runs the job's program as the unprivileged balistid-job user in the named transient
// unit jobUnit, which stays so its result can be read afterwards. systemd ends it, and every
// process it started, after the job disk's time limit; NoNewPrivileges matches an agent in the
// host sandbox. The returned context, which also bounds reading the result, outlasts the limit,
// the stop and its repeat after SIGKILL, and a margin, so the unit and not the context ends the job.
func jobCommand(ctx context.Context, job rangejob.Disk) (*exec.Cmd, context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(job.TimeoutS+2*jobStopSec+20)*time.Second)
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--wait", "--pipe", "--quiet", //nolint:gosec // fixed argv; the limit is an integer from the checked disk
		"--unit="+jobUnit, "-p", "User=balistid-job", "-p", "NoNewPrivileges=yes",
		"-p", fmt.Sprintf("RuntimeMaxSec=%d", job.TimeoutS), "-p", fmt.Sprintf("TimeoutStopSec=%d", jobStopSec),
		"-p", "MemoryMax=1G", "-p", "TasksMax=256", "--", jobProgram)
	return cmd, ctx, cancel
}

// readJob reads the whole job disk and returns what it carries only if every byte is as encoded.
func readJob(dev string) (rangejob.Disk, error) {
	f, err := os.Open(dev) //nolint:gosec // the device found by its virtio serial
	if err != nil {
		return rangejob.Disk{}, errors.New("cannot open the job disk")
	}
	defer f.Close() //nolint:errcheck // read-only
	disk := make([]byte, rangejob.DiskBytes+1)
	n, err := io.ReadFull(f, disk)
	if !errors.Is(err, io.ErrUnexpectedEOF) || n != rangejob.DiskBytes {
		return rangejob.Disk{}, errors.New("job disk has the wrong size")
	}
	job, err := rangejob.DecodeDisk(disk[:n])
	if err != nil {
		return rangejob.Disk{}, fmt.Errorf("job disk: %w", err)
	}
	return job, nil
}

// unitResult returns the job unit's result and its main process's exit status (a signal number for
// signal; for timeout or oom-kill a signal number or the program's own exit). systemd-run exits 0 only for success; any other exit is non-zero
// for a failed job and a failed start alike, so then systemd's own record decides, and only for a
// unit that exists and failed: systemctl shows a missing unit as a zeroed "success".
func unitResult(ctx context.Context, runErr error) (result, status string) {
	if runErr == nil {
		return "success", "0"
	}
	props := map[string]string{}
	out := output(ctx, "/usr/bin/systemctl", "show", "--property=LoadState,ActiveState,Result,ExecMainStatus", jobUnit+".service")
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = v
		}
	}
	if props["LoadState"] != "loaded" || props["ActiveState"] != "failed" || props["Result"] == "" || props["Result"] == "success" {
		return "unknown", "unknown"
	}
	return props["Result"], props["ExecMainStatus"]
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

// collectorPID is the main pid systemd started balistid-collector.service with, or "".
func collectorPID(ctx context.Context) string {
	pid := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", "balistid-collector.service"))
	if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
		return ""
	}
	return pid
}

// procUser is the name of pid's uid when its real, effective, saved and file uids agree.
func procUser(pid, absent string) string {
	if pid == "" {
		return absent
	}
	uids := strings.Fields(rangeguest.StatusField(readTrim("/proc/"+pid+"/status"), "Uid"))
	if len(uids) != 4 || uids[0] != uids[1] || uids[1] != uids[2] || uids[2] != uids[3] {
		return "uids differ: " + strings.Join(uids, " ")
	}
	return valueOr(rangeguest.UserName(readTrim("/etc/passwd"), uids[0]))
}

// threadCaps reports each capability set across all of pid's threads; differing threads show every
// value, which never matches the expected single value.
func threadCaps(pid, absent string) (prm, eff, amb string) {
	if pid == "" {
		return absent, absent, absent
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

// canarySeen is "seen" when the canary exec of token is among the Laurel lines the store read gave,
// "missing" when it is not or the read lacks its barrier, else the error.
func canarySeen(execErr, readErr error, lines []byte, token string) string {
	switch {
	case execErr != nil:
		return "error: " + execErr.Error()
	case readErr != nil:
		return readStatus(readErr)
	case rangeguest.HasExecArg(bytes.NewReader(lines), token):
		return "seen"
	}
	return "missing"
}

// token is prefix and 16 fresh random bytes in hex.
func token(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return prefix + hex.EncodeToString(b[:]), nil
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
		{"/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "short-monotonic", "-n", "200", "-u", "balistid-range-store", "-u", "balistid-collector.socket", "-u", "balistid-collector"},
		{"/usr/bin/systemctl", "status", "--no-pager", "-l", "-n", "0", "balistid-range-store", "balistid-collector.socket", "balistid-collector"},
		{"/usr/bin/journalctl", "-b", "-q", "--no-pager", "-o", "short-monotonic", "-n", "100", "-u", "balistid-range-ledger-key", "-u", "balistid-ledger"},
		{"/usr/bin/findmnt", "-n", "/var/lib/balistid-range/scratch"},
		{"/usr/bin/ls", "-ln", "/var/lib/balistid-range/scratch", "/usr/local/lib/balistid"},
		{"/usr/bin/auditctl", "-s"},
		{"/usr/bin/auditctl", "-l"},
		{"/usr/bin/findmnt", "-n", "/"},
		{"/usr/bin/ls", "-l", "/etc/audit", "/var/log/laurel"},
	} {
		out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // absolute binaries, fixed argv
		fmt.Printf("balistid-range-guest: $ %s (err %v)\n%s\n", strings.Join(argv, " "), err, out)
	}
}

// printLines prints the Laurel lines that contain substr to the console (serial.log), capped, so a
// failed check shows what the sensor actually wrote; quoted, so a record cannot forge a console line.
func printLines(lines []byte, substr string) {
	printed := 0
	for line := range bytes.SplitSeq(lines, []byte("\n")) {
		if bytes.Contains(line, []byte(substr)) && printed < 8<<10 {
			fmt.Printf("balistid-range-guest: laurel: %.2000q\n", line)
			printed += len(line)
		}
	}
}
