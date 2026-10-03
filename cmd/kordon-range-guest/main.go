// Command kordon-range-guest runs inside a range VM, checks the guest's isolation and its floor-0
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

	"github.com/Kordon-Sec/kordon/internal/rangeguest"
	"github.com/Kordon-Sec/kordon/internal/rangevm"
)

const (
	resultsDisk   = "/dev/disk/by-id/virtio-kordon-results"
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
		fmt.Fprintln(os.Stderr, "kordon-range-guest:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
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

	add("e0_result", disableAudit(ctx))
	add("audit_enabled_after_e0", valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["enabled"]))
	add("e0_recorded", yesNo(waitFor(func() bool { return inLaurelLog(rangeguest.HasRefusedDisable) })))

	add("io_uring_sysctl", readTrim(ioUringSysctl))
	add("io_uring_off", ioUringSetup())
	add("io_uring_on", withIoUring("0"))
	add("io_uring_off_again", withIoUring("2"))

	// Last, because it stops Laurel and floods auditd.
	before, after, lost, journal := overflow(ctx, pid)
	add("overflow_before", before)
	add("overflow_after", after)
	add("overflow_journal", journal)
	add("audit_lost_after", lost)
	return write(facts)
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
	token := "kordon-canary-" + hex.EncodeToString(b[:])
	if err := exec.CommandContext(ctx, "/usr/bin/true", token).Run(); err != nil { //nolint:gosec // the token is our own random hex
		return "error: " + err.Error()
	}
	if waitFor(func() bool { return inLaurelLog(func(r io.Reader) bool { return rangeguest.HasExecArg(r, token) }) }) {
		return "seen"
	}
	return "missing"
}

// disableAudit tries `auditctl -e 0`, which -e 2 must refuse with EPERM.
func disableAudit(ctx context.Context) string {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "/usr/bin/auditctl", "-e", "0")
	cmd.Stderr = &stderr
	err := cmd.Run()
	switch {
	case err == nil:
		return "accepted"
	case strings.Contains(stderr.String(), "Operation not permitted"):
		return "EPERM"
	default:
		return "other: " + strings.TrimSpace(stderr.String())
	}
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
