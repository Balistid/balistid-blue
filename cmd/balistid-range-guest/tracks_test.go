package main

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const tracksToken = "balistid-tracks-ab"

const guestPid = "4242"

var tracksProbeOK = tracksProbe{pid: guestPid, token: tracksToken, failed: map[string]string{}, modprobe: [2]string{"4300", "4301"}}

// tracksAllYes is the value internal/rangevm passes.
const tracksAllYes = rangevm.TracksAllYes

const guestExe = "/usr/lib/balistid-range/guest"

// call is a SYSCALL event shaped as Laurel writes it: the number beside the name, a0 to a3 as ARGV in hex
// (linux-audit-parser's Number::Hex, Laurel's coalesce.rs), the enriched "PID" beside "pid", PATH items when path
// is set.
type call struct {
	nr                       uint64
	pid, exe, success, key   string
	a2, path, nametype, arch string
}

func (c call) line() string {
	if c.arch == "" {
		c.arch = archB64
	}
	if c.a2 == "" {
		c.a2 = "0x0"
	}
	line := fmt.Sprintf(`{"ID":"1.000:1","SYSCALL":{"arch":%q,"syscall":%d,"SYSCALL":"x","success":%q,"ARGV":["0xffffff9c","0x7ffd1000",%q,"0x0"],"pid":%s,`+
		`"PID":{"EVENT_ID":"1.000:1"},"exe":%q,"key":%q}`, c.arch, c.nr, c.success, c.a2, c.pid, c.exe, c.key)
	if c.path != "" {
		line += fmt.Sprintf(`,"PATH":[{"item":0,"name":"/x","nametype":"PARENT"},{"item":1,"name":%q,"nametype":%q}]`, c.path, c.nametype)
	}
	return line + "}"
}

// tracksLines are every record the probe needs, by part, so a test can drop or change one.
func tracksLines() map[string][]string {
	lines := map[string][]string{}
	for _, tr := range tracksTrees {
		path := tr.dir + "/" + tracksToken
		lines[tr.part] = []string{
			call{nr: unix.SYS_OPENAT, pid: guestPid, exe: guestExe, success: "yes", key: tr.key, a2: "0x80241", path: path, nametype: "CREATE"}.line(),
			call{nr: unix.SYS_OPENAT, pid: guestPid, exe: guestExe, success: "yes", key: tr.key, a2: "0x80200", path: path, nametype: "NORMAL"}.line(),
			call{nr: unix.SYS_UNLINKAT, pid: guestPid, exe: guestExe, success: "yes", key: tr.key, path: path, nametype: "DELETE"}.line(),
		}
	}
	for _, c := range tracksCalls {
		lines[c.part] = []string{call{nr: c.nr, pid: guestPid, exe: guestExe, success: "no", key: c.key}.line()}
	}
	lines["modprobe"] = []string{
		call{nr: unix.SYS_FINIT_MODULE, pid: "4300", exe: "/usr/bin/kmod", success: "yes", key: keyKernel}.line(),
		call{nr: unix.SYS_DELETE_MODULE, pid: "4301", exe: "/usr/bin/kmod", success: "yes", key: keyKernel}.line(),
	}
	return lines
}

func join(lines map[string][]string, extra ...string) []byte {
	var all []string
	for _, part := range tracksParts() {
		all = append(all, lines[part]...)
	}
	return []byte(strings.Join(append(all, extra...), "\n") + "\n")
}

func part(fact, name string) string {
	for p := range strings.SplitSeq(fact, ",") {
		if v, ok := strings.CutPrefix(p, name+"="); ok {
			return v
		}
	}
	return "missing"
}

func TestTracksFoundIsAllYesForEveryRecord(t *testing.T) {
	var parts []string
	for _, p := range tracksParts() {
		parts = append(parts, p+"=yes")
	}
	if strings.Join(parts, ",") != tracksAllYes {
		t.Fatalf("rangevm expects %s,\nthe guest's parts are %s", tracksAllYes, strings.Join(parts, ","))
	}
	if got := tracksFound(join(tracksLines()), tracksProbeOK); got != tracksAllYes {
		t.Fatalf("tracks %s\nwant   %s", got, tracksAllYes)
	}
	// A key the kernel joined with another, and Laurel's list form, are the same key.
	lines := tracksLines()
	lines["bpf"] = []string{strings.Replace(lines["bpf"][0], `"key":"balistid-kernel"`, `"key":"other\u0001balistid-kernel"`, 1)}
	lines["kexec_load"] = []string{strings.Replace(lines["kexec_load"][0], `"key":"balistid-kernel"`, `"key":["other","balistid-kernel"]`, 1)}
	if got := tracksFound(join(lines), tracksProbeOK); got != tracksAllYes {
		t.Errorf("joined keys: %s", got)
	}
}

// Each way a part could read yes without its own record: the record gone, another pid, key, syscall or ABI, a
// failed file op, a refused call that succeeded, an open without O_TRUNC, one of a file's records missing,
// modprobe's records by another pid or failed.
func TestTracksFoundRefusesEachFalseYes(t *testing.T) {
	for name, c := range map[string]struct {
		part   string
		change func([]string) []string
	}{
		"journal gone":           {"journal", func([]string) []string { return nil }},
		"journal by another pid": {"journal", replaceAll(`"pid":4242`, `"pid":4243`)},
		"journal under config":   {"journal", replaceAll(`"key":"balistid-logs"`, `"key":"balistid-config"`)},
		"journal on i386":        {"journal", replaceAll(archB64, "0x40000003")},
		"journal ops failed":     {"journal", replaceAll(`"success":"yes"`, `"success":"no"`)},
		"journal not created":    {"journal", func(l []string) []string { return l[1:] }},
		"journal not truncated":  {"journal", func(l []string) []string { return []string{l[0], l[2]} }},
		"journal not removed":    {"journal", func(l []string) []string { return l[:2] }},
		"truncate without TRUNC": {"state", func(l []string) []string { return []string{l[0], strings.Replace(l[1], "0x80200", "0x80000", 1), l[2]} }},
		"truncate by unlinkat": {"state", func(l []string) []string {
			return []string{l[0], strings.Replace(l[1], `"syscall":257`, `"syscall":263`, 1), l[2]}
		}},
		"programs another file":  {"programs", replaceAll(tracksToken, "balistid-tracks-cd")},
		"bpf another syscall":    {"bpf", replaceAll(`"syscall":321`, `"syscall":59`)},
		"bpf by another pid":     {"bpf", replaceAll(`"pid":4242`, `"pid":4243`)},
		"bpf took it":            {"bpf", replaceAll(`"success":"no"`, `"success":"yes"`)},
		"bpf outcome unknown":    {"bpf", replaceAll(`"success":"no"`, `"success":""`)},
		"bpf on i386":            {"bpf", replaceAll(archB64, "0x40000003")},
		"bpf without a key":      {"bpf", replaceAll(`"key":"balistid-kernel"`, `"key":null`)},
		"mount under uring":      {"mount", replaceAll(`"key":"balistid-kernel"`, `"key":"balistid-uring"`)},
		"pidfd under kernel":     {"pidfd_getfd", replaceAll(`"key":"balistid-inject"`, `"key":"balistid-kernel"`)},
		"uring under kernel":     {"io_uring_setup", replaceAll(`"key":"balistid-uring"`, `"key":"balistid-kernel"`)},
		"modprobe failed load":   {"modprobe", replaceAll(`"success":"yes"`, `"success":"no"`)},
		"modprobe another pid":   {"modprobe", replaceAll(`"pid":4300`, `"pid":4242`)},
		"modprobe by a stranger": {"modprobe", replaceAll(`"pid":4300`, `"pid":4999`)},
		"removal by a stranger":  {"modprobe", replaceAll(`"pid":4301`, `"pid":4999`)},
		"modprobe only loads":    {"modprobe", func(l []string) []string { return l[:1] }},
	} {
		lines := tracksLines()
		lines[c.part] = c.change(lines[c.part])
		got := tracksFound(join(lines), tracksProbeOK)
		if v := part(got, c.part); v == "yes" {
			t.Errorf("%s: %s=yes", name, c.part)
		}
		if strings.Count(got, "=yes") != strings.Count(tracksAllYes, "=yes")-1 {
			t.Errorf("%s: more than %s changed: %s", name, c.part, got)
		}
	}
}

func replaceAll(old, repl string) func([]string) []string {
	return func(l []string) []string {
		out := make([]string, len(l))
		for i, s := range l {
			out[i] = strings.ReplaceAll(s, old, repl)
		}
		return out
	}
}

// quiet fails for a left-out program's record in its own directory (the never rule did not hold), bpf or openat2 of
// pid 1, a line that is no JSON object, a record under its keys without the fields to judge it, and an unread line.
func TestTracksQuietFails(t *testing.T) {
	ledger := "/usr/local/lib/balistid/balistid-ledger"
	for name, extra := range map[string]string{
		"ledger in its tiles": call{nr: unix.SYS_OPENAT, pid: "300", exe: ledger, success: "yes", key: keyState, path: "/var/lib/balistid/ledger/tile/0", nametype: "CREATE"}.line(),
		"ledger elsewhere":    call{nr: unix.SYS_OPENAT, pid: "300", exe: ledger, success: "yes", key: keyConfig, path: "/etc/audit/x", nametype: "CREATE"}.line(),
		"runner's results":    call{nr: unix.SYS_OPENAT, pid: "302", exe: "/usr/local/lib/balistid/balistid-runner", success: "yes", key: keyState, path: "/var/lib/balistid/results/r", nametype: "CREATE"}.line(),
		"systemd's bpf":       call{nr: unix.SYS_BPF, pid: "1", exe: "/usr/lib/systemd/systemd", success: "yes", key: keyKernel}.line(),
		"systemd's openat2":   call{nr: unix.SYS_OPENAT2, pid: "1", exe: "/usr/lib/systemd/systemd", success: "yes", key: keyConfig, path: "/etc/systemd/x", nametype: "NORMAL"}.line(),
		"a cut record":        `{"ID":"1.000:1","SYSCALL":{"exe":"/usr/local/lib/balistid/balistid-ledger","key":"balis`,
		"a cut joined key":    `{"ID":"1.000:1","SYSCALL":{"key":"x` + "\u0001" + `balistid-st`,
		"an exe not a string": `{"ID":"1.000:1","SYSCALL":{"arch":"0xc000003e","syscall":257,"success":"yes","pid":3,"key":"balistid-state","exe":3}}`,
		"no arch":             `{"ID":"1.000:1","SYSCALL":{"syscall":257,"success":"yes","pid":3,"key":"balistid-state","exe":"/x"}}`,
	} {
		if v := part(tracksFound(join(tracksLines(), extra), tracksProbeOK), "quiet"); !strings.HasPrefix(v, "1_ first ") {
			t.Errorf("%s: quiet=%s", name, v)
		}
	}
	long := strings.Repeat("x", rawrecord.MaxBytes+2)
	if v := part(tracksFound(join(tracksLines(), long), tracksProbeOK), "quiet"); !strings.HasPrefix(v, "unread") {
		t.Errorf("an unread line: quiet=%s", v)
	}
}

// Records the rules rightly keep do not fail quiet: the collector and journald (left out nowhere), a left-out
// program's exec, other event types and a valid io_uring event.
func TestTracksQuietKeepsRecordedActions(t *testing.T) {
	for name, extra := range map[string]string{
		"the ledger's exec": call{nr: unix.SYS_EXECVE, pid: "300", exe: "/usr/local/lib/balistid/balistid-ledger", success: "yes", key: "balistid-exec"}.line(),
		"the collector":     call{nr: unix.SYS_OPENAT, pid: "301", exe: "/usr/local/lib/balistid/balistid-collector", success: "yes", key: keyState, path: "/var/lib/balistid/collector/store/s", nametype: "CREATE"}.line(),
		"journald":          call{nr: unix.SYS_OPENAT, pid: "200", exe: "/usr/lib/systemd/systemd-journald", success: "yes", key: keyLogs, path: "/var/log/journal/m/system.journal", nametype: "CREATE"}.line(),
		"the canary":        call{nr: unix.SYS_OPENAT, pid: "301", exe: "/usr/local/lib/balistid/balistid-collector", success: "yes", key: collectorCanaryKey, path: "c-1", nametype: "CREATE"}.line(),
		"another event":     `{"ID":"1.000:2","CONFIG_CHANGE":[{"audit_enabled":0,"res":0}]}`,
		"an io_uring op":    `{"ID":"1.000:3","URINGOP":{"uring_op":18,"success":"yes","pid":5,"exe":"/x","key":"balistid-uring"}}`,
	} {
		if v := part(tracksFound(join(tracksLines(), extra), tracksProbeOK), "quiet"); v != "yes" {
			t.Errorf("%s: quiet=%s", name, v)
		}
	}
}

// A failed action names itself even with its records there, the reason kept on the fact's line.
func TestTracksFoundNamesAFailedAction(t *testing.T) {
	p := tracksProbeOK
	p.failed = map[string]string{"systemd": "write: open /etc/systemd/x, denied=1", "modprobe": "dummy: exit status 1"}
	got := tracksFound(join(tracksLines()), p)
	if v := part(got, "systemd"); v != "write: open /etc/systemd/x_ denied_1" {
		t.Errorf("systemd=%s", v)
	}
	if v := part(got, "modprobe"); v != "dummy: exit status 1" {
		t.Errorf("modprobe=%s", v)
	}
	p.failed = map[string]string{"token": "random token: no entropy"}
	if got := tracksFound(join(tracksLines()), p); strings.Count(got, "random token") != len(tracksParts())-1 {
		t.Errorf("no token: %s", got)
	}
}

// The calls are the rules' syscalls on x86-64, and each is refused when run unprivileged here.
func TestTracksCallsAreRefused(t *testing.T) {
	want := map[string]uint64{"init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246,
		"kexec_file_load": 320, "bpf": 321, "mount": 165, "umount2": 166, "move_mount": 429, "fsmount": 432,
		"fsconfig": 431, "fspick": 433, "mount_setattr": 442, "open_tree": 428, "pidfd_getfd": 438,
		"io_uring_setup": 425, "io_uring_register": 427}
	for _, c := range tracksCalls {
		if c.nr != want[c.part] {
			t.Errorf("%s is %d, want %d", c.part, c.nr, want[c.part])
		}
		if c.call() == nil {
			t.Errorf("%s: the kernel took it", c.part)
		}
	}
	if len(tracksCalls) != len(want) {
		t.Errorf("%d calls, want %d", len(tracksCalls), len(want))
	}
}
