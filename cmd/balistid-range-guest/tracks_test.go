package main

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const (
	tracksToken = "balistid-tracks-ab"
	guestPid    = "4242"
	guestExe    = "/usr/lib/balistid-range/guest"
	ledgerExe   = "/usr/local/lib/balistid/balistid-ledger"
	// tracksAllYes is the value internal/rangevm passes.
	tracksAllYes = rangevm.TracksAllYes
)

var tracksProbeOK = tracksProbe{pid: guestPid, token: tracksToken, failed: map[string]string{}, modprobe: [2]string{"4300", "4301"}, euid: [2]string{"4400", "4401"}}

// call is a SYSCALL event shaped as Laurel writes it: the number beside the name, a0 to a3 as ARGV in hex
// (linux-audit-parser's Number::Hex, Laurel's coalesce.rs), the enriched "PID" beside "pid", PATH items when path
// is set.
type call struct {
	nr                     uint64
	pid, exe, success, key string
	a0, a2, path, nametype string
	arch                   string
}

func (c call) line() string {
	if c.arch == "" {
		c.arch = archB64
	}
	if c.a0 == "" {
		c.a0 = "0xffffff9c"
	}
	if c.a2 == "" {
		c.a2 = "0x0"
	}
	line := fmt.Sprintf(`{"ID":"1.000:1","SYSCALL":{"arch":%q,"syscall":%d,"SYSCALL":"x","success":%q,`+
		`"ARGV":[%q,"0x7ffd1000",%q,"0x0"],"pid":%s,"PID":{"EVENT_ID":"1.000:1"},"exe":%q,"key":%q}`,
		c.arch, c.nr, c.success, c.a0, c.a2, c.pid, c.exe, c.key)
	if c.path != "" {
		line += fmt.Sprintf(`,"PATH":[{"item":0,"name":"/x","nametype":"PARENT"},{"item":1,"name":%q,"nametype":%q}]`, c.path, c.nametype)
	}
	return line + "}"
}

// guestFile is a successful file op of the guest on its probe file in tree tr.
func guestFile(tr tracksTree, nr uint64, a2, nametype string) string {
	return call{nr: nr, pid: guestPid, exe: guestExe, success: "yes", key: tr.key, a2: a2, path: tr.dir + "/" + tracksToken, nametype: nametype}.line()
}

// tracksLines are every record the probe needs, by part, so a test can drop or change one.
func tracksLines() map[string][]string {
	lines := map[string][]string{}
	for _, tr := range tracksTrees {
		lines[tr.part] = []string{
			guestFile(tr, unix.SYS_OPENAT, "0x80241", "CREATE"),
			guestFile(tr, unix.SYS_OPENAT, "0x80200", "NORMAL"),
			guestFile(tr, unix.SYS_OPENAT2, "0x7ffd2000", "NORMAL"),
			guestFile(tr, unix.SYS_UNLINKAT, "0x0", "DELETE"),
		}
	}
	for _, c := range tracksCalls {
		a0 := ""
		if c.a0 != anyArg {
			a0 = fmt.Sprintf("0x%x", c.a0)
		}
		lines[c.part] = []string{call{nr: c.nr, pid: guestPid, exe: guestExe, success: "no", key: c.key, a0: a0}.line()}
	}
	lines["open_by_handle_at"] = []string{
		call{nr: unix.SYS_OPEN_BY_HANDLE_AT, pid: guestPid, exe: guestExe, success: "yes", key: keyHandle, a0: "0x5", a2: "0x80000"}.line(),
		call{nr: unix.SYS_OPEN_BY_HANDLE_AT, pid: guestPid, exe: guestExe, success: "yes", key: keyHandle, a0: "0x5", a2: "0x80201"}.line(),
	}
	lines["mount_suid"] = []string{withUids(call{nr: unix.SYS_MOUNT, pid: "4401", exe: guestExe, success: "no", key: keyKernel}.line(), "65534", "65534", "0")}
	lines["mount_euid"] = []string{withUids(call{nr: unix.SYS_MOUNT, pid: "4400", exe: guestExe, success: "no", key: keyKernel}.line(), "0", "65534", "0")}
	lines["modprobe"] = []string{
		call{nr: unix.SYS_FINIT_MODULE, pid: "4300", exe: "/usr/bin/kmod", success: "yes", key: keyKernel}.line(),
		call{nr: unix.SYS_DELETE_MODULE, pid: "4301", exe: "/usr/bin/kmod", success: "yes", key: keyKernel}.line(),
	}
	return lines
}

// withUids puts the real, effective and saved uid into a SYSCALL line, as the kernel's record carries them.
func withUids(line, uid, euid, suid string) string {
	return strings.Replace(line, `"pid":`, `"uid":`+uid+`,"euid":`+euid+`,"suid":`+suid+`,"pid":`, 1)
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
	lines["bpf"] = replaceAll(`"key":"balistid-kernel"`, `"key":"other\u0001balistid-kernel"`)(lines["bpf"])
	lines["kexec_load"] = replaceAll(`"key":"balistid-kernel"`, `"key":["other","balistid-kernel"]`)(lines["kexec_load"])
	if got := tracksFound(join(lines), tracksProbeOK); got != tracksAllYes {
		t.Errorf("joined keys: %s", got)
	}
}

func keep(idx ...int) func([]string) []string {
	return func(l []string) []string {
		var out []string
		for _, i := range idx {
			out = append(out, l[i])
		}
		return out
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

// Each way a part could read yes without its own record: the record gone, another pid, key, syscall, argument or
// ABI, a failed file op, a refused call that succeeded or has no outcome, an open without O_TRUNC, one of a file's
// records missing, modprobe's records by another pid or failed.
func TestTracksFoundRefusesEachFalseYes(t *testing.T) {
	for name, c := range map[string]struct {
		part   string
		change func([]string) []string
	}{
		"journal gone":             {"journal", func([]string) []string { return nil }},
		"journal by another pid":   {"journal", replaceAll(`"pid":4242`, `"pid":4243`)},
		"journal under config":     {"journal", replaceAll(`"key":"balistid-logs"`, `"key":"balistid-config"`)},
		"journal on i386":          {"journal", replaceAll(archB64, "0x40000003")},
		"journal ops failed":       {"journal", replaceAll(`"success":"yes"`, `"success":"no"`)},
		"journal not created":      {"journal", keep(1, 2, 3)},
		"journal not truncated":    {"journal", keep(0, 2, 3)},
		"journal no openat2":       {"journal", keep(0, 1, 3)},
		"journal not removed":      {"journal", keep(0, 1, 2)},
		"truncate without TRUNC":   {"state", replaceAll(`"0x80200"`, `"0x80000"`)},
		"truncate by unlinkat":     {"state", replaceAll(`"syscall":257,"SYSCALL":"x","success":"yes","ARGV":["0xffffff9c","0x7ffd1000","0x80200"`, `"syscall":263,"SYSCALL":"x","success":"yes","ARGV":["0xffffff9c","0x7ffd1000","0x80200"`)},
		"programs another file":    {"programs", replaceAll(tracksToken, "balistid-tracks-cd")},
		"bpf another syscall":      {"bpf", replaceAll(`"syscall":321`, `"syscall":59`)},
		"bpf by another pid":       {"bpf", replaceAll(`"pid":4242`, `"pid":4243`)},
		"bpf took it":              {"bpf", replaceAll(`"success":"no"`, `"success":"yes"`)},
		"bpf on i386":              {"bpf", replaceAll(archB64, "0x40000003")},
		"bpf without a key":        {"bpf", replaceAll(`"key":"balistid-kernel"`, `"key":null`)},
		"mount under uring":        {"mount", replaceAll(`"key":"balistid-kernel"`, `"key":"balistid-uring"`)},
		"pidfd under kernel":       {"pidfd_getfd", replaceAll(`"key":"balistid-inject"`, `"key":"balistid-kernel"`)},
		"uring under kernel":       {"io_uring_setup", replaceAll(`"key":"balistid-uring"`, `"key":"balistid-kernel"`)},
		"prctl another option":     {"prctl_set_mm", replaceAll(`"ARGV":["0x23"`, `"ARGV":["0xf"`)},
		"handle not truncating":    {"open_by_handle_at", replaceAll(`"0x80201"`, `"0x80001"`)},
		"handle under config":      {"open_by_handle_at", replaceAll(`"key":"balistid-handle"`, `"key":"balistid-config"`)},
		"handle by another pid":    {"open_by_handle_at", replaceAll(`"pid":4242`, `"pid":4243`)},
		"handle only read-only":    {"open_by_handle_at", keep(0)},
		"handle only writes":       {"open_by_handle_at", keep(1)},
		"suid mount by a stranger": {"mount_suid", replaceAll(`"pid":4401`, `"pid":4999`)},
		"suid mount took it":       {"mount_suid", replaceAll(`"success":"no"`, `"success":"yes"`)},
		"suid mount, real root":    {"mount_suid", replaceAll(`"uid":65534,"euid"`, `"uid":0,"euid"`)},
		"euid mount, real nobody":  {"mount_euid", replaceAll(`"uid":0,"euid"`, `"uid":65534,"euid"`)},
		"euid mount, still root":   {"mount_euid", replaceAll(`"euid":65534`, `"euid":0`)},
		"openat2 as DELETE":        {"journal", replaceAll(`"0x7ffd2000","0x0"],"pid":4242,"PID":{"EVENT_ID":"1.000:1"},"exe":"/usr/lib/balistid-range/guest","key":"balistid-logs"},"PATH":[{"item":0,"name":"/x","nametype":"PARENT"},{"item":1,"name":"/var/log/journal/balistid-tracks-ab","nametype":"NORMAL"}]`, `"0x7ffd2000","0x0"],"pid":4242,"PID":{"EVENT_ID":"1.000:1"},"exe":"/usr/lib/balistid-range/guest","key":"balistid-logs"},"PATH":[{"item":0,"name":"/x","nametype":"PARENT"},{"item":1,"name":"/var/log/journal/balistid-tracks-ab","nametype":"DELETE"}]`)},
		"openat2 by openat":        {"journal", replaceAll(`"syscall":437,"SYSCALL":"x","success":"yes","ARGV":["0xffffff9c","0x7ffd1000","0x7ffd2000"`, `"syscall":257,"SYSCALL":"x","success":"yes","ARGV":["0xffffff9c","0x7ffd1000","0x80000"`)},
		"euid mount by guest":      {"mount_euid", replaceAll(`"pid":4400`, `"pid":4242`)},
		"euid mount took it":       {"mount_euid", replaceAll(`"success":"no"`, `"success":"yes"`)},
		"euid mount by a stranger": {"mount_euid", replaceAll(`"pid":4400`, `"pid":4999`)},
		"euid umount2":             {"mount_euid", replaceAll(`"syscall":165`, `"syscall":166`)},
		"modprobe failed load":     {"modprobe", replaceAll(`"success":"yes"`, `"success":"no"`)},
		"modprobe another pid":     {"modprobe", replaceAll(`"pid":4300`, `"pid":4242`)},
		"modprobe by a stranger":   {"modprobe", replaceAll(`"pid":4300`, `"pid":4999`)},
		"removal by a stranger":    {"modprobe", replaceAll(`"pid":4301`, `"pid":4999`)},
		"modprobe only loads":      {"modprobe", keep(0)},
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

// quiet fails for a left-out program's record, bpf or openat2 of pid 1, a line that is no JSON object, a SYSCALL that
// is no object, a record of its keys without fields of the right type to judge it, and an unread line.
func TestTracksQuietFails(t *testing.T) {
	ours := call{nr: unix.SYS_OPENAT, pid: "3", exe: "/x", success: "yes", key: keyState}
	for name, extra := range map[string]string{
		"ledger in its tiles":   call{nr: unix.SYS_OPENAT, pid: "300", exe: ledgerExe, success: "yes", key: keyState, path: "/var/lib/balistid/ledger/tile/0", nametype: "CREATE"}.line(),
		"ledger elsewhere":      call{nr: unix.SYS_OPENAT, pid: "300", exe: ledgerExe, success: "yes", key: keyConfig, path: "/etc/audit/x", nametype: "CREATE"}.line(),
		"runner's results":      call{nr: unix.SYS_OPENAT, pid: "302", exe: "/usr/local/lib/balistid/balistid-runner", success: "yes", key: keyState, path: "/var/lib/balistid/results/r", nametype: "CREATE"}.line(),
		"systemd's bpf":         call{nr: unix.SYS_BPF, pid: "1", exe: "/usr/lib/systemd/systemd", success: "yes", key: keyKernel}.line(),
		"systemd's openat2":     call{nr: unix.SYS_OPENAT2, pid: "1", exe: "/usr/lib/systemd/systemd", success: "yes", key: keyConfig, path: "/etc/systemd/x", nametype: "NORMAL"}.line(),
		"a cut record":          `{"ID":"1.000:1","SYSCALL":{"exe":"/usr/local/lib/balistid/balistid-ledger","key":"balis`,
		"a cut joined key":      `{"ID":"1.000:1","SYSCALL":{"key":"x` + "\u0001" + `balistid-st`,
		"a null line":           `null`,
		"a null SYSCALL":        `{"ID":"1.000:1","SYSCALL":null}`,
		"a SYSCALL list":        `{"ID":"1.000:1","SYSCALL":[]}`,
		"an exe not a string":   strings.Replace(ours.line(), `"exe":"/x"`, `"exe":3`, 1),
		"a null exe":            strings.Replace(ours.line(), `"exe":"/x"`, `"exe":null`, 1),
		"a null arch":           strings.Replace(ours.line(), `"arch":"0xc000003e"`, `"arch":null`, 1),
		"no arch":               strings.Replace(ours.line(), `"arch":"0xc000003e",`, ``, 1),
		"a null outcome":        strings.Replace(ours.line(), `"success":"yes"`, `"success":null`, 1),
		"an overflowing arg":    call{nr: unix.SYS_OPENAT, pid: "3", exe: "/x", success: "yes", key: keyState, a2: "0x10000000000000000"}.line(),
		"an arg without 0x":     call{nr: unix.SYS_OPENAT, pid: "3", exe: "/x", success: "yes", key: keyState, a2: "80200"}.line(),
		"a padded arg":          call{nr: unix.SYS_OPEN_BY_HANDLE_AT, pid: "3", exe: "/x", success: "yes", key: keyHandle, a2: "0x080200"}.line(),
		"an inject record":      `{"ID":"1.000:1","SYSCALL":{"arch":"0xc000003e","syscall":157,"key":"balistid-inject"}}`,
		"an unknown arch":       strings.Replace(ours.line(), `"arch":"0xc000003e"`, `"arch":"0x1"`, 1),
		"an unknown outcome":    strings.Replace(ours.line(), `"success":"yes"`, `"success":"maybe"`, 1),
		"an empty exe":          strings.Replace(ours.line(), `"exe":"/x"`, `"exe":""`, 1),
		"three args":            strings.Replace(ours.line(), `,"0x0"],"pid"`, `],"pid"`, 1),
		"a URINGOP object":      `{"ID":"1.000:3","URINGOP":{"uring_op":18,"success":"yes","pid":5,"key":"balistid-uring"}}`,
		"a URINGOP null item":   `{"ID":"1.000:3","URINGOP":[null]}`,
		"a bare URINGOP":        `{"ID":"1.000:3","URINGOP":[{"key":"balistid-uring"}]}`,
		"a URINGOP null op":     `{"ID":"1.000:3","URINGOP":[{"uring_op":null,"success":"yes","pid":5,"key":"balistid-uring"}]}`,
		"a URINGOP odd outcome": `{"ID":"1.000:3","URINGOP":[{"uring_op":18,"success":"maybe","pid":5,"key":"balistid-uring"}]}`,
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
// program's exec, other event types and an io_uring event.
func TestTracksQuietKeepsRecordedActions(t *testing.T) {
	for name, extra := range map[string]string{
		"the ledger's exec":  call{nr: unix.SYS_EXECVE, pid: "300", exe: ledgerExe, success: "yes", key: "balistid-exec"}.line(),
		"the ledger's prctl": call{nr: unix.SYS_PRCTL, pid: "300", exe: ledgerExe, success: "no", key: "balistid-inject", a0: "0x23"}.line(),
		"the collector":      call{nr: unix.SYS_OPENAT, pid: "301", exe: "/usr/local/lib/balistid/balistid-collector", success: "yes", key: keyState, path: "/var/lib/balistid/collector/store/s", nametype: "CREATE"}.line(),
		"journald":           call{nr: unix.SYS_OPENAT, pid: "200", exe: "/usr/lib/systemd/systemd-journald", success: "yes", key: keyLogs, path: "/var/log/journal/m/system.journal", nametype: "CREATE"}.line(),
		"the canary":         call{nr: unix.SYS_OPENAT, pid: "301", exe: "/usr/local/lib/balistid/balistid-collector", success: "yes", key: collectorCanaryKey, path: "c-1", nametype: "CREATE"}.line(),
		"another event":      `{"ID":"1.000:2","CONFIG_CHANGE":[{"audit_enabled":0,"res":0}]}`,
		"an io_uring op":     `{"ID":"1.000:3","URINGOP":[{"uring_op":18,"success":"yes","pid":5,"key":"balistid-uring"}]}`,
		"no ring op":         `{"ID":"1.000:3","URINGOP":[]}`,
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
		"io_uring_setup": 425, "io_uring_register": 427, "open_tree_attr": 467, "prctl_set_mm": 157,
		"prctl_securebits": 157, "prctl_keepcaps": 157}
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
