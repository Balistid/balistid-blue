package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const tracksToken = "balistid-tracks-ab"

var tracksProbeOK = tracksProbe{pid: "4242", token: tracksToken, failed: map[string]string{}, modprobe: [2]string{"4300", "4301"}}

// tracksAllYes is internal/rangevm's expected value of the fact tracks.
const tracksAllYes = "journal=yes,audit=yes,systemd=yes,laurel=yes,programs=yes,state=yes,init_module=yes,finit_module=yes," +
	"delete_module=yes,kexec_load=yes,kexec_file_load=yes,bpf=yes,umount2=yes,pidfd_getfd=yes,io_uring_register=yes," +
	"io_uring_setup=yes,modprobe=yes,quiet=yes"

// tracksLine is a SYSCALL event shaped as Laurel writes it: the number beside the name, the enriched "PID" beside
// "pid", and PATH items when path is set.
func tracksLine(nr int, pid, exe, success, key, path, nametype string) string {
	line := fmt.Sprintf(`{"ID":"1.000:1","SYSCALL":{"arch":"0xc000003e","syscall":%d,"SYSCALL":"x","success":%q,"pid":%s,`+
		`"PID":{"EVENT_ID":"1.000:1"},"exe":%q,"key":%q}`, nr, success, pid, exe, key)
	if path != "" {
		line += fmt.Sprintf(`,"PATH":[{"item":0,"name":"/x","nametype":"PARENT"},{"item":1,"name":%q,"nametype":%q}]`, path, nametype)
	}
	return line + "}"
}

const guestExe = "/usr/lib/balistid-range/guest"

// tracksLines are every record the probe needs, by part, so a test can drop or change one.
func tracksLines() map[string][]string {
	lines := map[string][]string{}
	for _, tr := range tracksTrees {
		path := tr.dir + "/" + tracksToken
		lines[tr.part] = []string{
			tracksLine(unix.SYS_OPENAT, "4242", guestExe, "yes", tr.key, path, "CREATE"),
			tracksLine(unix.SYS_UNLINKAT, "4242", guestExe, "yes", tr.key, path, "DELETE"),
		}
		if tr.trunc {
			lines[tr.part] = append(lines[tr.part], tracksLine(unix.SYS_OPENAT, "4242", guestExe, "yes", tr.key, path, "NORMAL"))
		}
	}
	for _, c := range tracksCalls() {
		lines[c.part] = []string{tracksLine(int(c.nr), "4242", guestExe, "no", c.key, "", "")}
	}
	lines["io_uring_setup"] = []string{tracksLine(unix.SYS_IO_URING_SETUP, "4242", guestExe, "no", keyUring, "", "")}
	lines["modprobe"] = []string{
		tracksLine(unix.SYS_FINIT_MODULE, "4300", "/usr/bin/kmod", "yes", keyKernel, "", ""),
		tracksLine(unix.SYS_DELETE_MODULE, "4301", "/usr/bin/kmod", "yes", keyKernel, "", ""),
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

// Each way a part could read yes without its own record: the record gone, another pid, another key, another
// syscall, only one of a file's two records, modprobe's records by another pid or failed.
func TestTracksFoundRefusesEachFalseYes(t *testing.T) {
	for name, c := range map[string]struct {
		part   string
		change func([]string) []string
	}{
		"journal gone":           {"journal", func([]string) []string { return nil }},
		"journal by another pid": {"journal", replaceAll(`"pid":4242`, `"pid":4243`)},
		"journal under config":   {"journal", replaceAll(`"key":"balistid-logs"`, `"key":"balistid-config"`)},
		"journal only created":   {"journal", func(l []string) []string { return l[:1] }},
		"journal only removed":   {"journal", func(l []string) []string { return l[1:] }},
		"journal not truncated":  {"journal", func(l []string) []string { return l[:2] }},
		"truncate by unlinkat": {"state", func(l []string) []string {
			return append(l[:2], strings.Replace(l[2], `"syscall":257`, `"syscall":263`, 1))
		}},
		"bpf by another pid":   {"bpf", replaceAll(`"pid":4242`, `"pid":4243`)},
		"pidfd under kernel":   {"pidfd_getfd", replaceAll(`"key":"balistid-inject"`, `"key":"balistid-kernel"`)},
		"state another file":   {"state", replaceAll(tracksToken, "balistid-tracks-cd")},
		"bpf another syscall":  {"bpf", replaceAll(`"syscall":321`, `"syscall":59`)},
		"bpf without a key":    {"bpf", replaceAll(`"key":"balistid-kernel"`, `"key":null`)},
		"uring under kernel":   {"io_uring_setup", replaceAll(`"key":"balistid-uring"`, `"key":"balistid-kernel"`)},
		"modprobe failed load": {"modprobe", replaceAll(`"success":"yes"`, `"success":"no"`)},
		"modprobe another pid": {"modprobe", replaceAll(`"pid":4300`, `"pid":4242`)},
		"modprobe only loads":  {"modprobe", func(l []string) []string { return l[:1] }},
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

// quiet fails for any record under the keys from a program the rules leave out, for bpf of pid 1, and when the
// lines could not all be read; records of left-out programs under other keys do not count.
func TestTracksQuiet(t *testing.T) {
	for name, extra := range map[string]string{
		"journald writes":  tracksLine(unix.SYS_WRITE, "300", "/usr/lib/systemd/systemd-journald", "yes", keyLogs, "/var/log/journal/x", "NORMAL"),
		"collector writes": tracksLine(unix.SYS_WRITE, "301", "/usr/local/lib/balistid/balistid-collector", "yes", keyState, "/var/lib/balistid/x", "NORMAL"),
		"runner writes":    tracksLine(unix.SYS_WRITE, "302", "/usr/local/lib/balistid/balistid-runner", "yes", keyState, "/var/lib/balistid/x", "NORMAL"),
		"systemd's bpf":    tracksLine(unix.SYS_BPF, "1", "/usr/lib/systemd/systemd", "yes", keyKernel, "", ""),
		"a cut record":     `{"ID":"1.000:1","SYSCALL":{"exe":"/usr/local/lib/balistid/balistid-ledger","key":"balistid-state"`,
	} {
		if v := part(tracksFound(join(tracksLines(), extra), tracksProbeOK), "quiet"); !strings.HasPrefix(v, "1 from ") {
			t.Errorf("%s: quiet=%s", name, v)
		}
	}
	canary := tracksLine(unix.SYS_OPENAT, "301", "/usr/local/lib/balistid/balistid-collector", "yes", collectorCanaryKey, "c-1", "CREATE")
	if v := part(tracksFound(join(tracksLines(), canary), tracksProbeOK), "quiet"); v != "yes" {
		t.Errorf("the collector's canary: quiet=%s", v)
	}
	long := strings.Repeat("x", rawrecord.MaxBytes+2)
	if v := part(tracksFound(join(tracksLines(), long), tracksProbeOK), "quiet"); !strings.HasPrefix(v, "unread") {
		t.Errorf("an unread line: quiet=%s", v)
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
	want := map[string]int{"init_module": 175, "finit_module": 313, "delete_module": 176, "kexec_load": 246,
		"kexec_file_load": 320, "bpf": 321, "umount2": 166, "pidfd_getfd": 438, "io_uring_register": 427}
	for _, c := range tracksCalls() {
		if strconv.Itoa(int(c.nr)) != strconv.Itoa(want[c.part]) {
			t.Errorf("%s is %d, want %d", c.part, c.nr, want[c.part])
		}
		if c.call() == nil {
			t.Errorf("%s: the kernel took it", c.part)
		}
	}
}
