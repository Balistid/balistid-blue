package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// The keys of deploy/audit/balistid.rules for root covering its tracks (ADR 0061).
const (
	keyKernel = "balistid-kernel"
	keyUring  = "balistid-uring"
	keyLogs   = "balistid-logs"
	keyConfig = "balistid-config"
	keyState  = "balistid-state"
	keyInject = "balistid-inject"
	// tracksModule is a module the range's kernel builds as one and nothing loads at boot (ADR 0061, point 3).
	tracksModule = "dummy"
	// archB64 is the audit arch of x86-64, the guest's; its file ops are what the probe credits.
	archB64 = "0xc000003e"
	oTrunc  = 0x200
)

// tracksTree is a tree whose writes, removals and creating or truncating opens the rules record, by fact part.
type tracksTree struct{ part, dir, key string }

var tracksTrees = []tracksTree{
	{"journal", "/var/log/journal", keyLogs},
	{"audit", "/etc/audit", keyConfig},
	{"systemd", "/etc/systemd", keyConfig},
	{"laurel", "/etc/laurel", keyConfig},
	{"programs", "/usr/local/lib/balistid", keyConfig},
	{"state", "/var/lib/balistid", keyState},
}

// tracksLeftOut are the programs the rules leave out of the trees: no record under the trees' keys may come from one.
var tracksLeftOut = []string{
	"/usr/local/lib/balistid/balistid-ledger",
	"/usr/local/lib/balistid/balistid-relay",
	"/usr/local/lib/balistid/balistid-runner",
}

// tracksCall is a syscall the rules record, called with arguments the kernel refuses: no module, kexec image, eBPF
// program, mount or io_uring results from it. io_uring_setup is the self-test's two probes (ioUringSetup).
type tracksCall struct {
	part string
	nr   uintptr
	key  string
	call func() error
}

func tracksCalls() []tracksCall {
	const bad = ^uintptr(0) // fd -1
	errno := func(_, _ uintptr, e syscall.Errno) error {
		if e != 0 {
			return e
		}
		return nil
	}
	raw := func(nr uintptr) func() error {
		return func() error { return errno(unix.Syscall6(nr, bad, 0, 0, 0, 0, 0)) }
	}
	return []tracksCall{
		{"init_module", unix.SYS_INIT_MODULE, keyKernel, func() error { return unix.InitModule(nil, "") }},
		{"finit_module", unix.SYS_FINIT_MODULE, keyKernel, func() error { return unix.FinitModule(-1, "", 0) }},
		{"delete_module", unix.SYS_DELETE_MODULE, keyKernel, func() error { return unix.DeleteModule("balistid_none", unix.O_NONBLOCK) }},
		// 0x8000 is no kexec flag: refused before any segment or file is read.
		{"kexec_load", unix.SYS_KEXEC_LOAD, keyKernel, func() error {
			return errno(unix.Syscall6(unix.SYS_KEXEC_LOAD, 0, 0, 0, 0x8000, 0, 0))
		}},
		{"kexec_file_load", unix.SYS_KEXEC_FILE_LOAD, keyKernel, func() error { return unix.KexecFileLoad(-1, -1, "", 0x8000) }},
		// BPF_PROG_LOAD without an attribute: no program type, no instructions.
		{"bpf", unix.SYS_BPF, keyKernel, func() error { return errno(unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, 0, 0)) }},
		{"mount", unix.SYS_MOUNT, keyKernel, func() error { return unix.Mount("none", "/balistid-none", "tmpfs", 0, "") }},
		{"umount2", unix.SYS_UMOUNT2, keyKernel, func() error { return unix.Unmount("/balistid-none", 0) }},
		{"move_mount", unix.SYS_MOVE_MOUNT, keyKernel, raw(unix.SYS_MOVE_MOUNT)},
		{"fsmount", unix.SYS_FSMOUNT, keyKernel, raw(unix.SYS_FSMOUNT)},
		{"fsconfig", unix.SYS_FSCONFIG, keyKernel, raw(unix.SYS_FSCONFIG)},
		{"fspick", unix.SYS_FSPICK, keyKernel, raw(unix.SYS_FSPICK)},
		{"mount_setattr", unix.SYS_MOUNT_SETATTR, keyKernel, raw(unix.SYS_MOUNT_SETATTR)},
		{"open_tree", unix.SYS_OPEN_TREE, keyKernel, raw(unix.SYS_OPEN_TREE)},
		{"pidfd_getfd", unix.SYS_PIDFD_GETFD, keyInject, raw(unix.SYS_PIDFD_GETFD)},
		{"io_uring_register", unix.SYS_IO_URING_REGISTER, keyUring, raw(unix.SYS_IO_URING_REGISTER)},
	}
}

// tracksProbe is what the guest did to cover its tracks and how to find it in the store.
type tracksProbe struct {
	pid      string            // the guest's
	token    string            // the name of each tree's file
	failed   map[string]string // a part whose action failed, and why
	modprobe [2]string         // the pids of modprobe's load and removal
}

// coverTracks does, as root without a loginuid, what ADR 0061 point 3 names, apart from io_uring_setup.
func coverTracks(ctx context.Context) tracksProbe {
	p := tracksProbe{pid: strconv.Itoa(os.Getpid()), failed: map[string]string{}}
	t, err := token("balistid-tracks-")
	if err != nil {
		p.failed["token"] = err.Error()
		return p
	}
	p.token = t
	for _, tr := range tracksTrees {
		if err := createTruncateRemove(filepath.Join(tr.dir, t)); err != nil {
			p.failed[tr.part] = err.Error()
		}
	}
	for _, c := range tracksCalls() {
		if c.call() == nil {
			p.failed[c.part] = "the kernel took it" // a refused call was the point; the record still counts
		}
	}
	for i, args := range [][]string{{tracksModule}, {"-r", tracksModule}} {
		cmd := exec.CommandContext(ctx, "/usr/bin/modprobe", args...) //nolint:gosec // fixed program and module
		if err := cmd.Run(); err != nil {
			p.failed["modprobe"] = strings.Join(args, " ") + ": " + err.Error()
			break
		}
		p.modprobe[i] = strconv.Itoa(cmd.Process.Pid)
	}
	return p
}

// createTruncateRemove creates path, opens it read-only with O_TRUNC, which perm=wa does not see (ADR 0061, point 2),
// and removes it.
func createTruncateRemove(path string) error {
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_TRUNC, 0) //nolint:gosec // the probe's own file
	if err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

// tracksParts is the order of the fact's parts.
func tracksParts() []string {
	parts := make([]string, 0, 32)
	for _, tr := range tracksTrees {
		parts = append(parts, tr.part)
	}
	for _, c := range tracksCalls() {
		parts = append(parts, c.part)
	}
	return append(parts, "io_uring_setup", "modprobe", "quiet")
}

// tracksFound is the fact tracks: per part "yes" when the store's Laurel lines hold its records, else why not.
func tracksFound(lines []byte, p tracksProbe) string {
	seen := map[string]bool{}
	var loud []string
	sc := bufio.NewScanner(bytes.NewReader(lines))
	sc.Buffer(make([]byte, 64<<10), rawrecord.MaxBytes+1)
	for sc.Scan() {
		r, ours, err := parseTracksRecord(sc.Bytes())
		if err != nil {
			loud = append(loud, err.Error())
			continue
		}
		if why := r.leftOutLeak(); ours && why != "" {
			loud = append(loud, why)
		}
		for _, part := range r.matches(p) {
			seen[part] = true
		}
	}
	var out []string
	for _, part := range tracksParts() {
		v := "no record"
		switch {
		case part == "quiet" && sc.Err() != nil:
			v = "unread: " + sc.Err().Error()
		case part == "quiet" && len(loud) > 0:
			v = fmt.Sprintf("%d, first %s", len(loud), loud[0])
		case part == "quiet":
			v = "yes"
		case p.failed["token"] != "":
			v = p.failed["token"]
		case p.failed[part] != "":
			v = p.failed[part]
		case part == "modprobe" && seen["modprobe:load"] && seen["modprobe:remove"], seen[part],
			seen[part+":CREATE"] && seen[part+":TRUNC"] && seen[part+":DELETE"]:
			v = "yes"
		}
		out = append(out, part+"="+strings.Map(printable, v))
	}
	return strings.Join(out, ",")
}

// printable keeps a fact's value on one line of printable ASCII without the separators of its parts.
func printable(r rune) rune {
	if r < ' ' || r > '~' || r == ',' || r == '=' {
		return '_'
	}
	return r
}

// tracksRecord is a SYSCALL or URINGOP event of Laurel's, its keys matched exactly: Laurel puts an enriched "PID"
// beside "pid" and the name "SYSCALL" beside the number "syscall".
type tracksRecord struct {
	uring                       bool
	arch, nr, pid, exe, success string
	a2                          uint64
	keys                        []string
	paths                       map[string]string // name: nametype
}

// tracksKeys are the keys quiet judges.
var tracksKeys = []string{keyKernel, keyUring, keyLogs, keyConfig, keyState}

// parseTracksRecord reads one Laurel line. ours is whether it is under a key of ADR 0061; an error is a line that is
// no JSON object, or one under such a key without the fields a judgement needs: quiet must not read it as silence.
func parseTracksRecord(line []byte) (r tracksRecord, ours bool, err error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(line, &top) != nil {
		return r, false, errors.New("a line that is no JSON object")
	}
	ev, ok := top["SYSCALL"]
	if !ok {
		ev, r.uring = top["URINGOP"], true
	}
	var sc map[string]json.RawMessage
	if ev == nil || json.Unmarshal(ev, &sc) != nil {
		return r, false, nil // another event type
	}
	r.keys = rangeguest.AuditKeys(sc["key"])
	ours = slices.ContainsFunc(r.keys, func(k string) bool { return slices.Contains(tracksKeys, k) })
	nrField := "syscall"
	if r.uring {
		nrField = "uring_op"
	}
	r.nr, r.pid = string(sc[nrField]), string(sc["pid"])
	errExe := json.Unmarshal(sc["exe"], &r.exe)
	errOK := json.Unmarshal(sc["success"], &r.success)
	if !r.uring {
		if json.Unmarshal(sc["arch"], &r.arch) != nil && ours {
			return r, ours, fmt.Errorf("a record of %v without arch", r.keys)
		}
		// Laurel lists a0 to a3 as ARGV, each in hex ("0x80200").
		var argv []string
		if json.Unmarshal(sc["ARGV"], &argv) == nil && len(argv) > 2 {
			r.a2, _ = strconv.ParseUint(strings.TrimPrefix(argv[2], "0x"), 16, 64)
		}
	}
	if ours && (errExe != nil || errOK != nil || !decimal(r.nr) || !decimal(r.pid)) {
		return r, ours, fmt.Errorf("a record of %v without its number, pid, exe or success", r.keys)
	}
	var paths []map[string]json.RawMessage
	if raw, ok := top["PATH"]; ok && json.Unmarshal(raw, &paths) == nil {
		r.paths = map[string]string{}
		for _, item := range paths {
			var name, nametype string
			if json.Unmarshal(item["name"], &name) == nil && json.Unmarshal(item["nametype"], &nametype) == nil {
				r.paths[name] = nametype
			}
		}
	}
	return r, ours, nil
}

func decimal(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// leftOutLeak is why r should not exist under the rules' never rules, or "": a left-out program's record, bpf of
// pid 1, openat2 of pid 1.
func (r tracksRecord) leftOutLeak() string {
	switch {
	case r.uring:
		return ""
	case r.pid == "1" && r.nr == strconv.Itoa(unix.SYS_BPF):
		return "bpf of pid 1"
	case r.pid == "1" && r.nr == strconv.Itoa(unix.SYS_OPENAT2):
		return "openat2 of pid 1"
	case slices.Contains(tracksLeftOut, r.exe):
		return r.exe
	}
	return ""
}

// matches are the parts of probe p that r proves: in each tree a file the guest created, opened read-only with
// O_TRUNC and removed, each a successful x86-64 call under the tree's key; each refused call by the guest under its
// key; modprobe's own successful load and removal.
func (r tracksRecord) matches(p tracksProbe) []string {
	var out []string
	has := func(k string) bool { return slices.Contains(r.keys, k) }
	nr := func(n uintptr) bool { return r.nr == strconv.FormatUint(uint64(n), 10) }
	if r.uring {
		return nil
	}
	if r.pid == p.pid && p.token != "" && r.arch == archB64 && r.success == "yes" {
		for _, tr := range tracksTrees {
			t := r.paths[filepath.Join(tr.dir, p.token)]
			switch {
			case !has(tr.key):
			case t == "CREATE" && nr(unix.SYS_OPENAT):
				out = append(out, tr.part+":CREATE")
			case t == "NORMAL" && nr(unix.SYS_OPENAT) && r.a2&oTrunc != 0:
				out = append(out, tr.part+":TRUNC")
			case t == "DELETE" && nr(unix.SYS_UNLINKAT):
				out = append(out, tr.part+":DELETE")
			}
		}
	}
	if r.pid == p.pid && r.arch == archB64 && r.success == "no" {
		for _, c := range tracksCalls() {
			if has(c.key) && nr(c.nr) {
				out = append(out, c.part)
			}
		}
		if has(keyUring) && nr(unix.SYS_IO_URING_SETUP) {
			out = append(out, "io_uring_setup")
		}
	}
	if has(keyKernel) && r.arch == archB64 && r.success == "yes" && p.modprobe[0] != "" {
		switch {
		case r.pid == p.modprobe[0] && (nr(unix.SYS_FINIT_MODULE) || nr(unix.SYS_INIT_MODULE)):
			out = append(out, "modprobe:load")
		case r.pid == p.modprobe[1] && nr(unix.SYS_DELETE_MODULE):
			out = append(out, "modprobe:remove")
		}
	}
	return out
}
