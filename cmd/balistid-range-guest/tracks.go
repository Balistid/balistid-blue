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
	keyHandle = "balistid-handle"
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
// program, mount or io_uring results from it.
type tracksCall struct {
	part string
	nr   uint64
	a0   uint64 // the first argument a record must carry, or anyArg
	key  string
	call func() error
}

const (
	badFD  = ^uintptr(0) // fd -1
	anyArg = ^uint64(0)
)

func errnoOf(_, _ uintptr, e syscall.Errno) error {
	if e != 0 {
		return e
	}
	return nil
}

// refused calls nr with a bad first argument: refused before anything else is read.
func refused(nr uintptr) func() error {
	return func() error { return errnoOf(unix.Syscall6(nr, badFD, 0, 0, 0, 0, 0)) }
}

var tracksCalls = []tracksCall{
	{"init_module", unix.SYS_INIT_MODULE, anyArg, keyKernel, func() error { return unix.InitModule(nil, "") }},
	{"finit_module", unix.SYS_FINIT_MODULE, anyArg, keyKernel, func() error { return unix.FinitModule(-1, "", 0) }},
	{"delete_module", unix.SYS_DELETE_MODULE, anyArg, keyKernel, func() error { return unix.DeleteModule("balistid_none", unix.O_NONBLOCK) }},
	// 0x8000 is no kexec flag: refused before any segment or file is read.
	{"kexec_load", unix.SYS_KEXEC_LOAD, anyArg, keyKernel, func() error {
		return errnoOf(unix.Syscall6(unix.SYS_KEXEC_LOAD, 0, 0, 0, 0x8000, 0, 0))
	}},
	{"kexec_file_load", unix.SYS_KEXEC_FILE_LOAD, anyArg, keyKernel, func() error { return unix.KexecFileLoad(-1, -1, "", 0x8000) }},
	// BPF_PROG_LOAD without an attribute: no program type, no instructions.
	{"bpf", unix.SYS_BPF, anyArg, keyKernel, func() error { return errnoOf(unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, 0, 0)) }},
	{"mount", unix.SYS_MOUNT, anyArg, keyKernel, func() error { return unix.Mount("none", "/balistid-none", "tmpfs", 0, "") }},
	{"umount2", unix.SYS_UMOUNT2, anyArg, keyKernel, func() error { return unix.Unmount("/balistid-none", 0) }},
	{"move_mount", unix.SYS_MOVE_MOUNT, anyArg, keyKernel, refused(unix.SYS_MOVE_MOUNT)},
	{"fsmount", unix.SYS_FSMOUNT, anyArg, keyKernel, refused(unix.SYS_FSMOUNT)},
	{"fsconfig", unix.SYS_FSCONFIG, anyArg, keyKernel, refused(unix.SYS_FSCONFIG)},
	{"fspick", unix.SYS_FSPICK, anyArg, keyKernel, refused(unix.SYS_FSPICK)},
	{"mount_setattr", unix.SYS_MOUNT_SETATTR, anyArg, keyKernel, refused(unix.SYS_MOUNT_SETATTR)},
	{"open_tree", unix.SYS_OPEN_TREE, anyArg, keyKernel, refused(unix.SYS_OPEN_TREE)},
	{"pidfd_getfd", unix.SYS_PIDFD_GETFD, anyArg, rangeguest.InjectKey, refused(unix.SYS_PIDFD_GETFD)},
	// io_uring is disabled: refused before the entries are read; a huge count is refused too.
	{"io_uring_setup", unix.SYS_IO_URING_SETUP, anyArg, keyUring, refused(unix.SYS_IO_URING_SETUP)},
	{"io_uring_register", unix.SYS_IO_URING_REGISTER, anyArg, keyUring, refused(unix.SYS_IO_URING_REGISTER)},
	{"open_tree_attr", unix.SYS_OPEN_TREE_ATTR, anyArg, keyKernel, refused(unix.SYS_OPEN_TREE_ATTR)},
	// prctl with options that borrow an exe or keep capabilities, each refused: a bad fd, an unknown bit, a bad flag.
	{"prctl_set_mm", unix.SYS_PRCTL, unix.PR_SET_MM, rangeguest.InjectKey, func() error {
		return unix.Prctl(unix.PR_SET_MM, unix.PR_SET_MM_EXE_FILE, badFD, 0, 0)
	}},
	{"prctl_securebits", unix.SYS_PRCTL, unix.PR_SET_SECUREBITS, rangeguest.InjectKey, func() error {
		return unix.Prctl(unix.PR_SET_SECUREBITS, 1<<31, 0, 0, 0)
	}},
	{"prctl_keepcaps", unix.SYS_PRCTL, unix.PR_SET_KEEPCAPS, rangeguest.InjectKey, func() error {
		return unix.Prctl(unix.PR_SET_KEEPCAPS, 2, 0, 0, 0)
	}},
}

// tracksProbe is what the guest did to cover its tracks and how to find it in the store.
type tracksProbe struct {
	pid      string            // the guest's
	token    string            // the name of each tree's file
	failed   map[string]string // a part whose action failed, and why
	modprobe [2]string         // the pids of modprobe's load and removal
}

// coverTracks does, as root without a loginuid, what ADR 0061 point 4 names.
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
	if err := truncateByHandle(filepath.Join("/var/lib/balistid", t+"-h")); err != nil {
		p.failed["open_by_handle_at"] = err.Error()
	}
	for _, c := range tracksCalls {
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
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_TRUNC | unix.O_CLOEXEC})
	if err != nil {
		return fmt.Errorf("openat2: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("openat2: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove: %w", err)
	}
	return nil
}

// truncateByHandle creates path, opens it by its handle for writing with O_TRUNC, which carries no path a tree rule
// sees (ADR 0061, point 2), and removes it.
func truncateByHandle(path string) error {
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	defer os.Remove(path) //nolint:errcheck // the tree rule records the removal; a leftover file fails nothing
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return fmt.Errorf("handle: %w", err)
	}
	mount, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("mount fd: %w", err)
	}
	defer unix.Close(mount) //nolint:errcheck // a read-only directory
	fd, err := unix.OpenByHandleAt(mount, h, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC)
	if err != nil {
		return fmt.Errorf("open by handle: %w", err)
	}
	return unix.Close(fd) //nolint:wrapcheck // the probe's own file
}

// tracksParts is the order of the fact's parts.
func tracksParts() []string {
	parts := make([]string, 0, len(tracksTrees)+len(tracksCalls)+2)
	for _, tr := range tracksTrees {
		parts = append(parts, tr.part)
	}
	for _, c := range tracksCalls {
		parts = append(parts, c.part)
	}
	return append(parts, "open_by_handle_at", "modprobe", "quiet")
}

// tracksFound is the fact tracks: per part "yes" when the store's Laurel lines hold its records, else why not.
func tracksFound(lines []byte, p tracksProbe) string {
	seen := map[string]bool{}
	loud, first := 0, ""
	sc := bufio.NewScanner(bytes.NewReader(lines))
	sc.Buffer(make([]byte, 64<<10), rawrecord.MaxBytes+1)
	for sc.Scan() {
		r, ours, err := parseTracksRecord(sc.Bytes())
		why := r.leftOutLeak()
		switch {
		case err != nil:
			why = err.Error()
		case !ours:
			why = ""
		}
		if why != "" {
			if loud++; loud == 1 {
				first = why
			}
		}
		if err == nil {
			for _, part := range r.matches(p) {
				seen[part] = true
			}
		}
	}
	for _, tr := range tracksTrees {
		seen[tr.part] = seen[tr.part+":CREATE"] && seen[tr.part+":TRUNC"] && seen[tr.part+":TRUNC2"] && seen[tr.part+":DELETE"]
	}
	seen["modprobe"] = seen["modprobe:load"] && seen["modprobe:remove"]
	quiet := "yes"
	switch {
	case sc.Err() != nil:
		quiet = "unread: " + sc.Err().Error()
	case loud > 0:
		quiet = fmt.Sprintf("%d, first %s", loud, first)
	}
	out := make([]string, 0, len(tracksParts()))
	for _, part := range tracksParts() {
		v := "no record"
		switch {
		case part == "quiet":
			v = quiet
		case p.failed["token"] != "":
			v = p.failed["token"]
		case p.failed[part] != "":
			v = p.failed[part]
		case seen[part]:
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

// tracksRecord is a SYSCALL event of Laurel's, its keys matched exactly: Laurel puts an enriched "PID" beside "pid"
// and the name "SYSCALL" beside the number "syscall".
type tracksRecord struct {
	arch, pid, exe, success string
	nr                      uint64
	args                    []uint64 // a0 to a3, from Laurel's SYSCALL.ARGV
	keys                    []string
	paths                   map[string]string // name: nametype
}

// tracksKeys are the keys quiet judges.
var tracksKeys = []string{keyKernel, keyUring, keyLogs, keyConfig, keyState, keyHandle}

// parseTracksRecord reads one Laurel line. ours is whether it is under a key of ADR 0061 or the inject key; an error
// is a line that is no JSON object, a SYSCALL that is no object, or a record of ours without the fields a judgement
// needs, each of the right type: quiet must not read any of them as silence.
func parseTracksRecord(line []byte) (r tracksRecord, ours bool, err error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(line, &top) != nil || top == nil {
		return r, false, errors.New("a line that is no JSON object")
	}
	raw, ok := top["SYSCALL"]
	if !ok {
		return r, false, nil // another event type
	}
	var sc map[string]json.RawMessage
	if json.Unmarshal(raw, &sc) != nil || sc == nil {
		return r, false, errors.New("a SYSCALL that is no object")
	}
	r.keys = rangeguest.AuditKeys(sc["key"])
	ours = slices.ContainsFunc(r.keys, func(k string) bool { return slices.Contains(tracksKeys, k) || k == rangeguest.InjectKey })
	var argv []string
	okArch, okExe, okSuccess := jsonString(sc["arch"], &r.arch), jsonString(sc["exe"], &r.exe), jsonString(sc["success"], &r.success)
	nr, errNr := strconv.ParseUint(string(sc["syscall"]), 10, 64)
	r.nr, r.pid = nr, string(sc["pid"])
	okArgs := json.Unmarshal(sc["ARGV"], &argv) == nil && len(argv) == 4
	for _, a := range argv {
		n, ok := rangeguest.ArgHex(a)
		okArgs = okArgs && ok
		r.args = append(r.args, n)
	}
	if ours && (!okArch || !okExe || !okSuccess || errNr != nil || !decimal(r.pid) || !okArgs) {
		return r, ours, fmt.Errorf("a record of %v without its arch, number, pid, exe, outcome or arguments", r.keys)
	}
	var paths []map[string]json.RawMessage
	if raw, ok := top["PATH"]; ok && json.Unmarshal(raw, &paths) == nil {
		r.paths = map[string]string{}
		for _, item := range paths {
			var name, nametype string
			if jsonString(item["name"], &name) && jsonString(item["nametype"], &nametype) {
				r.paths[name] = nametype
			}
		}
	}
	return r, ours, nil
}

// jsonString decodes raw into s only when it is a JSON string: null and other types are not.
func jsonString(raw json.RawMessage, s *string) bool {
	return len(raw) > 0 && raw[0] == '"' && json.Unmarshal(raw, s) == nil
}

func decimal(s string) bool {
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// leftOutLeak is why r should not exist under the rules' never rules, or "": a left-out program's record, bpf of
// pid 1, openat2 of pid 1.
func (r tracksRecord) leftOutLeak() string {
	switch {
	case r.pid == "1" && r.nr == unix.SYS_BPF:
		return "bpf of pid 1"
	case r.pid == "1" && r.nr == unix.SYS_OPENAT2:
		return "openat2 of pid 1"
	case slices.Contains(tracksLeftOut, r.exe):
		return r.exe
	}
	return ""
}

// matches are the parts of probe p that r proves, each from a successful or refused x86-64 call: in each tree a
// file the guest created, opened read-only with O_TRUNC and removed under the tree's key; each refused call by the
// guest under its key; modprobe's own load and removal.
func (r tracksRecord) matches(p tracksProbe) []string {
	if r.arch != archB64 {
		return nil
	}
	var out []string
	has := func(k string) bool { return slices.Contains(r.keys, k) }
	switch {
	case r.pid == p.pid && r.success == "yes" && has(keyHandle) && r.nr == unix.SYS_OPEN_BY_HANDLE_AT &&
		r.args[2]&oTrunc != 0:
		out = append(out, "open_by_handle_at")
	case r.pid == p.pid && r.success == "yes":
		for _, tr := range tracksTrees {
			t := r.paths[filepath.Join(tr.dir, p.token)]
			switch {
			case !has(tr.key):
			case t == "CREATE" && r.nr == unix.SYS_OPENAT:
				out = append(out, tr.part+":CREATE")
			case t == "NORMAL" && r.nr == unix.SYS_OPENAT && r.args[2]&oTrunc != 0:
				out = append(out, tr.part+":TRUNC")
			case t == "NORMAL" && r.nr == unix.SYS_OPENAT2:
				out = append(out, tr.part+":TRUNC2") // its flags are behind a pointer the record does not show
			case t == "DELETE" && r.nr == unix.SYS_UNLINKAT:
				out = append(out, tr.part+":DELETE")
			}
		}
	case r.pid == p.pid && r.success == "no":
		for _, c := range tracksCalls {
			if has(c.key) && r.nr == c.nr && (c.a0 == anyArg || r.args[0] == c.a0) {
				out = append(out, c.part)
			}
		}
	case has(keyKernel) && r.success == "yes" && r.pid == p.modprobe[0] && (r.nr == unix.SYS_FINIT_MODULE || r.nr == unix.SYS_INIT_MODULE):
		out = append(out, "modprobe:load")
	case has(keyKernel) && r.success == "yes" && r.pid == p.modprobe[1] && r.nr == unix.SYS_DELETE_MODULE:
		out = append(out, "modprobe:remove")
	}
	return out
}
