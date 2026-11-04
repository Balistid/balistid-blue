package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// The keys of deploy/audit/balistid.rules for root covering its tracks (ADR 0061).
const (
	keyKernel = "balistid-kernel"
	keyUring  = "balistid-uring"
	keyLogs   = "balistid-logs"
	keyConfig = "balistid-config"
	keyState  = "balistid-state"
	// tracksModule is a module the range's kernel builds as one and nothing loads at boot (ADR 0061, point 3).
	tracksModule = "dummy"
)

// tracksTrees are the trees whose writes and removals the rules record, by fact part.
var tracksTrees = []struct{ part, dir, key string }{
	{"journal", "/var/log/journal", keyLogs},
	{"audit", "/etc/audit", keyConfig},
	{"systemd", "/etc/systemd", keyConfig},
	{"state", "/var/lib/balistid", keyState},
}

// tracksCall is a syscall the rules record, called with arguments the kernel refuses: no module, kexec image,
// eBPF program or io_uring results from it. io_uring_setup is the self-test's two probes (ioUringSetup).
type tracksCall struct {
	part string
	nr   uintptr
	key  string
	call func() error
}

// tracksLeftOut are the programs the rules leave out of the trees they own; no record under the keys above may
// come from one, nor bpf of pid 1.
var tracksLeftOut = []string{
	"/usr/lib/systemd/systemd-journald",
	"/usr/local/lib/balistid/balistid-collector",
	"/usr/local/lib/balistid/balistid-ledger",
	"/usr/local/lib/balistid/balistid-relay",
	"/usr/local/lib/balistid/balistid-runner",
}

func tracksCalls() []tracksCall {
	const bad = ^uintptr(0) // fd -1
	errno := func(_, _ uintptr, e syscall.Errno) error {
		if e != 0 {
			return e
		}
		return nil
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
		{"io_uring_register", unix.SYS_IO_URING_REGISTER, keyUring, func() error {
			return errno(unix.Syscall6(unix.SYS_IO_URING_REGISTER, bad, 0, 0, 0, 0, 0))
		}},
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
		path := filepath.Join(tr.dir, t)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			p.failed[tr.part] = "write: " + err.Error()
			continue
		}
		if err := os.Remove(path); err != nil {
			p.failed[tr.part] = "remove: " + err.Error()
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

// tracksParts is the order of the fact's parts.
func tracksParts() []string {
	parts := make([]string, 0, 16)
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
		r, ok := parseTracksRecord(sc.Bytes())
		if !ok {
			continue
		}
		if r.ours() && (slices.Contains(tracksLeftOut, r.exe) || r.nr == strconv.Itoa(unix.SYS_BPF) && r.pid == "1") {
			loud = append(loud, r.exe+" "+r.nr)
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
			v = fmt.Sprintf("%d from %s", len(loud), loud[0])
		case part == "quiet":
			v = "yes"
		case p.failed["token"] != "":
			v = p.failed["token"]
		case p.failed[part] != "":
			v = p.failed[part]
		case part == "modprobe" && seen["modprobe:load"] && seen["modprobe:remove"], seen[part],
			seen[part+":CREATE"] && seen[part+":DELETE"]:
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

// tracksRecord is what a SYSCALL event of Laurel's says, its keys matched exactly: Laurel puts an enriched
// "PID" beside "pid" and the name "SYSCALL" beside the number "syscall".
type tracksRecord struct {
	nr, pid, exe, success string
	keys                  []string
	paths                 map[string]string // name: nametype
}

func parseTracksRecord(line []byte) (tracksRecord, bool) {
	var top, sc map[string]json.RawMessage
	var paths []map[string]json.RawMessage
	r := tracksRecord{paths: map[string]string{}}
	if json.Unmarshal(line, &top) != nil || json.Unmarshal(top["SYSCALL"], &sc) != nil {
		return r, false
	}
	r.nr, r.pid = string(sc["syscall"]), string(sc["pid"])
	_ = json.Unmarshal(sc["exe"], &r.exe)
	_ = json.Unmarshal(sc["success"], &r.success)
	r.keys = auditKeys(sc["key"])
	if raw, ok := top["PATH"]; ok && json.Unmarshal(raw, &paths) == nil {
		for _, item := range paths {
			var name, nametype string
			if json.Unmarshal(item["name"], &name) == nil && json.Unmarshal(item["nametype"], &nametype) == nil {
				r.paths[name] = nametype
			}
		}
	}
	return r, true
}

// ours is whether r is under a key of ADR 0061.
func (r tracksRecord) ours() bool {
	return slices.ContainsFunc(r.keys, func(k string) bool {
		return k == keyKernel || k == keyUring || k == keyLogs || k == keyConfig || k == keyState
	})
}

// matches are the parts of probe p that r proves: a tree's file created or removed by the guest under the tree's
// key (both make the part), a refused call by the guest, modprobe's own load and removal.
func (r tracksRecord) matches(p tracksProbe) []string {
	var out []string
	has := func(k string) bool { return slices.Contains(r.keys, k) }
	if r.pid == p.pid && p.token != "" {
		for _, tr := range tracksTrees {
			if has(tr.key) && r.paths[filepath.Join(tr.dir, p.token)] != "" {
				out = append(out, tr.part+":"+r.paths[filepath.Join(tr.dir, p.token)])
			}
		}
		for _, c := range tracksCalls() {
			if has(c.key) && r.nr == strconv.Itoa(int(c.nr)) {
				out = append(out, c.part)
			}
		}
		if has(keyUring) && r.nr == strconv.Itoa(unix.SYS_IO_URING_SETUP) {
			out = append(out, "io_uring_setup")
		}
	}
	if has(keyKernel) && r.success == "yes" && p.modprobe[0] != "" {
		switch {
		case r.pid == p.modprobe[0] && (r.nr == strconv.Itoa(unix.SYS_FINIT_MODULE) || r.nr == strconv.Itoa(unix.SYS_INIT_MODULE)):
			out = append(out, "modprobe:load")
		case r.pid == p.modprobe[1] && r.nr == strconv.Itoa(unix.SYS_DELETE_MODULE):
			out = append(out, "modprobe:remove")
		}
	}
	return out
}
