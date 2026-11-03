package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The queue trial's burst overfills the queue it lowers the collector to at least twice and, an argument per record
// at most, fits auditd's plugin queue: only the collector's stage can lose. The crash trial's flood passes it at a
// record per execveChunk bytes at least (ADR 0039, points 2 and 5).
func TestBurstsAgainstTheQueues(t *testing.T) {
	number := func(path, pattern string) int {
		data, err := os.ReadFile(path) //nolint:gosec // the repo's own files, named below
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(pattern).FindSubmatch(data)
		if m == nil {
			t.Fatalf("no %s in %s", pattern, path)
		}
		n, err := strconv.Atoi(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	queue := smallQueue
	qDepth := number("../../deploy/auditd/auditd.conf", `(?m)^q_depth = (\d+)$`)
	// two records per argument at most, and SYSCALL, EXECVE's argc, CWD, two PATH, PROCTITLE and EOE beside them
	most, least := 2*bigArgs+7, (bigArgs*bigArg+execveChunk-1)/execveChunk
	switch {
	case bigArg >= execveChunk:
		t.Errorf("an argument of %d bytes spans more than two records of %d", bigArg, execveChunk)
	case queueExecs*bigArgs*bigArg < 2*queue:
		t.Errorf("%d execs carry %d bytes, under twice the trial's queue of %d", queueExecs, queueExecs*bigArgs*bigArg, queue)
	case queueExecs*most >= qDepth:
		t.Errorf("%d execs make up to %d kernel records, auditd's plugin queue holds %d", queueExecs, queueExecs*most, qDepth)
	case crashExecs*least <= qDepth:
		t.Errorf("%d execs make at least %d kernel records, not past auditd's plugin queue of %d", crashExecs, crashExecs*least, qDepth)
	}
}

// The queue trial's drop-in runs the collector's own argv with the small queue added, after the image's drop-in; an
// argv the added flag would not set, or one systemd could read otherwise than as given, is refused.
func TestQueueDropIn(t *testing.T) {
	argv := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	bin := "/usr/local/lib/balistid/balistid-collector"
	ranged := []string{bin, "-store", "/var/lib/balistid-range/scratch/store", "-canary", "/var/lib/balistid/collector/canary",
		"-rule-version", "adr-0004-v2", "-headroom", "67108864", "-log-commits"}
	body, want, err := queueDropIn(argv(ranged...))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(ranged, " ") + " -queue-bytes 8388608"
	if body != "[Service]\nExecStart=\nExecStart="+line+"\n" || want != argv(append(ranged, "-queue-bytes", "8388608")...) {
		t.Errorf("drop-in %q, argv %q", body, want)
	}
	if queueFlag(want) != "8388608" || smallQueue != 8<<20 || filepath.Base(queueDropInPath) <= "range.conf" {
		t.Errorf("queue %s of %d in %s", queueFlag(want), smallQueue, queueDropInPath)
	}
	for _, cmdline := range []string{
		argv(bin, "-queue-bytes", "4096"), argv(bin, "-queue-bytes=67108864"), argv(bin, "--queue-bytes", "1"), argv(bin, "--"),
		argv(bin, "-store", "/s", "--", "-x"), argv(bin, "-queue-bytes"), argv("balistid-collector", "-store", "/s"),
		strings.TrimSuffix(argv(bin), "\x00"), "", "\x00", argv(bin, ""), argv(bin, "-store", "/a b"), argv(bin, "-canary", "%h"),
		argv(bin, "-store", "$STORE"), argv(bin, "-store", `/a\x20`), argv(bin, "-store", "'/s'"), argv(bin, "-store", `"/s"`),
		argv(bin, ";", "-log-commits"), argv(bin, "-store", "/s\n-x"), argv(bin, "-store", "/é"),
	} {
		if body, want, err := queueDropIn(cmdline); err == nil {
			t.Errorf("%q: drop-in %q for argv %q", cmdline, body, want)
		}
	}
}

// Only the argv the drop-in starts, read from the process's cmdline, proves the small queue runs.
func TestRunsArgv(t *testing.T) {
	argv := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	bin := "/usr/local/lib/balistid/balistid-collector"
	want := argv(bin, "-store", "/s", "-log-commits", "-queue-bytes", "8388608")
	proc := t.TempDir()
	for pid, cmdline := range map[string]string{
		"10": want, "11": argv(bin, "-store", "/s", "-log-commits"), "12": argv(bin, "-store", "/s", "-queue-bytes", "8388608"),
		"13": argv(bin, "-store", "/s", "-log-commits", "-queue-bytes", "8388608", "-queue-bytes", "67108864"), "14": "",
		"15": argv(bin, "-store", "/s", "-log-commits", "-queue-bytes=8388608"),
	} {
		if err := os.MkdirAll(proc+"/"+pid, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(proc+"/"+pid+"/cmdline", []byte(cmdline), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := runsArgv(proc, "10", want); err != nil {
		t.Errorf("the drop-in's argv: %v", err)
	}
	for _, pid := range []string{"11", "12", "13", "14", "15", "16"} {
		if err := runsArgv(proc, pid, want); err == nil {
			t.Errorf("pid %s passes", pid)
		}
	}
}

// Only a whole "no" in the fresh generation, read before the deadline, lets auditd be killed.
func TestPreKillNeedsAFreshNo(t *testing.T) {
	fresh, now := time.Unix(100, 0), time.Unix(103, 0)
	deadline := now.Add(time.Second)
	for name, c := range map[string]struct {
		st      stateRead
		now     time.Time
		allowed bool
	}{
		"fresh no":        {stateRead{"no", fresh}, now, true},
		"yes":             {stateRead{"yes", fresh}, now, false},
		"changed":         {stateRead{stateChanged, time.Time{}}, now, false},
		"missing":         {stateRead{"missing", fresh}, now, false},
		"a later no":      {stateRead{"no", fresh.Add(5 * time.Second)}, now, false},
		"at the deadline": {stateRead{"no", fresh}, deadline, false},
	} {
		if err := preKill(c.st, fresh, c.now, deadline); (err == nil) != c.allowed {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A pidfd's process already gone cannot be the kill's: its exit came first. A cancelled trial kills nothing; a
// live process exits after the kill.
func TestKillAndWaitNeedsALiveProcess(t *testing.T) {
	start := func(args ...string) (*exec.Cmd, int) {
		cmd := exec.CommandContext(t.Context(), args[0], args[1:]...) //nolint:gosec // fixed test binaries
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd); _ = cmd.Wait() })
		return cmd, fd
	}
	_, gone := start("/usr/bin/true")
	for exited := false; !exited; {
		var err error
		if exited, err = pidfdExited(gone, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := killAndWait(t.Context(), gone); err == nil || !strings.Contains(err.Error(), "before the kill") {
		t.Errorf("an exited process killed: %v", err)
	}
	_, spared := start("/usr/bin/sleep", "30")
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := killAndWait(ended, spared); err == nil {
		t.Error("a cancelled trial killed")
	}
	if exited, err := pidfdExited(spared, 200*time.Millisecond); err != nil || exited {
		t.Errorf("a cancelled trial's process exited: %t %v", exited, err)
	}
	live, fd := start("/usr/bin/sleep", "30")
	before, err := uptime()
	if err != nil {
		t.Fatal(err)
	}
	at, err := killAndWait(t.Context(), fd)
	if err != nil || at < before {
		t.Fatalf("live process: exit at %s, before %s, %v", at, before, err)
	}
	if err := live.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
		t.Errorf("the live process ended as %v", err)
	}
}

// Without auditd's own line that its plugin queue drops events, the flood is no proof and nothing is killed.
func TestFloodAndKillNeedsTheDrop(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/usr/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = unix.Close(fd) }()
	quiet := func(context.Context) string { return "auditd started" }
	flooded := false
	flood := func(context.Context) { flooded = true } // no real flood: a host that audits execs would record it
	if _, err := floodAndKill(t.Context(), fd, flood, quiet, time.Now(), time.Now().Add(300*time.Millisecond)); err == nil || !flooded {
		t.Fatal("killed without a drop in the journal")
	}
	if exited, err := pidfdExited(fd, 0); err != nil || exited {
		t.Errorf("the process exited without a drop: %t %v", exited, err)
	}
}
