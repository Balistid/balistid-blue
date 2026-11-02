package main

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The queue trial's burst overfills the queue the range's drop-in sets at least twice and, an argument per record
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
	queue := number("../../range/balistid-collector-range.conf", `(?m)^ExecStart=/\S+ .*-queue-bytes (\d+)`)
	qDepth := number("../../deploy/auditd/auditd.conf", `(?m)^q_depth = (\d+)$`)
	// two records per argument at most, and SYSCALL, EXECVE's argc, CWD, two PATH, PROCTITLE and EOE beside them
	most, least := 2*bigArgs+7, (bigArgs*bigArg+execveChunk-1)/execveChunk
	switch {
	case bigArg >= execveChunk:
		t.Errorf("an argument of %d bytes spans more than two records of %d", bigArg, execveChunk)
	case queueExecs*bigArgs*bigArg < 2*queue:
		t.Errorf("%d execs carry %d bytes, under twice the range's queue of %d", queueExecs, queueExecs*bigArgs*bigArg, queue)
	case queueExecs*most >= qDepth:
		t.Errorf("%d execs make up to %d kernel records, auditd's plugin queue holds %d", queueExecs, queueExecs*most, qDepth)
	case crashExecs*least <= qDepth:
		t.Errorf("%d execs make at least %d kernel records, not past auditd's plugin queue of %d", crashExecs, crashExecs*least, qDepth)
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
