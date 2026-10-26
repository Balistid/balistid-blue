package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// numberedExec is the store record of a Laurel line of the exec of number n.
func numberedExec(n uint64) rawrecord.Record {
	line := fmt.Sprintf(`{"EXECVE":{"argc":2,"ARGV":["/usr/bin/true","%s%d"]}}`, rangeguest.NumberPrefix, n)
	return rawrecord.New(n, store.SensorProvider, n, 1, []byte(line))
}

func recoveredRecord(seq uint64, data string) rawrecord.Record {
	return rawrecord.New(seq, store.HealthProvider, 0, 1, []byte(data))
}

// The failure measures the collector only after a whole 10 s window at the rate and with a commit
// line at most commitStale old, which S comes from.
func TestCrashPremise(t *testing.T) {
	t0 := time.Unix(100, 0)
	var steady rangeguest.Handover
	for i := range 150 {
		steady.Add(t0.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	taken := t0.Add(15 * time.Second)
	cases := []struct {
		name   string
		taken  time.Time
		s      uint64
		at     time.Time
		reason string
	}{
		{"sound", taken, 7, taken.Add(-commitStale), ""},
		{"no whole window", t0.Add(9 * time.Second), 7, t0.Add(9 * time.Second), "rate not held"},
		{"window short", t0.Add(25 * time.Second), 7, t0.Add(25 * time.Second), "rate not held"},
		{"no commit", taken, 0, time.Time{}, "no commit line"},
		{"stale commit", taken, 7, taken.Add(-commitStale - time.Millisecond), "the last commit line came"},
	}
	for _, c := range cases {
		err := crashPremise(&steady, t0, c.taken, 10, c.s, c.at)
		if c.reason == "" && err != nil || c.reason != "" && (err == nil || !strings.Contains(err.Error(), c.reason)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.reason)
		}
	}
}

// Only the store's first recovery record counts, and only with its schema and last; others count.
func TestRecoveryReadsTheFirstRecord(t *testing.T) {
	var rc recovery
	rc.add(recoveredRecord(3, `{"schema_version":1,"kind":"stats"}`))
	rc.add(numberedExec(4))
	rc.add(recoveredRecord(9, `{"schema_version":1,"event":"recovered","shards":1,"first":1,"last":8}`))
	rc.add(recoveredRecord(20, `{"schema_version":1,"event":"recovered","shards":1,"first":9,"last":19}`))
	if rc != (recovery{count: 2, last: 8, seq: 9}) {
		t.Errorf("recovery %+v", rc)
	}
	for _, data := range []string{
		`{"schema_version":2,"event":"recovered","last":8}`, `{"schema_version":1,"event":"recovered"}`,
		`{"schema_version":1,"event":"recovered","last":"8"}`,
	} {
		var bad recovery
		bad.add(recoveredRecord(9, data))
		if bad != (recovery{count: 1, seq: 9}) {
			t.Errorf("%s: %+v, want last 0", data, bad)
		}
	}
}

// The facts of a read store: the numbers' run and count, and its recovery record.
func TestStoredRunReportsNumbersAndRecovery(t *testing.T) {
	var got []fact
	r := &report{send: func(f []fact) error { got = f; return nil }}
	read := func(before, after func(rawrecord.Record) error) error {
		for _, n := range []uint64{1, 2, 3, 5} {
			_ = before(numberedExec(n))
		}
		_ = before(recoveredRecord(6, `{"schema_version":1,"event":"recovered","shards":1,"first":1,"last":5}`))
		return after(numberedExec(6))
	}
	if err := storedRun(read, r); err != nil {
		t.Fatal(err)
	}
	want := "stored_prefix=3 stored_count=5 recovered=1 recovered_last=5 recovered_seq=6 seq_prefix=3"
	if s := factsString(got); s != want {
		t.Errorf("facts %s, want %s", s, want)
	}
	r = &report{send: func(f []fact) error { got = f; return nil }}
	_ = storedRun(func(_, _ func(rawrecord.Record) error) error { return rangeguest.ErrBarrierMissing }, r)
	if v, ok := factValueOf(got, rangevm.FactTrialError); !ok || !strings.Contains(v, "barrier missing") {
		t.Errorf("a missing barrier: %v", got)
	}
}

func factsString(facts []fact) string {
	var parts []string
	for _, f := range facts {
		parts = append(parts, f.name+"="+f.value)
	}
	return strings.Join(parts, " ")
}

// sleeper is a process to kill, reaped as soon as it ends, as systemd reaps the collector.
func sleeper(t *testing.T) (*exec.Cmd, chan *os.ProcessState) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan *os.ProcessState, 1)
	go func() { _ = cmd.Wait(); ended <- cmd.ProcessState }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd, ended
}

// killNow ends the process by SIGKILL and returns once it is gone; one already gone is an error.
func TestKillNow(t *testing.T) {
	cmd, ended := sleeper(t)
	p, err := os.FindProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := killNow(p); err != nil {
		t.Fatal(err)
	}
	if ws := (<-ended).Sys().(syscall.WaitStatus); !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Errorf("ended as %v", ws)
	}
	if err := killNow(p); err == nil {
		t.Error("a process already gone was killed")
	}
}

// crashFlow runs boot 1 of collector failure tr with a fake collector: a sleeping process as its main
// pid, a shell printing a commit line every 100 ms, and a store holding numbers 1..1000 with one
// recovery; the failure comes 10.3 s into a load of 100 execs a second.
func crashFlow(t *testing.T, name string) (console string, facts []fact, resetAsked bool) {
	t.Helper()
	if testing.Short() {
		t.Skip("a failure needs a whole 10 s window of load")
	}
	tr, ok := rangejob.Lookup(name)
	if !ok {
		t.Fatalf("no trial %s", name)
	}
	tr.Load.Rate = 100
	cmd, _ := sleeper(t)
	var killed atomic.Bool
	pathConsole := filepath.Join(t.TempDir(), "console")
	if err := os.WriteFile(pathConsole, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := crashEnv{
		fail: failEnv{
			console:   pathConsole,
			drain:     func(*os.File) error { return nil },
			reset:     func() error { resetAsked = true; return nil },
			failAfter: func(time.Duration) (time.Duration, error) { return 10300 * time.Millisecond, nil },
		},
		mainPID: func(context.Context) string {
			if killed.Load() {
				return "424242"
			}
			if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
				killed.Store(true)
				return ""
			}
			return strconv.Itoa(cmd.Process.Pid)
		},
		watch: func(ctx context.Context) (*commitWatch, error) {
			return watchCommits(exec.CommandContext(ctx, "/bin/sh", "-c",
				`i=0; while :; do i=$((i+1)); echo "{\"msg\":\"committed through\",\"seq\":$i}"; sleep 0.1; done`), time.Now)
		},
		emit: func(uint64) error { return nil },
		wait: func() error { return nil },
		wake: func(context.Context) error { return nil },
		read: func(before, _ func(rawrecord.Record) error) error {
			for n := uint64(1); n <= 1000; n++ {
				_ = before(numberedExec(n))
			}
			return before(recoveredRecord(1001, `{"schema_version":1,"event":"recovered","shards":1,"first":1,"last":1000}`))
		},
	}
	r := &report{send: func(f []fact) error { facts = f; return nil }}
	_ = crashLoadAndFail(t.Context(), tr, r, env)
	data, _ := os.ReadFile(pathConsole) //nolint:gosec // the test's temporary file
	return string(data), facts, resetAsked
}

var crashMarkRE = regexp.MustCompile(`\nbalistid-fail (\d+) (\d+)\n`)

// A kill of the collector writes the fail mark with H and S, kills it, writes the kill mark and reads
// the store once a collector of another pid commits.
func TestCrashKillsTheCollectorAndReadsTheStore(t *testing.T) {
	console, facts, resetAsked := crashFlow(t, "kill-collector-1")
	m := crashMarkRE.FindStringSubmatch(console)
	if m == nil || !strings.HasSuffix(console, killMark) || resetAsked {
		t.Fatalf("console %q, reset asked %v, facts %v", console, resetAsked, facts)
	}
	h, _ := strconv.ParseUint(m[1], 10, 64)
	s, _ := strconv.ParseUint(m[2], 10, 64)
	if h < 900 || h > 1000 || s == 0 {
		t.Errorf("H=%d S=%d: H counts the numbers execed 900 ms before the failure at 100/s, S a commit", h, s)
	}
	if got := factsString(facts); got != "stored_prefix=1000 stored_count=1000 recovered=1 recovered_last=1000 recovered_seq=1001 seq_prefix=1001" {
		t.Errorf("facts %s", got)
	}
}

// A reset writes the fail mark and asks for sysrq b; a reset that returns is the guest's error.
func TestCrashResetsAfterTheMark(t *testing.T) {
	console, facts, resetAsked := crashFlow(t, "reset-collector-1")
	if crashMarkRE.FindStringSubmatch(console) == nil || strings.Contains(console, killMark) || !resetAsked {
		t.Fatalf("console %q, reset asked %v", console, resetAsked)
	}
	if v, ok := factValueOf(facts, rangevm.FactTrialError); !ok || v != "sysrq b did not reset the guest" {
		t.Errorf("facts %v", facts)
	}
}

// A load that cannot hold the rate fails the run before any mark: no failure is measured.
func TestCrashWithoutTheRateMarksNothing(t *testing.T) {
	tr, _ := rangejob.Lookup("kill-collector-1")
	cmd, _ := sleeper(t)
	pathConsole := filepath.Join(t.TempDir(), "console")
	env := crashEnv{
		fail: failEnv{console: pathConsole, drain: func(*os.File) error { return nil }, reset: func() error { return nil },
			failAfter: func(time.Duration) (time.Duration, error) { return 1500 * time.Millisecond, nil }},
		mainPID: func(context.Context) string { return strconv.Itoa(cmd.Process.Pid) },
		watch: func(ctx context.Context) (*commitWatch, error) {
			return watchCommits(exec.CommandContext(ctx, "/bin/sh", "-c", `echo '{"msg":"committed through","seq":3}'; sleep 5`), time.Now)
		},
		emit: func(uint64) error { return nil },
		wait: func() error { return nil },
		wake: func(context.Context) error { return errors.New("no wake expected") },
		read: func(_, _ func(rawrecord.Record) error) error { return errors.New("no read expected") },
	}
	var facts []fact
	_ = crashLoadAndFail(t.Context(), tr, &report{send: func(f []fact) error { facts = f; return nil }}, env)
	if data, _ := os.ReadFile(pathConsole); len(data) != 0 { //nolint:gosec // the test's temporary file
		t.Errorf("console %q", data)
	}
	if v, ok := factValueOf(facts, rangevm.FactTrialError); !ok || !strings.Contains(v, "rate not held") {
		t.Errorf("facts %v", facts)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Error("the collector was killed without a failure")
	}
}
