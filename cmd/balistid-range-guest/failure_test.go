package main

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// TestHelperWriter is the measured writer when the test binary runs itself as one.
func TestHelperWriter(t *testing.T) {
	args := os.Getenv("BALISTID_TEST_WRITER")
	if args == "" {
		t.Skip("only as the writer process of the failure flow tests")
	}
	if err := writerMain(strings.Split(args, "|")); err != nil {
		os.Exit(3)
	}
	os.Exit(0)
}

// flow runs loadAndFail of the named trial with a file for the console, a fake reset and drain, the
// real writer as a child process and the failure 1.5 s into the load. It returns the facts sent, the
// console's text, the numbers file's size when the reset or the kill came and 300 ms later, and
// whether a reset was asked for.
type flowResult struct {
	facts        []fact
	console      string
	sizeAtFail   int64
	sizeLater    int64
	resetAsked   bool
	numbersBytes []byte
}

const freezeWaitInTests = 10 * time.Second

func flow(t *testing.T, name string, drain func(*os.File, *exec.Cmd) error) flowResult {
	t.Helper()
	return flowWaiting(t, name, drain, freezeWaitInTests)
}

func flowWaiting(t *testing.T, name string, drain func(*os.File, *exec.Cmd) error, freezeWait time.Duration) flowResult {
	t.Helper()
	tr, ok := rangejob.Lookup(name)
	if !ok {
		t.Fatal(name)
	}
	dir := t.TempDir()
	numbers, console := filepath.Join(dir, "numbers"), filepath.Join(dir, "console")
	if err := os.WriteFile(console, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var res flowResult
	var mu sync.Mutex
	var cmd *exec.Cmd
	size := func() int64 {
		st, err := os.Stat(numbers)
		if err != nil {
			return -1
		}
		return st.Size()
	}
	env := failEnv{
		console: console,
		drain: func(f *os.File) error {
			mu.Lock()
			defer mu.Unlock()
			return drain(f, cmd)
		},
		reset: func() error {
			res.resetAsked = true
			res.sizeAtFail = size()
			time.Sleep(300 * time.Millisecond)
			res.sizeLater = size()
			return nil
		},
		writer: func(ctx context.Context, args ...string) *exec.Cmd {
			mu.Lock()
			defer mu.Unlock()
			cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperWriter$") //nolint:gosec // this test binary
			cmd.Env = append(os.Environ(), "BALISTID_TEST_WRITER="+strings.Join(args, "|"))
			return cmd
		},
		numbers:   numbers,
		failAfter: func(time.Duration) (time.Duration, error) { return 1500 * time.Millisecond, nil },
		// The writer syncs every 250 ms; on a loaded CI disk one fsync can outlast the guest's 1 s.
		freezeWait: freezeWait,
	}
	r := &report{send: func(f []fact) error { res.facts = f; return nil }}
	_ = loadAndFail(t.Context(), tr, r, env)
	data, _ := os.ReadFile(console) //nolint:gosec // the test's temporary file
	res.console = string(data)
	res.numbersBytes, _ = os.ReadFile(numbers) //nolint:gosec // the test's temporary file
	if !res.resetAsked {
		res.sizeAtFail = size()
	}
	return res
}

var failMarkRE = regexp.MustCompile(`\nbalistid-fail (\d+) (\d+)\n`)

func factValueOf(facts []fact, name string) (string, bool) {
	for _, f := range facts {
		if f.name == name {
			return f.value, true
		}
	}
	return "", false
}

// A reset meets a frozen writer: from the fail mark on nothing more is written, and S in the mark
// is what the file holds through an fsync, at least up to H.
func TestResetMeetsAFrozenWriter(t *testing.T) {
	res := flow(t, "reset-control-sync250", func(*os.File, *exec.Cmd) error { return nil })
	m := failMarkRE.FindStringSubmatch(res.console)
	if m == nil || !res.resetAsked {
		t.Fatalf("console %q, reset asked %v, facts %v", res.console, res.resetAsked, res.facts)
	}
	h, _ := strconv.ParseUint(m[1], 10, 64)
	s, _ := strconv.ParseUint(m[2], 10, 64)
	if res.sizeLater != res.sizeAtFail {
		t.Errorf("the writer wrote on after the fail mark: %d then %d bytes", res.sizeAtFail, res.sizeLater)
	}
	written := uint64(len(res.numbersBytes) / 8)
	if s == 0 || s < h || s > written {
		t.Errorf("H=%d S=%d with %d records written: S must be synced, at least H, at most written", h, s, written)
	}
	for i := uint64(0); i < s; i++ {
		if binary.LittleEndian.Uint64(res.numbersBytes[i*8:]) != i+1 {
			t.Fatalf("record %d is not %d", i, i+1)
		}
	}
	if v, ok := factValueOf(res.facts, rangevm.FactTrialError); !ok || v != "sysrq b did not reset the guest" {
		t.Errorf("after a reset that returned: %v", res.facts)
	}
}

// A writer that does not answer Freeze within the environment's bound is a trial error, never a failure.
func TestWriterNotFrozenInTimeIsATrialError(t *testing.T) {
	res := flowWaiting(t, "reset-control-sync250", func(*os.File, *exec.Cmd) error { return nil }, time.Nanosecond)
	if res.resetAsked || failMarkRE.MatchString(res.console) {
		t.Errorf("reset asked %v, console %q: no mark and no reset without a frozen writer", res.resetAsked, res.console)
	}
	if v, ok := factValueOf(res.facts, rangevm.FactTrialError); !ok || v != "the writer did not freeze" {
		t.Errorf("facts %v", res.facts)
	}
}

// A writer that ends while the fail mark drains is never certified as reset.
func TestWriterEndingDuringTheMarkIsNoReset(t *testing.T) {
	res := flow(t, "reset-control-sync250", func(_ *os.File, cmd *exec.Cmd) error {
		_ = cmd.Process.Kill()
		time.Sleep(50 * time.Millisecond)
		return nil
	})
	if res.resetAsked {
		t.Error("reset asked for after the writer ended")
	}
	if v, ok := factValueOf(res.facts, rangevm.FactTrialError); !ok || v != "the writer ended before the failure" {
		t.Errorf("facts %v", res.facts)
	}
}

// A drain that fails is a trial error, not a failure.
func TestDrainErrorIsNoFailure(t *testing.T) {
	res := flow(t, "reset-control-sync250", func(*os.File, *exec.Cmd) error { return errors.New("EIO") })
	if res.resetAsked || failMarkRE.FindStringSubmatch(res.console) == nil {
		t.Errorf("reset asked %v, console %q: the mark must be written, and no reset after its drain failed", res.resetAsked, res.console)
	}
	if _, ok := factValueOf(res.facts, rangevm.FactTrialError); !ok {
		t.Errorf("facts %v", res.facts)
	}
}

// A kill trial kills the frozen writer, writes the kill mark and reports what the file holds; the
// records it held in memory are lost.
func TestKillTrialKillsTheWriter(t *testing.T) {
	res := flow(t, "kill-control-buffer2s", func(*os.File, *exec.Cmd) error { return nil })
	if failMarkRE.FindStringSubmatch(res.console) == nil || !regexp.MustCompile(`\nbalistid-killed\n`).MatchString(res.console) {
		t.Fatalf("console %q", res.console)
	}
	if _, ok := factValueOf(res.facts, rangevm.FactTrialError); ok {
		t.Fatalf("facts %v", res.facts)
	}
	if v, ok := factValueOf(res.facts, rangevm.FactStoredPrefix); !ok || v == "" {
		t.Errorf("facts %v", res.facts)
	}
}
