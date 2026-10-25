package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// The time limit an encoded job disk carries is the unit's runtime limit, the context outlasts it
// by the stop and a fixed margin, and nothing else in the command depends on the job.
func TestJobCommandEnforcesTheDiskTimeLimit(t *testing.T) {
	var first []string
	for _, s := range []int{1, 7, rangejob.MaxTimeoutS} {
		image, err := rangejob.EncodeDisk([]byte("#!/bin/sh\n"), s)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "disk")
		if err := os.WriteFile(path, image, 0o600); err != nil {
			t.Fatal(err)
		}
		job, err := readJob(path)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		cmd, ctx, cancel := jobCommand(t.Context(), job)
		cancel()
		limits := slices.DeleteFunc(slices.Clone(cmd.Args), func(a string) bool { return !strings.HasPrefix(a, "RuntimeMaxSec=") })
		if want := []string{"RuntimeMaxSec=" + strconv.Itoa(s)}; !slices.Equal(limits, want) {
			t.Fatalf("limit %d s: runtime limits %q, want %q", s, limits, want)
		}
		deadline, ok := ctx.Deadline()
		want := start.Add(time.Duration(s+2*jobStopSec+20) * time.Second)
		if !ok || deadline.Before(want) || deadline.After(want.Add(time.Second)) {
			t.Fatalf("limit %d s: deadline %v after start, want %v", s, deadline.Sub(start), want.Sub(start))
		}
		if !slices.Contains(cmd.Args, "TimeoutStopSec="+strconv.Itoa(jobStopSec)) {
			t.Fatalf("limit %d s: the stop time is not jobStopSec: %q", s, cmd.Args)
		}
		if cmd.Path != "/usr/bin/systemd-run" || cmd.Args[len(cmd.Args)-1] != jobProgram {
			t.Fatalf("limit %d s: command %q", s, cmd.Args)
		}
		other := slices.DeleteFunc(slices.Clone(cmd.Args), func(a string) bool { return strings.HasPrefix(a, "RuntimeMaxSec=") })
		if first == nil {
			first = other
		} else if !slices.Equal(first, other) {
			t.Fatalf("limit %d s changes more than the limit: %q vs %q", s, other, first)
		}
	}
}

// An exec job's window is the Laurel lines received from t0 on, whole lines up to the cap, and "no" only
// when nothing may be missing: a loss record, a collector start or a Laurel reconnect in the window
// (T25), or a barrier that never came back, makes it "lost" (ADR 0022, point 3).
func TestJobWindowIsWholeOnlyWithoutALoss(t *testing.T) {
	laurel := func(at int64, data string) rawrecord.Record {
		return rawrecord.New(0, store.SensorProvider, 1, at, []byte(data))
	}
	health := func(at int64, kind string) rawrecord.Record {
		return rawrecord.New(0, store.HealthProvider, 0, at, []byte(`{"kind":"`+kind+`","schema_version":1}`))
	}
	read := func(err error, recs ...rawrecord.Record) func(func(rawrecord.Record) error) error {
		return func(fn func(rawrecord.Record) error) error {
			for _, r := range recs {
				if err := fn(r); err != nil {
					return err
				}
			}
			return err
		}
	}
	before, job := laurel(5, "before"), laurel(10, "job-a")
	for name, c := range map[string]struct {
		read          func(func(rawrecord.Record) error) error
		limit         int
		window, state string
	}{
		"whole":             {read(nil, before, job, health(11, "stats")), 1 << 20, "job-a\n", "no"},
		"over the cap":      {read(nil, job, laurel(12, "job-b")), 8, "job-a\n", "yes"},
		"collector started": {read(nil, job, health(11, "started")), 1 << 20, "job-a\n", "lost"},
		"laurel reconnect":  {read(nil, job, health(11, "connection")), 1 << 20, "job-a\n", "lost"},
		"counted loss":      {read(nil, job, rawrecord.New(0, store.LossProvider, 0, 11, []byte("{}"))), 1 << 20, "job-a\n", "lost"},
		"unreadable health": {read(nil, job, rawrecord.New(0, store.HealthProvider, 0, 11, []byte("x"))), 1 << 20, "job-a\n", "lost"},
		"start before t0":   {read(nil, health(9, "started"), job), 1 << 20, "job-a\n", "no"},
		"barrier missing":   {read(rangeguest.ErrBarrierMissing, job), 1 << 20, "job-a\n", "lost"},
		"store unreadable":  {read(errors.New("read store: x"), job), 1 << 20, "", "error"},
	} {
		w, state, _ := jobWindow(c.read, 10, c.limit)
		if string(w) != c.window || state != c.state {
			t.Errorf("%s: %q %s, want %q %s", name, w, state, c.window, c.state)
		}
	}
}

// A trial never runs with a job disk (ADR 0018, point 1); without either the guest runs the self-test.
func TestModeRefusesATrialWithAJobDisk(t *testing.T) {
	cases := []struct{ trial, dev, want string }{
		{"", "", modeSelftest},
		{"", "/dev/vdc", modeJob},
		{"rate-burst", "", modeTrial},
	}
	for _, c := range cases {
		if got, err := mode(c.trial, c.dev); err != nil || got != c.want {
			t.Errorf("mode(%q, %q) = %q, %v; want %q", c.trial, c.dev, got, err, c.want)
		}
	}
	if got, err := mode("rate-burst", "/dev/vdc"); err == nil {
		t.Errorf("a trial with a job disk ran as %q", got)
	}
}

// Each mark stands on a line of its own and the fail mark carries H then S (ADR 0019).
func TestMarksAreWholeLines(t *testing.T) {
	if got := failMark(41, 7); got != "\nbalistid-fail 41 7\n" {
		t.Errorf("failMark = %q", got)
	}
	if killMark != "\nbalistid-killed\n" {
		t.Errorf("killMark = %q", killMark)
	}
}

// Only a writer that SIGKILL ended counts as killed; one that exited by itself lost its records for
// another reason.
func TestKilledBySIGKILL(t *testing.T) {
	sleeper := exec.CommandContext(t.Context(), "/usr/bin/sleep", "30")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	_ = sleeper.Process.Kill()
	_ = sleeper.Wait()
	if err := killedBySIGKILL(sleeper.ProcessState); err != nil {
		t.Errorf("a killed sleeper: %v", err)
	}
	failed := exec.CommandContext(t.Context(), "/usr/bin/false")
	_ = failed.Run()
	if err := killedBySIGKILL(failed.ProcessState); err == nil {
		t.Error("a writer that exited 1 counted as killed")
	}
	term := exec.CommandContext(t.Context(), "/usr/bin/sleep", "30")
	if err := term.Start(); err != nil {
		t.Fatal(err)
	}
	_ = term.Process.Signal(syscall.SIGTERM)
	_ = term.Wait()
	if err := killedBySIGKILL(term.ProcessState); err == nil {
		t.Error("a writer ended by SIGTERM counted as killed")
	}
	if err := killedBySIGKILL(nil); err == nil {
		t.Error("a writer that has not ended counted as killed")
	}
}

// H describes the moment it was taken: a fail mark that leaves later than MarkWindow is refused.
func TestMarkInTime(t *testing.T) {
	t0 := time.Unix(100, 0)
	if err := markInTime(t0, t0.Add(100*time.Millisecond)); err != nil {
		t.Errorf("a mark 100 ms after H: %v", err)
	}
	if err := markInTime(t0, t0.Add(101*time.Millisecond)); err == nil {
		t.Error("a mark 101 ms after H was accepted")
	}
}
