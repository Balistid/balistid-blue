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

	"github.com/Balistid/balistid-blue/internal/collector"
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
// when nothing may be missing up to the end of the stopped run, its "stopping" record: anything but
// a known, safe health record of schema 1, inside the window or stored after the barrier (the collector
// writes a tick's health after its lines), makes it "lost" (T25, ADR 0022 point 3).
func TestJobWindowIsWholeOnlyWithoutALoss(t *testing.T) {
	t.Run("reason", func(t *testing.T) {
		_, _, why, _ := jobWindow(func(b, a func(rawrecord.Record) error) error {
			return errors.Join(b(rawrecord.New(0, store.HealthProvider, 0, 11, []byte(`{"schema_version":1,"kind":"something-new"}`))),
				a(rawrecord.New(0, store.HealthProvider, 0, 20, []byte(`{"schema_version":1,"kind":"stopping"}`))))
		}, 10, 1<<20)
		if !strings.Contains(why, `"something-new" in the window`) {
			t.Errorf("reason %q does not name the record", why)
		}
	})
	laurel := func(at int64, data string) rawrecord.Record {
		return rawrecord.New(0, store.SensorProvider, 1, at, []byte(data))
	}
	health := func(at int64, body string) rawrecord.Record {
		return rawrecord.New(0, store.HealthProvider, 0, at, []byte(body))
	}
	kind := func(at int64, k string) rawrecord.Record {
		return health(at, `{"schema_version":1,"kind":"`+k+`"}`)
	}
	stopping := kind(20, "stopping")
	type recs = []rawrecord.Record
	read := func(err error, before, after recs) storeRead {
		return func(b, a func(rawrecord.Record) error) error {
			for _, r := range before {
				if err := b(r); err != nil {
					return err
				}
			}
			for _, r := range after {
				if err := a(r); err != nil {
					return err
				}
			}
			return err
		}
	}
	job := laurel(10, "job-a")
	for name, c := range map[string]struct {
		read          storeRead
		limit         int
		window, state string
	}{
		"whole":                    {read(nil, recs{laurel(5, "before"), job, kind(11, "stats")}, recs{laurel(15, "x"), kind(16, "lag"), stopping}), 1 << 20, "job-a\n", "no"},
		"health OK":                {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"health","state":"OK"}`)}, recs{stopping}), 1 << 20, "job-a\n", "no"},
		"over the cap":             {read(nil, recs{job, laurel(12, "job-b")}, recs{stopping}), 8, "job-a\n", "yes"},
		"no end of the run":        {read(nil, recs{job}, nil), 1 << 20, "job-a\n", "lost"},
		"reconnect after barrier":  {read(nil, recs{job}, recs{kind(16, "connection"), stopping}), 1 << 20, "job-a\n", "lost"},
		"loss after barrier":       {read(nil, recs{job}, recs{kind(16, "lost"), stopping}), 1 << 20, "job-a\n", "lost"},
		"collector loss":           {read(nil, recs{job, kind(11, "lost")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"truncated record":         {read(nil, recs{job, laurel(12, strings.Repeat("x", rawrecord.MaxBytes+1))}, recs{stopping}), 8 << 20, "job-a\n", "yes"},
		"next run after the end":   {read(nil, recs{job}, recs{stopping, kind(21, "started"), kind(22, "connection")}), 1 << 20, "job-a\n", "no"},
		"collector started":        {read(nil, recs{job, kind(11, "started")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"laurel reconnect":         {read(nil, recs{job, kind(11, "connection")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"a stop inside the window": {read(nil, recs{job, kind(11, "stopping")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"store recovered":          {read(nil, recs{job, kind(11, "recovered")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"health not OK":            {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"health","state":"UNKNOWN canary-missed"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"unknown kind":             {read(nil, recs{job, kind(11, "something-new")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"unknown schema":           {read(nil, recs{job, health(11, `{"schema_version":2,"kind":"stats"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"no schema":                {read(nil, recs{job, health(11, `{"kind":"stats"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"schema as a string":       {read(nil, recs{job, health(11, `{"schema_version":"1","kind":"stats"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"unreadable health":        {read(nil, recs{job, health(11, "x")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"counted loss":             {read(nil, recs{job, rawrecord.New(0, store.LossProvider, 0, 11, []byte("{}"))}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"start before t0":          {read(nil, recs{kind(9, "started"), job}, recs{stopping}), 1 << 20, "job-a\n", "no"},
		"end of another schema":    {read(nil, recs{job}, recs{health(20, `{"schema_version":2,"kind":"stopping"}`)}), 1 << 20, "job-a\n", "lost"},
		"barrier missing":          {read(rangeguest.ErrBarrierMissing, recs{job}, nil), 1 << 20, "job-a\n", "lost"},
		"store unreadable":         {read(errors.New("read store: x"), recs{job}, nil), 1 << 20, "", "error"},
	} {
		w, state, why, _ := jobWindow(c.read, 10, c.limit)
		if string(w) != c.window || state != c.state || (why != "") != (state == "lost" || state == "error") {
			t.Errorf("%s: %q %s (%q), want %q %s", name, w, state, why, c.window, c.state)
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

// A rate trial counts the numbers in Laurel's lines; a loss record of the store, which drops only on a
// full scratch disk, marks the read so the run is INVALID instead of a MISS of the collector.
func TestRateRecordsCountNumbersAndNoteAStoreLoss(t *testing.T) {
	c, err := rangeguest.NewCounter(rangejob.LoadExec, 0)
	if err != nil {
		t.Fatal(err)
	}
	lost := false
	fn := rateRecords(c, &lost)
	line := `{"EXECVE":{"argc":2,"ARGV":["/usr/bin/true","balistid-n-1"]}}`
	for _, r := range []rawrecord.Record{
		rawrecord.New(0, store.SensorProvider, 1, 1, []byte(line)),
		rawrecord.New(0, store.HealthProvider, 0, 2, []byte(`{"schema_version":1,"kind":"stats"}`)),
	} {
		if err := fn(r); err != nil {
			t.Fatal(err)
		}
	}
	if stored, _, _, _ := c.Numbers().Count(1); stored != 1 || lost {
		t.Fatalf("stored %d, lost %v", stored, lost)
	}
	if err := fn(rawrecord.New(0, store.LossProvider, 0, 3, []byte("{}"))); err != nil || !lost {
		t.Fatalf("a store loss record: %v, lost %v", err, lost)
	}
	behind := false
	after := storeLoss(&behind)
	for _, r := range []rawrecord.Record{rawrecord.New(0, store.SensorProvider, 1, 4, []byte(line)), rawrecord.New(0, store.LossProvider, 0, 5, []byte("{}")),
		rawrecord.New(0, store.HealthProvider, 0, 6, []byte(`{"schema_version":1,"kind":"stats"}`))} {
		if err := after(r); err != nil {
			t.Fatal(err)
		}
	}
	if !behind {
		t.Error("a store loss record behind the barrier was not noted")
	}
}

func TestCollectorCanaryKeyIsTheCollectors(t *testing.T) {
	if collectorCanaryKey != collector.CanaryKey {
		t.Errorf("guest looks for %q, the collector's canary uses %q", collectorCanaryKey, collector.CanaryKey)
	}
}

// healthKind decodes JSON a collector wrote into the store; whatever the bytes, it returns.
func FuzzHealthKind(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"kind":"health","state":"OK"}`))
	f.Add([]byte(`{"schema_version":2,"kind":"stats"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = healthKind(data)
	})
}
