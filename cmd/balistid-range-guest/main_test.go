package main

import (
	"context"
	"errors"
	"fmt"
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
		}, 10, 1<<20, noKernelLoss)
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
	stats := func(at int64, lost, lostHealth int) rawrecord.Record {
		return health(at, fmt.Sprintf(`{"schema_version":1,"kind":"stats","lost":%d,"lost_health":%d}`, lost, lostHealth))
	}
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
		"whole":                      {read(nil, recs{laurel(5, "before"), job, stats(11, 0, 0)}, recs{laurel(15, "x"), kind(16, "lag"), stopping}), 1 << 20, "job-a\n", "no"},
		"stats counting a loss":      {read(nil, recs{job, stats(11, 3, 0)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"stats counting lost health": {read(nil, recs{job}, recs{stats(16, 0, 1), stopping}), 1 << 20, "job-a\n", "lost"},
		"stats without counts":       {read(nil, recs{job, kind(11, "stats")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"stats with null counts":     {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"stats","lost":null,"lost_health":null}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"health OK":                  {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"health","state":"OK"}`)}, recs{stopping}), 1 << 20, "job-a\n", "no"},
		"over the cap":               {read(nil, recs{job, laurel(12, "job-b")}, recs{stopping}), 8, "job-a\n", "yes"},
		"no end of the run":          {read(nil, recs{job}, nil), 1 << 20, "job-a\n", "lost"},
		"reconnect after barrier":    {read(nil, recs{job}, recs{kind(16, "connection"), stopping}), 1 << 20, "job-a\n", "lost"},
		"own stop after barrier":     {read(nil, recs{job}, recs{health(16, `{"schema_version":1,"kind":"connection","causes":{"eof":1}}`), stopping}), 1 << 20, "job-a\n", "no"},
		"eof inside the window":      {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"connection","causes":{"eof":2}}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"eof and reconnect":          {read(nil, recs{job}, recs{health(16, `{"schema_version":1,"kind":"connection","causes":{"eof":1,"reconnect":1}}`), stopping}), 1 << 20, "job-a\n", "lost"},
		"laurel restarted":           {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"connection","causes":{"laurel-restart":1}}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"read error":                 {read(nil, recs{job}, recs{health(16, `{"schema_version":1,"kind":"connection","causes":{"read-error":1}}`), stopping}), 1 << 20, "job-a\n", "lost"},
		"connection without causes":  {read(nil, recs{job}, recs{health(16, `{"schema_version":1,"kind":"connection"}`), stopping}), 1 << 20, "job-a\n", "lost"},
		"zero eof":                   {read(nil, recs{job}, recs{health(16, `{"schema_version":1,"kind":"connection","causes":{"eof":0}}`), stopping}), 1 << 20, "job-a\n", "lost"},
		"loss after barrier":         {read(nil, recs{job}, recs{kind(16, "lost"), stopping}), 1 << 20, "job-a\n", "lost"},
		"collector loss":             {read(nil, recs{job, kind(11, "lost")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"truncated record":           {read(nil, recs{job, laurel(12, strings.Repeat("x", rawrecord.MaxBytes+1))}, recs{stopping}), 8 << 20, "job-a\n", "yes"},
		"next run after the end":     {read(nil, recs{job}, recs{stopping, kind(21, "started"), kind(22, "connection")}), 1 << 20, "job-a\n", "no"},
		"collector started":          {read(nil, recs{job, kind(11, "started")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"laurel reconnect":           {read(nil, recs{job, kind(11, "connection")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"a stop inside the window":   {read(nil, recs{job, kind(11, "stopping")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"store recovered":            {read(nil, recs{job, kind(11, "recovered")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"health not OK":              {read(nil, recs{job, health(11, `{"schema_version":1,"kind":"health","state":"UNKNOWN canary-missed"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"unknown kind":               {read(nil, recs{job, kind(11, "something-new")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"unknown schema":             {read(nil, recs{job, health(11, `{"schema_version":2,"kind":"stats"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"no schema":                  {read(nil, recs{job, health(11, `{"kind":"stats"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"schema as a string":         {read(nil, recs{job, health(11, `{"schema_version":"1","kind":"stats"}`)}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"unreadable health":          {read(nil, recs{job, health(11, "x")}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"counted loss":               {read(nil, recs{job, rawrecord.New(0, store.LossProvider, 0, 11, []byte("{}"))}, recs{stopping}), 1 << 20, "job-a\n", "lost"},
		"start before t0":            {read(nil, recs{kind(9, "started"), job}, recs{stopping}), 1 << 20, "job-a\n", "no"},
		"end of another schema":      {read(nil, recs{job}, recs{health(20, `{"schema_version":2,"kind":"stopping"}`)}), 1 << 20, "job-a\n", "lost"},
		"barrier missing":            {read(rangeguest.ErrBarrierMissing, recs{job}, nil), 1 << 20, "job-a\n", "lost"},
		"store unreadable":           {read(errors.New("read store: x"), recs{job}, nil), 1 << 20, "", "error"},
	} {
		w, state, why, _ := jobWindow(c.read, 10, c.limit, noKernelLoss)
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

// decodeHealth decodes JSON a collector wrote into the store; whatever the bytes, it returns.
func FuzzHealthKind(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"kind":"health","state":"OK"}`))
	f.Add([]byte(`{"schema_version":2,"kind":"stats"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeHealth(data)
	})
}

// A lost window's reason goes to the console with the rule, quoted; a whole window prints nothing.
func TestReportWindow(t *testing.T) {
	var b strings.Builder
	reportWindow(&b, "no", "")
	reportWindow(&b, "lost", "balistid-health record \"x\"\nfake line")
	want := "balistid-range-guest: job window lost (rule " + jobWindowRule + "): \"balistid-health record \\\"x\\\"\\nfake line\"\n"
	if b.String() != want {
		t.Errorf("console %q, want %q", b.String(), want)
	}
}

// A journal line too long to scan ends the follower at once: the process is killed and the channel
// closes, so a read fails instead of waiting out its limit.
func TestFollowCommitsEndsOnAnOverlongLine(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "head -c 70000 /dev/zero | tr '\\0' x; sleep 60")
	commits, err := followCommits(cmd)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-commits:
		if ok {
			t.Fatal("a commit from a line that is no commit line")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the follower still runs after an overlong line")
	}
}

// Commit lines become seqs in order; other lines send nothing.
func TestFollowCommitsSendsCommitLines(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `printf '%s\n' '{"msg":"lag"}' '{"msg":"committed through","seq":7}'`)
	commits, err := followCommits(cmd)
	if err != nil {
		t.Fatal(err)
	}
	var got []uint64
	for n := range commits {
		got = append(got, n)
	}
	if len(got) != 1 || got[0] != 7 {
		t.Errorf("commits %v, want [7]", got)
	}
}

// A rate trial's read fails with errStoreLost when the store dropped records before or behind the
// barrier, so the run is INVALID; without a loss it counts the numbers and a read error stays its own.
func TestRateReadFailsOnAStoreLoss(t *testing.T) {
	line := rawrecord.New(0, store.SensorProvider, 1, 1, []byte(`{"EXECVE":{"argc":2,"ARGV":["/usr/bin/true","balistid-n-1"]}}`))
	loss := rawrecord.New(0, store.LossProvider, 0, 2, []byte("{}"))
	feed := func(before, after []rawrecord.Record, err error) storeRead {
		return func(b, a func(rawrecord.Record) error) error {
			for _, r := range before {
				_ = b(r)
			}
			for _, r := range after {
				_ = a(r)
			}
			return err
		}
	}
	other := errors.New("read store: x")
	for name, c := range map[string]struct {
		read storeRead
		want error
	}{
		"whole":       {feed([]rawrecord.Record{line}, nil, nil), nil},
		"loss before": {feed([]rawrecord.Record{line, loss}, nil, nil), errStoreLost},
		"loss behind": {feed([]rawrecord.Record{line}, []rawrecord.Record{loss}, nil), errStoreLost},
		"read error":  {feed([]rawrecord.Record{line, loss}, nil, other), other},
	} {
		counter, err := rangeguest.NewCounter(rangejob.LoadExec, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := rateRead(counter, c.read); !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if stored, _, _, _ := counter.Numbers().Count(1); stored != 1 {
			t.Errorf("%s: %d numbers stored", name, stored)
		}
	}
}

// A health record with a null or missing count, or any other bytes, never panics the window check.
func FuzzKeepsWindow(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"kind":"stats","lost":null,"lost_health":null}`), true)
	f.Add([]byte(`{"schema_version":1,"kind":"connection","causes":null}`), true)
	f.Fuzz(func(t *testing.T, data []byte, afterBarrier bool) {
		_ = keepsWindow(rawrecord.New(0, store.HealthProvider, 0, 1, data), afterBarrier)
	})
}

// The reason names a loss record by its provider, not as an unreadable health record.
func TestDescribeNamesTheProvider(t *testing.T) {
	if got := describe(rawrecord.New(0, store.LossProvider, 0, 1, []byte("{}")), "in the window"); got != store.LossProvider+" record in the window" {
		t.Errorf("describe = %q", got)
	}
}

// A job window is whole only while the kernel's lost count stays and auditd's plugin queue never
// overflows: both drop records before Laurel, so the store cannot show them missing.
func TestKernelLossBreaksTheWindow(t *testing.T) {
	for name, c := range map[string]struct {
		lostBefore, lostAfter, overflowBefore, overflowAfter string
		lost                                                 bool
	}{
		"nothing lost":       {"0", "0", "no", "no", false},
		"lost earlier":       {"3", "3", "no", "no", false},
		"kernel lost some":   {"0", "5", "no", "no", true},
		"count went down":    {"5", "0", "no", "no", true},
		"count unknown":      {"", "0", "no", "no", true},
		"count not a number": {"0", "x", "no", "no", true},
		"overflow during":    {"0", "0", "no", "yes", true},
		"overflow before":    {"0", "0", "yes", "yes", true},
		"overflow unknown":   {"0", "0", "no", "missing", true},
	} {
		if got := kernelLoss(c.lostBefore, c.lostAfter, c.overflowBefore, c.overflowAfter); (got != "") != c.lost {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func noKernelLoss() string { return "" }

// A window the store shows whole is still lost when the kernel or auditd dropped records meanwhile.
func TestJobWindowCountsTheKernelsLoss(t *testing.T) {
	read := func(b, a func(rawrecord.Record) error) error {
		return errors.Join(b(rawrecord.New(0, store.SensorProvider, 1, 11, []byte("job-a"))),
			a(rawrecord.New(0, store.HealthProvider, 0, 20, []byte(`{"schema_version":1,"kind":"stopping"}`))))
	}
	if _, state, _, _ := jobWindow(read, 10, 1<<20, noKernelLoss); state != "no" {
		t.Fatalf("without a kernel loss: %s", state)
	}
	_, state, why, _ := jobWindow(read, 10, 1<<20, func() string { return "the kernel lost 5 records during the job" })
	if state != "lost" || !strings.Contains(why, "kernel lost 5") {
		t.Fatalf("with a kernel loss: %s %q", state, why)
	}
}

// laurelHold rests on Laurel 0.8.2's coalescing timeouts: a Laurel upgrade must re-check it.
func TestLaurelHoldMatchesThePackagedLaurel(t *testing.T) {
	pkg, err := os.ReadFile("../../packaging/laurel/PKGBUILD")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pkg), "\npkgver=0.8.2\n") {
		t.Fatal("Laurel is no longer 0.8.2: check its EXPIRE_INFLIGHT_TIMEOUT and EXPIRE_PERIOD against laurelHold")
	}
	if laurelHold < 5*time.Second+time.Second {
		t.Errorf("laurelHold %s is under Laurel's 5 s hold and 1 s expiry period", laurelHold)
	}
}

// The job's evidence waits out Laurel's hold before the store read, and the loss check compares the
// sample from before the job with one taken after the read.
func TestJobEvidenceWaitsThenComparesSamples(t *testing.T) {
	var steps []string
	sleep := func(d time.Duration) { steps = append(steps, "sleep "+d.String()) }
	read := func(b, a func(rawrecord.Record) error) error {
		steps = append(steps, "read")
		return errors.Join(b(rawrecord.New(0, store.SensorProvider, 1, 11, []byte("job-a"))),
			a(rawrecord.New(0, store.HealthProvider, 0, 20, []byte(`{"schema_version":1,"kind":"stopping"}`))))
	}
	for name, c := range map[string]struct {
		after lossSample
		state string
	}{
		"no loss":        {lossSample{"2", "no"}, "no"},
		"kernel lost":    {lossSample{"4", "no"}, "lost"},
		"queue overflow": {lossSample{"2", "yes"}, "lost"},
	} {
		steps = nil
		sample := func() lossSample { steps = append(steps, "sample"); return c.after }
		_, state, why, _ := jobEvidence(sleep, read, 10, 1<<20, lossSample{"2", "no"}, sample)
		if state != c.state || strings.Join(steps, ",") != "sleep "+laurelHold.String()+",read,sample" {
			t.Errorf("%s: %s (%q) after %v", name, state, why, steps)
		}
	}
	if got := kernelLoss("5", "0", "no", "no"); !strings.Contains(got, "went back from 5 to 0") {
		t.Errorf("a counter going back reads %q", got)
	}
}

// The overflow line may reach the journal after the flood: a later read before the context ends finds it,
// a line that never comes gives "no", and an ended context reads nothing.
func TestJournalNamesALateOverflowLine(t *testing.T) {
	reads := 0
	late := func(after int) func(context.Context) string {
		return func(context.Context) string {
			reads++
			if reads > after {
				return "queue to plugins is full - dropping event"
			}
			return "started"
		}
	}
	ctx := context.Background()
	if got := journalNames(ctx, late(2), time.Millisecond); got != "yes" {
		t.Errorf("a line on the third read: %q, want yes", got)
	}
	short, cancelShort := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelShort()
	reads = 0
	if got := journalNames(short, late(1<<30), time.Millisecond); got != "no" {
		t.Errorf("no line before the context ends: %q, want no", got)
	}
	ended, cancel := context.WithCancel(ctx)
	cancel()
	reads = 0
	if got := journalNames(ended, late(0), time.Millisecond); got != "no" || reads != 0 {
		t.Errorf("an ended context: %q after %d reads, want no after 0", got, reads)
	}
}

// Only root's auditd after the cursor taken before the flood counts; no cursor, no read.
func TestOverflowJournalReadsOnlyAuditdAfterTheCursor(t *testing.T) {
	if got := journalCursor("-- cursor: s=ab;i=1f\n"); got != "s=ab;i=1f" {
		t.Errorf("cursor %q", got)
	}
	for _, out := range []string{"", "-- cursor: \n", "cursor: s=ab\n"} {
		if got := journalCursor(out); got != "" {
			t.Errorf("cursor of %q: %q, want none", out, got)
		}
	}
	args := overflowJournalArgs("s=ab;i=1f")
	for _, want := range []string{"--after-cursor=s=ab;i=1f", "_SYSTEMD_UNIT=auditd.service", "_EXE=/usr/bin/auditd", "_UID=0"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %q lack %q", args, want)
		}
	}
	for _, a := range args {
		// Fields without a leading underscore are the sender's to choose (systemd.journal-fields).
		if a == "-b" || strings.HasPrefix(a, "SYSLOG_") || strings.HasPrefix(a, "MESSAGE") {
			t.Errorf("args %q match on %q", args, a)
		}
	}
}
