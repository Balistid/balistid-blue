package rangeguest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// execLine is a Laurel line of an exec as deploy/laurel/config.toml writes it: the number appears in
// EXECVE.ARGV and again in PROCTITLE, and SYSCALL holds its registers as ARGV too.
func execLine(arg string) string {
	return fmt.Sprintf(`{"ID":"1.000:1","SYSCALL":{"arch":"0xc000003e","ARCH":"x86_64","syscall":59,"SYSCALL":"execve",`+
		`"success":"yes","exit":0,"ARGV":["0x1","0x2","0x3","0x0"],"key":"balistid-exec"},`+
		`"EXECVE":{"argc":2,"ARGV":["/usr/bin/true",%q]},"PROCTITLE":{"ARGV":["/usr/bin/true",%q]}}`, arg, arg)
}

func ptraceLine(a0, a1, a2 string) string {
	return fmt.Sprintf(`{"ID":"1.000:2","SYSCALL":{"syscall":101,"SYSCALL":"ptrace","success":"no","exit":-3,`+
		`"ARGV":[%q,%q,%q,"0x0"],"key":"balistid-inject"},"PROCTITLE":{"ARGV":["guest"]}}`, a0, a1, a2)
}

func TestNumbersCountEveryKindOfLoss(t *testing.T) {
	var n Numbers
	for _, seq := range []uint64{1, 2, 2, 4, 6, 0, MaxNumber + 1} {
		n.Add(seq)
	}
	// 1..5 generated: 3 and 5 missing, 2 repeated, 6 beyond the set, 0 and MaxNumber+1 outside it.
	stored, missing, duplicate, outside := n.Count(5)
	if stored != 3 || missing != 2 || duplicate != 1 || outside != 3 {
		t.Errorf("Count(5) = %d stored, %d missing, %d duplicate, %d outside; want 3, 2, 1, 3", stored, missing, duplicate, outside)
	}
	var all Numbers
	for seq := uint64(1); seq <= 200; seq++ {
		all.Add(seq)
	}
	if s, m, d, o := all.Count(200); s != 200 || m != 0 || d != 0 || o != 0 {
		t.Errorf("complete set counted %d, %d, %d, %d", s, m, d, o)
	}
}

func TestRecordReadsOnlyTheGeneratorsNumbers(t *testing.T) {
	cases := []struct {
		kind, line string
		want       []uint64
		outside    uint64
	}{
		{rangejob.LoadExec, execLine("balistid-n-7"), []uint64{7}, 0},
		{rangejob.LoadExec, execLine("balistid-n-07"), nil, 1},
		{rangejob.LoadExec, execLine("balistid-n-"), nil, 1},
		{rangejob.LoadExec, `{"PROCTITLE":{"ARGV":["balistid-n-9"]}}`, nil, 1},
		{rangejob.LoadExec, execLine("other"), nil, 0},
		{rangejob.LoadPtrace, ptraceLine("0x2", "0x7fffffff", "0x7b"), []uint64{123}, 0},
		{rangejob.LoadPtrace, ptraceLine("0x2", "0x7fffffff", "0x07b"), nil, 1},
		{rangejob.LoadPtrace, ptraceLine("0x2", "0x7fffffff", "0x7B"), nil, 1},
		{rangejob.LoadPtrace, ptraceLine("0x10", "0x7fffffff", "0x7b"), nil, 0},
		{rangejob.LoadPtrace, ptraceLine("0x2", "0x1", "0x7b"), nil, 0},
		{rangejob.LoadPtrace, strings.Replace(ptraceLine("0x2", "0x7fffffff", "0x7b"), `"syscall":101`, `"syscall":310`, 1), nil, 0},
		{rangejob.LoadPtrace, execLine("balistid-n-7"), nil, 0},
	}
	for _, c := range cases {
		fl := NewFollower("", c.kind, 0)
		fl.record([]byte(c.line))
		var want Numbers
		for _, n := range c.want {
			want.Add(n)
		}
		gs, _, _, _ := fl.nums.Count(MaxNumber)
		ws, _, _, _ := want.Count(MaxNumber)
		if gs != ws || fl.nums.outside != c.outside || fl.nums.duplicate != 0 {
			t.Errorf("%s %s: %d stored, %d outside; want %d, %d", c.kind, c.line, gs, fl.nums.outside, ws, c.outside)
		}
		for _, n := range c.want {
			if _, missing, _, _ := fl.nums.Count(n); missing != n-1 {
				t.Errorf("%s: number %d not stored", c.line, n)
			}
		}
	}
}

func TestRecordDropsTheControlsNumberOnce(t *testing.T) {
	fl := NewFollower("", rangejob.LoadExec, 2)
	for _, a := range []string{"balistid-n-1", "balistid-n-2", "balistid-n-2", "balistid-n-3"} {
		fl.record([]byte(execLine(a)))
	}
	if s, m, d, _ := fl.nums.Count(3); s != 2 || m != 1 || d != 1 {
		t.Errorf("drop counted %d stored, %d missing, %d duplicate; want 2 missing the dropped one and its repeat a duplicate", s, m, d)
	}
}

// laurel imitates Laurel's writer: whole lines, rotation by renaming path to path.1 and onwards
// past size, and the new file created on the next write.
type laurel struct {
	t    *testing.T
	path string
	gens int
}

func (l *laurel) write(lines ...string) {
	l.t.Helper()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // test file
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			l.t.Fatal(err)
		}
	}
}

func (l *laurel) rotate() {
	l.t.Helper()
	for k := l.gens - 1; k >= 0; k-- {
		if err := os.Rename(rotated(l.path, k), rotated(l.path, k+1)); err != nil && !os.IsNotExist(err) {
			l.t.Fatal(err)
		}
	}
}

func newLaurel(t *testing.T) *laurel {
	l := &laurel{t: t, path: filepath.Join(t.TempDir(), "audit.log"), gens: 10}
	l.write(execLine("balistid-n-999")) // before Start: not part of the run
	return l
}

func readAll(t *testing.T, tail *logTail) (lines []string, err error) {
	t.Helper()
	for {
		line, err := tail.line()
		if err != nil || line == nil {
			return lines, err
		}
		lines = append(lines, string(line))
	}
}

func TestTailFollowsRotationWithoutLoss(t *testing.T) {
	l := newLaurel(t)
	tail := logTail{path: l.path}
	if err := tail.openAtEnd(); err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	l.write("a", "b")
	l.rotate()
	if got, err := readAll(t, &tail); err != nil || strings.Join(got, ",") != "a,b" {
		t.Fatalf("before the new file exists: %q, %v", got, err)
	}
	l.write("c")
	l.rotate()
	l.write("d")
	l.rotate()
	l.write("e")
	if got, err := readAll(t, &tail); err != nil || strings.Join(got, ",") != "c,d,e" {
		t.Fatalf("two rotations behind: %q, %v", got, err)
	}
}

func TestTailRefusesAGap(t *testing.T) {
	behind := func(l *laurel, tail *logTail) {
		l.write("a")
		for range l.gens + 1 {
			l.rotate()
			l.write("x")
		}
	}
	truncated := func(l *laurel, tail *logTail) {
		l.write("a")
		if _, err := readAll(t, tail); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(l.path, 0); err != nil {
			t.Fatal(err)
		}
	}
	cutLine := func(l *laurel, tail *logTail) {
		l.write("a")
		f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("half")
		_ = f.Close()
		l.rotate()
	}
	for name, setup := range map[string]func(*laurel, *logTail){"behind": behind, "truncated": truncated, "cut line": cutLine} {
		l := newLaurel(t)
		tail := logTail{path: l.path}
		if err := tail.openAtEnd(); err != nil {
			t.Fatal(err)
		}
		setup(l, &tail)
		if _, err := readAll(t, &tail); err == nil {
			t.Errorf("%s: read without an error", name)
		}
		tail.close()
	}
}

func TestFollowerFinishesAtTheBarrier(t *testing.T) {
	l := newLaurel(t)
	fl := NewFollower(l.path, rangejob.LoadExec, 0)
	if err := fl.Start(); err != nil {
		t.Fatal(err)
	}
	l.write(execLine("balistid-n-1"), execLine("balistid-n-2"))
	l.rotate()
	l.write(execLine("balistid-n-3"))
	nums, err := fl.Finish(t.Context(), "balistid-canary-x", func(context.Context) error {
		l.write(execLine("balistid-canary-x"), execLine("balistid-n-4"))
		return nil
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s, m, d, o := nums.Count(3); s != 3 || m != 0 || d != 0 || o != 0 {
		t.Errorf("counted %d, %d, %d, %d; want 3 stored and nothing else (4 came after the barrier)", s, m, d, o)
	}

	l = newLaurel(t)
	fl = NewFollower(l.path, rangejob.LoadExec, 0)
	if err := fl.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := fl.Finish(t.Context(), "balistid-canary-y", func(context.Context) error { return nil }, 50*time.Millisecond); err == nil {
		t.Error("finished without the barrier")
	}

	// The mark runs under the same deadline: one that hangs ends with it.
	l = newLaurel(t)
	fl = NewFollower(l.path, rangejob.LoadExec, 0)
	if err := fl.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = fl.Finish(t.Context(), "balistid-canary-z", func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, 50*time.Millisecond)
	if err == nil || time.Since(start) > time.Second {
		t.Errorf("a hanging mark: %v after %s", err, time.Since(start))
	}
}

// A log that does not end with a whole line at Start ends with part of an event from before the run:
// its rest is not the run's, so it is neither a number nor outside.
func TestTailSkipsTheLineItStartsInside(t *testing.T) {
	l := newLaurel(t)
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"EXECVE":{"argc":2,"ARGV":["/usr/bin/true",`)
	fl := NewFollower(l.path, rangejob.LoadExec, 0)
	if err := fl.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`"balistid-n-5"]}}` + "\n")
	_ = f.Close()
	l.write(execLine("balistid-n-1"))
	nums, err := fl.Finish(t.Context(), "balistid-canary-p", func(context.Context) error {
		l.write(execLine("balistid-canary-p"))
		return nil
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s, m, d, o := nums.Count(1); s != 1 || m != 0 || d != 0 || o != 0 {
		t.Errorf("counted %d, %d, %d, %d; want only number 1", s, m, d, o)
	}
}

// Laurel renames one file at a time: a reader looking between two renames finds no successor yet
// and waits for it instead of failing the run.
func TestTailWaitsBetweenRenames(t *testing.T) {
	l := newLaurel(t)
	tail := logTail{path: l.path}
	if err := tail.openAtEnd(); err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	l.write("a")
	l.rotate()
	l.write("b")
	// Half of the next rotation: audit.log.1 moved to .2, audit.log not yet to .1.
	if err := os.Rename(rotated(l.path, 1), rotated(l.path, 2)); err != nil {
		t.Fatal(err)
	}
	if got, err := readAll(t, &tail); err != nil || strings.Join(got, ",") != "a" {
		t.Fatalf("between renames: %q, %v", got, err)
	}
	if err := os.Rename(l.path, rotated(l.path, 1)); err != nil {
		t.Fatal(err)
	}
	if got, err := readAll(t, &tail); err != nil || strings.Join(got, ",") != "b" {
		t.Fatalf("after the rename: %q, %v", got, err)
	}
}

func TestTailRefusesAnOverlongLine(t *testing.T) {
	l := newLaurel(t)
	tail := logTail{path: l.path}
	if err := tail.openAtEnd(); err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	l.write(strings.Repeat("x", maxLine+1))
	if _, err := readAll(t, &tail); err == nil {
		t.Error("a line over maxLine was read")
	}
}

// Only an exec whose argument is exactly the barrier ends the run.
func TestBarrierIsAnExactArgument(t *testing.T) {
	fl := NewFollower("", rangejob.LoadExec, 0)
	fl.barrier = "balistid-canary-x"
	for _, line := range []string{execLine("balistid-canary-xy"), `{"PROCTITLE":{"ARGV":["balistid-canary-x"]}}`} {
		if fl.record([]byte(line)); fl.seen {
			t.Fatalf("barrier seen in %s", line)
		}
	}
	if fl.record([]byte(execLine("balistid-canary-x"))); !fl.seen {
		t.Error("barrier not seen")
	}
}

func TestNumbersKeepUpToMaxNumber(t *testing.T) {
	var n Numbers
	n.Add(MaxNumber)
	n.Add(MaxNumber + 1)
	if s, m, d, o := n.Count(MaxNumber); s != 1 || m != MaxNumber-1 || d != 0 || o != 1 {
		t.Errorf("Count(MaxNumber) = %d, %d, %d, %d; want MaxNumber stored and the next one outside", s, m, d, o)
	}
}

// Only the generator's rule key counts: a PEEKDATA of NoPID under another key is not its record.
func TestPtraceNeedsTheRuleKey(t *testing.T) {
	fl := NewFollower("", rangejob.LoadPtrace, 0)
	fl.record([]byte(strings.Replace(ptraceLine("0x2", "0x7fffffff", "0x7b"), `"key":"balistid-inject"`, `"key":"other","x":"balistid-inject"`, 1)))
	if s, _, _, o := fl.nums.Count(MaxNumber); s != 0 || o != 0 {
		t.Errorf("record under another key counted: %d stored, %d outside", s, o)
	}
}

func TestTailRefusesAnOverlongUnfinishedLine(t *testing.T) {
	l := newLaurel(t)
	tail := logTail{path: l.path}
	if err := tail.openAtEnd(); err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(strings.Repeat("x", maxLine+1))
	_ = f.Close()
	if _, err := readAll(t, &tail); err == nil {
		t.Error("an unfinished line over maxLine was buffered")
	}
}

// Laurel keeps ten rotated files: a reader ten rotations behind still finds its successor.
func TestTailFollowsTenRotationsBehind(t *testing.T) {
	l := newLaurel(t)
	tail := logTail{path: l.path}
	if err := tail.openAtEnd(); err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	var want []string
	for i := range 10 {
		line := fmt.Sprintf("l%d", i)
		l.write(line)
		want = append(want, line)
		l.rotate()
	}
	l.write("last")
	want = append(want, "last")
	if got, err := readAll(t, &tail); err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ten rotations behind: %q, %v", got, err)
	}
}

// A barrier the reader only reaches after the deadline, behind a backlog, does not end the run in
// time: the measurement is missing, not complete.
func TestBarrierBehindABacklogMissesTheDeadline(t *testing.T) {
	l := newLaurel(t)
	fl := NewFollower(l.path, rangejob.LoadExec, 0)
	if err := fl.Start(); err != nil {
		t.Fatal(err)
	}
	const lines = 50000
	backlog := make([]string, 0, lines)
	for n := 1; n <= lines; n++ {
		backlog = append(backlog, execLine(fmt.Sprintf("balistid-n-%d", n)))
	}
	l.write(backlog...)
	l.write(execLine("balistid-canary-late"))
	start := time.Now()
	_, err := fl.Finish(t.Context(), "balistid-canary-late", func(context.Context) error { return nil }, time.Millisecond)
	if err == nil {
		t.Error("a barrier read after the deadline completed the run")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("Finish took %s: the reader did not stop at the deadline", time.Since(start))
	}
	if stored, _, _, _ := fl.nums.Count(lines); stored == lines {
		t.Error("the reader went on through the whole backlog after the deadline")
	}
}

// A start inside a line that a rotation then cuts off is a broken log, never a silent loss of the
// next file's first record.
func TestTailRefusesARotationInsideTheStartingLine(t *testing.T) {
	l := newLaurel(t)
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"EXECVE":{"argc":2,`)
	_ = f.Close()
	tail := logTail{path: l.path}
	if err := tail.openAtEnd(); err != nil {
		t.Fatal(err)
	}
	defer tail.close()
	l.rotate()
	l.write(execLine("balistid-n-1"))
	if got, err := readAll(t, &tail); err == nil {
		t.Errorf("read %q across a rotation inside the starting line", got)
	}
}
