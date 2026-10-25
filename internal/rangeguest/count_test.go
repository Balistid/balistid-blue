package rangeguest

import (
	"fmt"
	"slices"
	"strings"
	"testing"

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
		fl, err := NewCounter(c.kind, 0)
		if err != nil {
			t.Fatal(err)
		}
		fl.Line([]byte(c.line))
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
	fl, err := NewCounter(rangejob.LoadExec, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"balistid-n-1", "balistid-n-2", "balistid-n-2", "balistid-n-3"} {
		fl.Line([]byte(execLine(a)))
	}
	if s, m, d, _ := fl.nums.Count(3); s != 2 || m != 1 || d != 1 {
		t.Errorf("drop counted %d stored, %d missing, %d duplicate; want 2 missing the dropped one and its repeat a duplicate", s, m, d)
	}
}

// Only an exec whose argument is exactly the barrier ends the run.
func TestBarrierIsAnExactArgument(t *testing.T) {
	for _, line := range []string{execLine("balistid-canary-xy"), `{"PROCTITLE":{"ARGV":["balistid-canary-x"]}}`} {
		if IsBarrier([]byte(line), "balistid-canary-x") {
			t.Fatalf("barrier seen in %s", line)
		}
	}
	if !IsBarrier([]byte(execLine("balistid-canary-x")), "balistid-canary-x") {
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
	fl, err := NewCounter(rangejob.LoadPtrace, 0)
	if err != nil {
		t.Fatal(err)
	}
	fl.Line([]byte(strings.Replace(ptraceLine("0x2", "0x7fffffff", "0x7b"), `"key":"balistid-inject"`, `"key":"other","x":"balistid-inject"`, 1)))
	if s, _, _, o := fl.nums.Count(MaxNumber); s != 0 || o != 0 {
		t.Errorf("record under another key counted: %d stored, %d outside", s, o)
	}
}

// The first records counted as outside are kept, cut to 2000 bytes, so a run shows what Laurel wrote.
func TestCounterKeepsWhatItCountedOutside(t *testing.T) {
	fl, err := NewCounter(rangejob.LoadExec, 0)
	if err != nil {
		t.Fatal(err)
	}
	long := execLine("balistid-n-" + strings.Repeat("9", 3000))
	for _, line := range []string{execLine("balistid-n-1"), execLine("balistid-n-07"), execLine("balistid-n-0"), long,
		execLine("balistid-n-x"), execLine("balistid-n-2"), execLine("balistid-n-5")} {
		fl.Line([]byte(line))
	}
	kept := fl.Outside()
	if len(kept) != 3 || kept[0] != execLine("balistid-n-07") || kept[1] != execLine("balistid-n-0") || len(kept[2]) != 2000 {
		t.Fatalf("kept %d records: %.80q", len(kept), kept)
	}
	if _, _, _, o := fl.Numbers().Count(2); o != 5 {
		t.Errorf("outside %d, want 5 (07, 0, the long one, x, 5)", o)
	}
	if above := fl.Numbers().Above(2, 3); !slices.Equal(above, []uint64{5}) {
		t.Errorf("above %v", above)
	}
}

func TestCounterRefusesAnUnknownLoad(t *testing.T) {
	if _, err := NewCounter(rangejob.LoadWrite, 0); err == nil {
		t.Error("a write load was counted")
	}
}
