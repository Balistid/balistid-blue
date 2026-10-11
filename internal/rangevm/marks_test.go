package rangevm

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// clockAt returns a clock that reads t0 plus 10 ms more on every call.
func clockAt(t0 time.Time) func() time.Time {
	n := 0
	return func() time.Time { n++; return t0.Add(time.Duration(n) * 10 * time.Millisecond) }
}

func TestMarkWriterStampsExactMarksAndPassesEverything(t *testing.T) {
	t0 := time.Unix(1000, 0)
	var out bytes.Buffer
	mw := &markWriter{w: &out, now: clockAt(t0)}
	in := "booting\r\nbalistid-range-guest: armed\nbalistid-fa" + "il 41\r\nbalistid-killed\n[ 3.2] tail"
	for _, part := range []string{in[:20], in[20:47], in[47:]} {
		if n, err := mw.Write([]byte(part)); err != nil || n != len(part) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if out.String() != in {
		t.Errorf("console changed: %q", out.String())
	}
	m := mw.m
	if m.Bad != "" || m.H != 41 || !m.Fail.Equal(t0.Add(10*time.Millisecond)) || !m.Killed.Equal(t0.Add(20*time.Millisecond)) {
		t.Errorf("marks = %+v", m)
	}
}

// Anything that starts like a mark and is not exactly one, a repeat, a kill before the fail, or a
// line too long to look at makes the marks Bad: hostile console text never becomes a mark.
func TestMarkWriterRefusesAnythingButExactMarks(t *testing.T) {
	cases := []string{
		"balistid-fail 041\n",
		"balistid-fail \n",
		"balistid-fail 4 1\n",
		"balistid-fail -1\n",
		"balistid-fail 41 \n",
		"balistid-fail\t41\n",
		"balistid-failure 3\n",
		"balistid-fail 18446744073709551616\n",
		"balistid-fail 1\nbalistid-fail 2\n",
		"balistid-killed\n",
		"balistid-fail 1\nbalistid-killed now\n",
		"balistid-fail 1\nbalistid-killed\nbalistid-killed\n",
		"balistid-fail " + strings.Repeat("1", 60) + "\n",
	}
	for _, in := range cases {
		mw := &markWriter{w: &bytes.Buffer{}, now: clockAt(time.Unix(0, 0))}
		_, _ = mw.Write([]byte(in))
		if mw.m.Bad == "" {
			t.Errorf("%q: marks %+v accepted", in, mw.m)
		}
	}
	mw := &markWriter{w: &bytes.Buffer{}, now: clockAt(time.Unix(0, 0))}
	_, _ = mw.Write([]byte("balistid-fail 7"))
	if !mw.m.Fail.IsZero() {
		t.Error("a mark without its newline was stamped")
	}
}

func TestFailureInvalid(t *testing.T) {
	t0 := time.Unix(1000, 0)
	ms := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Millisecond) }
	cases := []struct {
		kind  string
		m     Marks
		valid bool
	}{
		{FailReset, Marks{H: 5, Fail: t0, Exited: ms(100)}, true},
		{FailReset, Marks{H: 5, Fail: t0, Exited: ms(101)}, false},
		{FailReset, Marks{Exited: ms(1)}, false},
		{FailReset, Marks{Fail: t0, Killed: ms(1), Exited: ms(2)}, false},
		{FailReset, Marks{Fail: t0, Exited: ms(1), Bad: "two fail marks"}, false},
		{FailKill, Marks{Fail: t0, Killed: ms(100), Exited: ms(900)}, true},
		{FailKill, Marks{Fail: t0, Killed: ms(101), Exited: ms(900)}, false},
		{FailKill, Marks{Fail: t0, Exited: ms(50)}, false},
	}
	for i, c := range cases {
		if why := failureInvalid(c.kind, c.m); (why == "") != c.valid {
			t.Errorf("case %d (%s): %q", i, c.kind, why)
		}
	}
}

// A reset trial boots again only after a fail mark that QEMU's exit followed within MarkWindow;
// a kill trial needs the kill mark within it. Late, missing or garbled marks are INVALID.
func TestFailureTrialsNeedTheirMarksInTime(t *testing.T) {
	armed := facts(t, append(echo("reset-crash", 1), fact(FactResetArmed, "yes"))...)
	second := facts(t, echo("reset-crash", 2)...)
	reset := resetTrial
	reset.Failure = FailReset
	kill := Limits{Trial: "kill-crash", Wall: time.Minute, Serial: 1 << 20, Boots: 1, Failure: FailKill}
	killed := facts(t, echo("kill-crash", 1)...)
	cases := []struct {
		name  string
		lim   Limits
		vm    fakeVM
		boots int
		why   string
		wantH uint64
	}{
		{"reset in time", reset, fakeVM{streams: [][]byte{armed, second}, serial: [][]byte{[]byte("balistid-fail 9\n")}}, 2, "", 9},
		{"reset exits late", reset, fakeVM{streams: [][]byte{armed, second}, serial: [][]byte{[]byte("balistid-fail 9\n")}, linger: []time.Duration{150 * time.Millisecond}}, 1, "after the fail mark", 9},
		{"reset without mark", reset, fakeVM{streams: [][]byte{armed, second}}, 1, "no fail mark", 0},
		{"reset garbled", reset, fakeVM{streams: [][]byte{armed, second}, serial: [][]byte{[]byte("balistid-fail 09\n")}}, 1, "malformed", 0},
		{"kill in time", kill, fakeVM{streams: [][]byte{killed}, serial: [][]byte{[]byte("balistid-fail 3\nbalistid-killed\n")}}, 1, "", 3},
		{"kill without kill mark", kill, fakeVM{streams: [][]byte{killed}, serial: [][]byte{[]byte("balistid-fail 3\n")}}, 1, "no kill mark", 3},
	}
	for _, c := range cases {
		vm := c.vm
		out, _ := runFake(t, c.lim, vm.run)
		if !strings.Contains(out.Invalid, c.why) || (c.why == "") != (out.Invalid == "") || len(vm.boots) != c.boots || out.Marks.H != c.wantH {
			t.Errorf("%s: Invalid %q after %d boots, H %d; want %q after %d, H %d", c.name, out.Invalid, len(vm.boots), out.Marks.H, c.why, c.boots, c.wantH)
		}
	}
	plain := &fakeVM{streams: [][]byte{armed, second}, serial: [][]byte{[]byte("balistid-fail 09\n")}}
	if out, _ := runFake(t, resetTrial, plain.run); out.Invalid != "" || !out.Marks.Fail.IsZero() {
		t.Errorf("a trial that is not a failure trial read marks: %+v", out)
	}
}

// A console line without end keeps at most maxMarkLine bytes for the marks, whatever the guest sends.
func TestMarkWriterKeepsLinesShort(t *testing.T) {
	mw := &markWriter{w: &bytes.Buffer{}, now: clockAt(time.Unix(0, 0))}
	_, _ = mw.Write(bytes.Repeat([]byte("x"), 1<<20))
	if len(mw.line) > maxMarkLine || !mw.long {
		t.Errorf("kept %d bytes of an unfinished line", len(mw.line))
	}
}
