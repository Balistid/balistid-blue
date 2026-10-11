package rangeguest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecsReportAFailedChild(t *testing.T) {
	for prog, wantErr := range map[string]bool{"/usr/bin/true": false, "/usr/bin/false": true} {
		e := NewExecs(2)
		e.prog = prog
		for seq := uint64(1); seq <= 3; seq++ {
			if err := e.Emit(seq); err != nil {
				t.Fatal(err)
			}
		}
		if err := e.Wait(); (err != nil) != wantErr {
			t.Errorf("%s: Wait = %v", prog, err)
		}
	}
}

// No process has NoPID, so a sound kernel answers ESRCH; anything else is reported.
func TestPeekOfNoProcess(t *testing.T) {
	if err := Peek(1); err != nil {
		t.Skipf("ptrace is not ESRCH here (a seccomp sandbox?): %v", err)
	}
}

func TestTickDelta(t *testing.T) {
	before, after := "cpu  10 0 0 0 0 0 0 1 0 0\n", "cpu  60 0 0 40 0 0 0 3 0 0\n"
	if total, steal, err := TickDelta(before, after); err != nil || total != 92 || steal != 2 {
		t.Errorf("TickDelta = %d, %d, %v; want 92 and 2", total, steal, err)
	}
	for _, c := range [][2]string{{after, before}, {"cpu  10 0 0 0 0 0 0 5 0 0\n", "cpu  20 0 0 0 0 0 0 4 0 0\n"}, {"", after}} {
		if _, _, err := TickDelta(c[0], c[1]); err == nil {
			t.Errorf("TickDelta(%q, %q) accepted", c[0], c[1])
		}
	}
}

// Only a rewrite after the signal, and only a complete one, gives the flag; an old file or a
// truncated one never does.
func TestFreshStateReadsOnlyARewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auditd.state")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const no, yes = "plugin queue overflow detected = no\n", "plugin queue overflow detected = yes\n"
	cases := map[string]struct {
		before string
		signal func()
		want   string
	}{
		"not rewritten":   {no, func() {}, "stale"},
		"rewritten yes":   {no, func() { write(yes) }, "yes"},
		"rewritten no":    {yes, func() { write("x\n" + no) }, "no"},
		"left truncated":  {no, func() { write("") }, "stale"},
		"created":         {"", func() { write(yes) }, "yes"},
		"half then whole": {no, func() { write("plugin"); go func() { time.Sleep(30 * time.Millisecond); write(yes) }() }, "yes"},
	}
	for name, c := range cases {
		_ = os.Remove(path)
		if c.before != "" {
			write(c.before)
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
		if got := FreshState(path, c.signal, 300*time.Millisecond, 5*time.Millisecond); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestTrialForRunsOnlyOneBootTrialsInPhaseOne(t *testing.T) {
	if tr, err := TrialFor("rate-burst", "1"); err != nil || tr.Name != "rate-burst" {
		t.Errorf("TrialFor(rate-burst, 1) = %+v, %v", tr, err)
	}
	for _, c := range [][2]string{{"rate-burst", "2"}, {"rate-burst", ""}, {"rate-burst", "01"}, {"nope", "1"}, {"", "1"}} {
		if _, err := TrialFor(c[0], c[1]); err == nil {
			t.Errorf("TrialFor(%q, %q) accepted", c[0], c[1])
		}
	}
}
