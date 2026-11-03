package rangevm

import (
	"io"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// tools/ci/range_kvm.py finds the guest's host lines where a trial run of the launcher keeps them: check stores the
// serial log beside result.json under the state directory, which cmd/balistid-range puts at
// $XDG_STATE_HOME/balistid-range and the KVM job mounts as <work>/state, in the form journald forwards the guest's
// stdout to the console (a line of a kept serial.log), carriage return included. Of two runs it reads the newer.
func TestHostLinesOfARealTrialLayout(t *testing.T) {
	work := t.TempDir()
	state := filepath.Join(work, "state", "balistid-range")
	tr := trial(t, "rate-burst")
	image := storeImage(t, t.TempDir(), "x", cleanBuild)
	run := func(serial string) {
		t.Helper()
		_, err := check(t.Context(), image, t.TempDir(), state, tr.Name, TrialLabel(tr),
			func(_ string, w io.Writer) (Outcome, error) {
				_, err := io.WriteString(w, serial)
				return report(tr), err
			},
			func(o Outcome, _, _ string) (string, string) { return JudgeTrial(tr, o, cleanBuild, cleanBuild) }, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	run("[   10.100000] guest[555]: balistid-range-guest: host: an older run\r\n")
	time.Sleep(1100 * time.Millisecond) // run ids are by the second
	run("[    9.100000] systemd[1]: Started auditd.service.\r\n" +
		"[   61.408037] guest[555]: balistid-range-guest: host: store read: audit idle after 3.2s, <nil>\r\n" +
		"[   61.408100] guest[555]: balistid-range-guest: $ /usr/bin/systemctl show (err <nil>)\r\n" +
		"[   61.508037] guest[555]: balistid-range-guest: host: loss record seq 7 balistid-loss\r\n")
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	script := "import sys; sys.path.insert(0, sys.argv[1]); import range_kvm; from pathlib import Path; " +
		"print('\\n'.join(range_kvm.host_lines(Path(sys.argv[2]))))"
	out, err := exec.CommandContext(t.Context(), "/usr/bin/python3", "-I", "-c", script, filepath.Join(repo, "tools", "ci"), //nolint:gosec // the repository's own script
		filepath.Join(work, "state")).Output()
	if err != nil {
		t.Fatalf("range_kvm.host_lines: %v", err)
	}
	want := "balistid-range-guest: host: store read: audit idle after 3.2s, <nil>\n" +
		"balistid-range-guest: host: loss record seq 7 balistid-loss\n"
	if string(out) != want {
		t.Errorf("host lines %q\nwant       %q", out, want)
	}
}
