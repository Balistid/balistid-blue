package rangerun

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func printableASCII(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range data {
		if (c < 0x20 && c != '\n') || c > 0x7e {
			t.Fatalf("%s: byte %#x at %d", filepath.Base(path), c, i)
		}
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("%s: mode %v, %v", filepath.Base(path), st.Mode().Perm(), err)
	}
}

// resultsRoot is a results directory as the install leaves it: agent/ and evidence/ setgid.
func resultsRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, l := range []string{LabelAgent, LabelEvidence, LabelAcceptance} {
		d := filepath.Join(root, l)
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o750|os.ModeSetgid); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestNewResultDir(t *testing.T) {
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)
	results := resultsRoot(t)
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	dir, id, err := NewResultDir(results, LabelAgent, "probe-1", now)
	if err != nil || !strings.HasPrefix(id, "20261006T090000Z-") || !strings.HasSuffix(id, "-probe-1") || dir != filepath.Join(results, LabelAgent, id) {
		t.Fatalf("agent result dir = %q %q %v", dir, id, err)
	}
	if _, id, err := NewResultDir(results, LabelEvidence, "", now); err != nil || len(id) != len("20261006T090000Z-")+8 {
		t.Fatalf("evidence result id = %q %v", id, err)
	}
	for _, c := range []struct{ label, job string }{{"other", ""}, {LabelAgent, "../x"}, {LabelAgent, "Upper"}} {
		if _, _, err := NewResultDir(results, c.label, c.job, now); err == nil {
			t.Errorf("NewResultDir(%q, %q) succeeded", c.label, c.job)
		}
	}
}

// A result directory the maintainer's group could not read is refused, never repaired: a missing
// label directory, one without setgid, or a umask that takes the group's bits.
func TestNewResultDirRefusesAMisinstall(t *testing.T) {
	now := time.Now()
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)
	if _, _, err := NewResultDir(t.TempDir(), LabelAgent, "", now); err == nil {
		t.Error("a missing label directory was created instead of refused")
	}
	plain := t.TempDir()
	if err := os.Mkdir(filepath.Join(plain, LabelAgent), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewResultDir(plain, LabelAgent, "", now); err == nil {
		t.Error("a label directory without setgid was accepted")
	}
	open := resultsRoot(t)
	if err := os.Chmod(filepath.Join(open, LabelAgent), 0o777|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewResultDir(open, LabelAgent, "", now); err == nil {
		t.Error("a label directory others can write was accepted")
	}
	linked := t.TempDir()
	if err := os.Symlink(filepath.Join(resultsRoot(t), LabelAgent), filepath.Join(linked, LabelAgent)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewResultDir(linked, LabelAgent, "", now); err == nil {
		t.Error("a symlinked label directory was followed")
	}
	syscall.Umask(0o077)
	tight := resultsRoot(t)
	if _, _, err := NewResultDir(tight, LabelAgent, "", now); err == nil {
		t.Error("a 0700 result directory was accepted")
	}
	if left, _ := os.ReadDir(filepath.Join(tight, LabelAgent)); len(left) != 0 {
		t.Errorf("a refused result directory stayed: %v", left)
	}
}

// Whatever a guest or an agent put in a reason or a kernel name, result.json is printable ASCII
// readable by the maintainer's group.
func TestWriteResultEscapesGuestText(t *testing.T) {
	dir := t.TempDir()
	exit := 9
	r := Result{
		ID: "x\u009b", Label: "agent\u202e", Verdict: "RAN\u202e", ImageCommit: "\u009b", ImageSHA256: "\xff", Reason: "ok\x1b[2J\u202e", RunnerCommit: "c\u2028",
		Job:  &JobInfo{Name: "a\u202e", Kind: "k\x1b", Program: "p\n", ContentKey: "\u009b", ProgramSHA256: "\u202e", DiskSHA256: "\xff"},
		Runs: []Run{{Verdict: "RAN", Reason: "line\nforged", GuestKernel: "7.2.8-\u0430rch1-2", JobResult: "signal\u202e", JobExit: &exit}},
	}
	if err := WriteResult(dir, r); err != nil {
		t.Fatal(err)
	}
	if r.Runs[0].Reason != "line\nforged" {
		t.Fatalf("WriteResult changed the caller's runs: %q", r.Runs[0].Reason)
	}
	path := filepath.Join(dir, "result.json")
	printableASCII(t, path)
	data, _ := os.ReadFile(path) //nolint:gosec // test temp dir
	if !bytes.Contains(data, []byte(`"schema_version": 1`)) || !bytes.Contains(data, []byte(`line\\x0aforged`)) {
		t.Fatalf("result.json:\n%s", data)
	}
}

func TestWriteTextEscapesEveryByte(t *testing.T) {
	dir := t.TempDir()
	raw := []byte("{\"a\":1}\n\x1b]0;title\x07\xff\x00")
	if err := WriteText(dir, "job-out.txt", raw); err != nil {
		t.Fatal(err)
	}
	printableASCII(t, filepath.Join(dir, "job-out.txt"))
	got, _ := os.ReadFile(filepath.Join(dir, "job-out.txt")) //nolint:gosec // test temp dir
	if want := `{\x22a\x22:1}\x0a\x1b]0;title\x07\xff\x00`; string(got) != want {
		t.Fatalf("job-out.txt = %q, want %q", got, want)
	}
}

// Retention keeps the newest results and the pinned one, and leaves what is not a result alone.
func TestPruneKeepsTheNewestAndThePin(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"20261001T000000Z-00000001", "20261002T000000Z-00000002", "20261003T000000Z-00000003-job",
		"20261004T000000Z-00000004", "not-a-result",
	}
	for _, n := range names {
		if err := os.Mkdir(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := Prune(dir, 2, "20261001T000000Z-00000001"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	want := []string{"20261001T000000Z-00000001", "20261003T000000Z-00000003-job", "20261004T000000Z-00000004", "not-a-result"}
	if !slices.Equal(got, want) {
		t.Fatalf("after prune %q, want %q", got, want)
	}
}

// A result retention cannot remove is an error, not a silent skip (R5).
func TestPruneReportsWhatItCannotRemove(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"20261001T000000Z-00000001", "20261002T000000Z-00000002"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // a directory made read-only for the test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restores the test directory
	if err := Prune(dir, 1, ""); err == nil {
		t.Fatal("Prune in a read-only directory reported nothing")
	}
}

func TestWriteTextTakesOnlyPlainNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "../x", "result.json", "a/b", ".hidden", "Upper.txt"} {
		if err := WriteText(dir, name, []byte("{}")); err == nil {
			t.Errorf("WriteText(%q) succeeded", name)
		}
	}
}

func TestPruneKeepsAtLeastOne(t *testing.T) {
	for _, keep := range []int{0, -1} {
		if err := Prune(t.TempDir(), keep, ""); err == nil {
			t.Errorf("Prune(keep %d) succeeded", keep)
		}
	}
}
