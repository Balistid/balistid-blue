package collector

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/status"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// statusRig is a rig whose writer publishes its report into a temp directory on a boot clock the test sets.
func statusRig(t *testing.T) (*rig, string, *uint64) {
	t.Helper()
	r := newRig(t)
	path, boot := filepath.Join(t.TempDir(), "status"), new(uint64)
	r.w.StatusPath = path
	r.w.Boottime = func() (uint64, error) { return *boot, nil }
	return r, path, boot
}

func readStatus(t *testing.T, path string) status.Report {
	t.Helper()
	rep, err := status.ReadReport(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// The report says what the tick computed, world-readable whatever the umask: UNKNOWN before the store opens,
// then the next reason, here Laurel not connected.
func TestStatusReportFollowsHealth(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	r, path, boot := statusRig(t)
	*boot = 7
	r.start(nil)
	r.step(0)
	rep := readStatus(t, path)
	if rep.Health.State != entry.StateUnknown || rep.Boot != 7 {
		t.Fatalf("first report %+v", rep)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("report %v, %v", fi, err)
	}
	r.settle()
	if rep := readStatus(t, path); rep.Health != (entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLaurelDisconnected}) {
		t.Fatalf("report after the store opened %+v", rep.Health)
	}
}

// While health holds the report is rewritten every second, not every tick, so its age shows a stopped writer.
func TestStatusReportIsRewrittenEverySecond(t *testing.T) {
	r, path, boot := statusRig(t)
	r.start(nil)
	r.settle()
	first := readStatus(t, path)
	*boot = 1
	r.step(250 * time.Millisecond)
	if rep := readStatus(t, path); rep.At != first.At {
		t.Fatalf("rewritten after 250 ms of the same health: %+v", rep)
	}
	r.step(time.Second)
	if rep := readStatus(t, path); rep.At == first.At || rep.Boot != 1 {
		t.Fatalf("not rewritten after a second: %+v", rep)
	}
}

// A report that cannot be written leaves the writer and its store running.
func TestStatusReportWriteFailureKeepsTheWriterGoing(t *testing.T) {
	r, path, _ := statusRig(t)
	r.w.StatusPath = filepath.Join(path, "missing", "status")
	r.start(nil)
	r.settle()
	r.step(time.Second)
	if !r.last.up {
		t.Fatal("the store closed over a status write")
	}
	if _, err := os.Stat(r.w.StatusPath); err == nil {
		t.Fatal("a report in a missing directory")
	}
}

// A write that fails removes the last report, which said OK, so the CLI reads UNKNOWN at once rather than an OK that
// is still fresh; the next write that succeeds publishes again.
func TestStatusWriteFailureRemovesTheOKReport(t *testing.T) {
	r, path, _ := statusRig(t)
	fail := make(chan bool, 1)
	fail <- false
	r.w.writeFile = func(p string, b []byte, perm os.FileMode) error {
		f := <-fail
		fail <- f
		if f {
			return errors.New("no space left on device")
		}
		return wholefile.Write(p, b, perm)
	}
	r.start(nil)
	r.settle()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no first report: %v", err)
	}
	<-fail
	fail <- true
	r.step(time.Second)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a report outlived its failed write: %v", err)
	}
	<-fail
	fail <- false
	r.step(250 * time.Millisecond)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("not written again after the failure: %v", err)
	}
}
