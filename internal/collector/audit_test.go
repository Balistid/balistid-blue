package collector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/auditstat"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

// auditFake stands in for auditstat's report and auditd's state file; the test changes them while the writer reads.
type auditFake struct {
	mu        sync.Mutex
	report    auditstat.Report
	reportErr error
	overflow  bool
	mtime     int64
	stateErr  error
}

// newAuditFake is a healthy auditd 100 with the rules locked, no loss and no overflow.
func newAuditFake() *auditFake {
	return &auditFake{report: auditstat.Report{Seq: 1, Status: auditstat.Status{PID: 100, Enabled: 2}}, mtime: 1}
}

func (f *auditFake) set(fn func(*auditFake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// write is auditstat's next report and auditd's next state write, as every 5 s.
func (f *auditFake) write() { f.set(func(f *auditFake) { f.report.Seq++; f.mtime++ }) }

func (f *auditFake) audit(seenPath, bootID string) *Audit {
	return &Audit{
		readReport: func() (auditstat.Report, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.report, f.reportErr
		},
		readState: func() (bool, int64, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.overflow, f.mtime, f.stateErr
		},
		seenPath: seenPath, bootID: bootID,
	}
}

// auditRig is a rig whose writer reads f, with its seen file at seenPath, started and settled.
func auditRig(t *testing.T, f *auditFake, seenPath, bootID string) *rig {
	t.Helper()
	r := newRig(t)
	r.w.Audit = f.audit(seenPath, bootID)
	r.start(nil)
	r.settle()
	return r
}

// healthy connects Laurel and stores its probe, so health is OK but for the audit's reasons.
func healthy(r *rig) {
	r.t.Helper()
	connect(r, 77)
	r.step(0)
	n := probed(r)
	r.push(canaryLine(1, n, 1000, 4242))
	r.step(0)
}

// stepFresh advances by d in steps of at most 5 s, auditstat and auditd writing at each.
func stepFresh(r *rig, f *auditFake, d time.Duration) {
	for ; d > 0; d -= 5 * time.Second {
		f.write()
		r.step(min(d, 5*time.Second))
	}
}

// losses is each lost record of stage, as its count.
func losses(r *rig, stage Stage) []float64 {
	var out []float64
	for _, n := range r.st.kinds("lost") {
		if n["stage"] == string(stage) {
			out = append(out, n["count"].(float64))
		}
	}
	return out
}

func seenPath(t *testing.T) string { return filepath.Join(t.TempDir(), "audit-seen") }

func TestParseAuditdState(t *testing.T) {
	const yes, no = overflowName + " = yes", overflowName + " = no"
	head := "audit version = 4.2.1\ncurrent plugin queue depth = 0\n"
	for state, want := range map[string]string{
		head + yes + "\nplugin queueing suspended = no\n": "yes",
		head + no + "\n":              "no",
		no:                            "no",
		head:                          "error",
		"":                            "error",
		yes + "\n" + yes + "\n":       "error",
		yes + "\n" + no + "\n":        "error",
		overflowName + " = maybe\n":   "error",
		overflowName + "=yes\n":       "error",
		overflowName + " = yes \n":    "error",
		overflowName + " = yes\r\n":   "error",
		overflowName + " = n":         "error",
		"x" + yes + "\n":              "error",
		"# " + yes + "\n" + no + "\n": "error",
	} {
		ov, err := parseAuditdState([]byte(state))
		got := "error"
		if err == nil {
			got = map[bool]string{true: "yes", false: "no"}[ov]
		}
		if got != want {
			t.Errorf("%q: %s, want %s", state, got, want)
		}
	}
}

func FuzzParseAuditdState(f *testing.F) {
	f.Add([]byte("audit version = 4.2.1\nplugin queue overflow detected = yes\n"))
	f.Add([]byte("plugin queue overflow detected = no"))
	f.Add([]byte("plugin queue overflow detected = no\nplugin queue overflow detected = no\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ov, err := parseAuditdState(b)
		if err != nil {
			return
		}
		lines, want := strings.Split(string(b), "\n"), overflowName+" = no"
		if ov {
			want = overflowName + " = yes"
		}
		named := 0
		for _, l := range lines {
			if strings.Contains(l, overflowName) {
				named++
				if l != want {
					t.Fatalf("flag %v from the line %q", ov, l)
				}
			}
		}
		if named != 1 {
			t.Fatalf("flag %v from %d lines", ov, named)
		}
	})
}

// The state file is read only as a regular file of root, not through a symlink, a FIFO without waiting, and at
// most maxStateBytes; the report has its own reader (auditstat.ReadReport).
func TestStateFileChecks(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "auditd.state")
	if err := os.WriteFile(good, []byte(overflowName+" = yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, mtime, err := readSmall(good, maxStateBytes, os.Getuid()); err != nil || len(b) == 0 || mtime == 0 {
		t.Fatalf("own file: %q, %d, %v", b, mtime, err)
	}
	if os.Getuid() != 0 {
		if _, _, err := readAuditdState(good); err == nil || !strings.Contains(err.Error(), "uid 0") {
			t.Errorf("a state file not of root: %v", err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("x\n", maxStateBytes)+overflowName+" = no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"symlink": link, "fifo": fifo, "over 4 KiB": big, "missing": dir + "/none",
		"directory": dir} {
		if _, _, err := readSmall(path, maxStateBytes, os.Getuid()); err == nil {
			t.Errorf("%s read", name)
		}
	}
	// A file whose stat size understates what a read returns, as one auditd grows after the stat.
	if _, _, err := readSmall("/proc/self/status", 64, os.Getuid()); err == nil {
		t.Error("a file over the limit read because its stat said 0 bytes")
	}
	for _, uid := range []int{-1, os.Getuid() + 1} {
		if _, _, err := readSmall(good, maxStateBytes, uid); err == nil {
			t.Errorf("a file of uid %d read as of another owner", os.Getuid())
		}
	}
}

func TestDecodeSeen(t *testing.T) {
	for b, ok := range map[string]bool{
		`{"schema_version":1,"boot_id":"b","lost":3,"overflow":true,"auditd_pid":9}`: true,
		`{"schema_version":2,"boot_id":"b","lost":3,"overflow":true,"auditd_pid":9}`: false,
		`{"schema_version":1,"boot_id":"","lost":3}`:                                 false,
		`{"schema_version":1,"boot_id":"b","lost":-1}`:                               false,
		`{"schema_version":1,"boot_id":"b","lost":4294967296}`:                       false,
		`{"schema_version":1,"boot_id":"b","extra":1}`:                               false,
		`{"schema_version":1,"boot_id":"b"} {}`:                                      false,
		`{"schema_version":1,"boot_id":"b"}]`:                                        false,
		`{"schema_version":1,"boot_id":"b"}}`:                                        false,
		`{"schema_version":1,"boot_id":"b"}` + "\n":                                  true,
		`[]`: false,
	} {
		if _, err := decodeSeen([]byte(b)); (err == nil) != ok {
			t.Errorf("%s: %v", b, err)
		}
	}
}

func FuzzDecodeSeen(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"boot_id":"b","lost":3,"overflow":true,"auditd_pid":9}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := decodeSeen(b)
		if err == nil && (s.SchemaVersion != seenSchema || s.BootID == "") {
			t.Fatalf("decoded %+v", s)
		}
	})
}

// Kernel loss: a rise of lost counts its difference, a fall is a reset and counts max(new, 1).
func TestKernelLossRiseAndReset(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	for _, lost := range []uint32{5, 12, 3, 0, 0, 2} {
		f.set(func(f *auditFake) { f.report.Status.Lost = lost })
		stepFresh(r, f, time.Second)
		r.step(0)
		r.step(0)
	}
	if got := losses(r, StageKernel); len(got) != 5 || got[0] != 5 || got[1] != 7 || got[2] != 3 || got[3] != 1 || got[4] != 2 {
		t.Fatalf("kernel losses %v, want 5 7 3 1 2", got)
	}
}

// Dispatcher loss: one record each time the flag turns from no to yes, none while it stays yes.
func TestDispatcherLossOnEachTurnToYes(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	for _, ov := range []bool{true, true, false, true} {
		f.set(func(f *auditFake) { f.overflow = ov })
		stepFresh(r, f, time.Second)
		r.step(0)
		r.step(0)
	}
	if got := losses(r, StageDispatcher); len(got) != 2 || got[0] != 1 || got[1] != 1 {
		t.Fatalf("dispatcher losses %v, want 1 1", got)
	}
}

// The started record carries lost, the flag and auditd's pid; a boot's first report counts a non-zero lost and a
// yes once; a restart in the same boot counts only what changed since what the store committed; another boot
// counts afresh.
func TestRestartCountsOnlyChangesSinceTheStoredReport(t *testing.T) {
	f := newAuditFake()
	f.set(func(f *auditFake) { f.report.Status.Lost, f.overflow = 7, true })
	path := seenPath(t)
	run := func(boot string, steps int) *rig {
		r := auditRig(t, f, path, boot)
		for range steps {
			stepFresh(r, f, time.Second)
		}
		if err := stopRig(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := run("boot", 2)
	started := r.st.kinds("started")
	if len(started) != 1 {
		t.Fatalf("started records %v", started)
	}
	audit := started[0]["audit"].(map[string]any)
	if audit["lost"] != 7.0 || audit["overflow"] != "yes" || audit["auditd_pid"] != 100.0 {
		t.Fatalf("started record's audit %v", audit)
	}
	if k, d := losses(r, StageKernel), losses(r, StageDispatcher); len(k) != 1 || k[0] != 7 || len(d) != 1 {
		t.Fatalf("first run: kernel %v, dispatcher %v", k, d)
	}
	if r = run("boot", 2); len(losses(r, StageKernel))+len(losses(r, StageDispatcher)) != 0 {
		t.Fatalf("a restart counted again: %v", r.st.kinds("lost"))
	}
	f.set(func(f *auditFake) { f.report.Status.Lost = 9 })
	if r = run("boot", 2); len(losses(r, StageKernel)) != 1 || losses(r, StageKernel)[0] != 2 || len(losses(r, StageDispatcher)) != 0 {
		t.Fatalf("a restart after a rise: %v", r.st.kinds("lost"))
	}
	if r = run("next-boot", 2); len(losses(r, StageKernel)) != 1 || losses(r, StageKernel)[0] != 9 || len(losses(r, StageDispatcher)) != 1 {
		t.Fatalf("another boot: %v", r.st.kinds("lost"))
	}
}

// A loss not yet committed stays out of the seen file: a restart then counts it again, never not at all.
func TestSeenFileWaitsForTheCommit(t *testing.T) {
	f := newAuditFake()
	path := seenPath(t)
	r := auditRig(t, f, path, "boot")
	stepFresh(r, f, time.Second)
	r.step(0)
	if s, err := readSeen(path); err != nil || s.Lost != 0 {
		t.Fatalf("seen before the loss: %+v, %v", s, err)
	}
	r.st.set(func(s *fakeStore) { s.failFlush = true })
	f.set(func(f *auditFake) { f.report.Status.Lost = 4 })
	for range 4 {
		stepFresh(r, f, time.Second)
	}
	if s, err := readSeen(path); err != nil || s.Lost != 0 || r.last.up {
		t.Fatalf("seen holds a loss the store never committed: %+v, %v, store up %v", s, err, r.last.up)
	}
	r2 := auditRig(t, f, path, "boot")
	stepFresh(r2, f, time.Second)
	r2.step(0)
	r2.step(0)
	if got := losses(r2, StageKernel); len(got) != 1 || got[0] != 4 {
		t.Fatalf("the restart counted %v, want 4", got)
	}
	if s, err := readSeen(path); err != nil || s.Lost != 4 {
		t.Fatalf("seen after the commit: %+v, %v", s, err)
	}
}

// Reasons 8 and 10 wait the collector's first 15 s; then an unchanged seq, an unchanged mtime or a failed read is 8.
func TestAuditStaleAfter15s(t *testing.T) {
	report := func(f *auditFake) { f.report.Seq++ }
	state := func(f *auditFake) { f.mtime++ }
	for name, c := range map[string]struct{ spoil, other func(*auditFake) }{
		"seq unchanged":    {func(*auditFake) {}, state},
		"mtime unchanged":  {func(*auditFake) {}, report},
		"report refused":   {func(f *auditFake) { f.reportErr = errors.New("auditstat: the report is not auditstat's") }, state},
		"report symlinked": {func(f *auditFake) { f.reportErr = syscall.ELOOP }, state},
		"state refused":    {func(f *auditFake) { f.stateErr = errors.New("collector: auditd.state is not of uid 0") }, report},
		"state missing":    {func(f *auditFake) { f.stateErr = os.ErrNotExist }, report},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAuditFake()
			r := auditRig(t, f, seenPath(t), "boot")
			healthy(r)
			stepFresh(r, f, 20*time.Second)
			if health(r) != "OK" {
				t.Fatalf("health %q while fresh", health(r))
			}
			f.set(c.spoil) // the last fresh read was the step before
			for i := 1; i <= 15; i++ {
				f.set(c.other)
				r.step(time.Second)
				if want := map[bool]string{true: auditStale, false: "OK"}[i == 15]; health(r) != want {
					t.Fatalf("health %q %d s after the last fresh read, want %q", health(r), i, want)
				}
			}
		})
	}
}

// Nothing read at all is not OK either, but only after the collector's first 15 s.
func TestNothingReadIsStaleAfterTheFirst15s(t *testing.T) {
	f := newAuditFake()
	f.set(func(f *auditFake) {
		f.reportErr, f.stateErr = os.ErrNotExist, os.ErrNotExist
	})
	r := auditRig(t, f, seenPath(t), "boot")
	healthy(r)
	if health(r) != "OK" {
		t.Fatalf("health %q in the first 15 s", health(r))
	}
	r.step(15 * time.Second)
	if health(r) != auditStale {
		t.Fatalf("health %q after 15 s", health(r))
	}
}

// 9 over 10 over 8, each only where health would otherwise be OK; a fresh report without auditd or with audit not
// locked is 10, also in the first 15 s only after them.
func TestAuditReasonsInOrder(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	healthy(r)
	f.set(func(f *auditFake) { f.report.Status.Enabled = 1 })
	stepFresh(r, f, 5*time.Second)
	if health(r) != "OK" {
		t.Fatalf("health %q: 10 waits the first 15 s", health(r))
	}
	stepFresh(r, f, 10*time.Second)
	if health(r) != auditdDown {
		t.Fatalf("health %q with audit not locked", health(r))
	}
	f.set(func(f *auditFake) { f.report.Status.Enabled, f.report.Status.PID, f.stateErr = 2, 0, os.ErrNotExist })
	stepFresh(r, f, 20*time.Second)
	if health(r) != auditdDown {
		t.Fatalf("health %q without auditd and its state file", health(r))
	}
	f.set(func(f *auditFake) { f.stateErr, f.overflow = nil, true })
	stepFresh(r, f, time.Second)
	if health(r) != auditOverflow {
		t.Fatalf("health %q with the flag yes", health(r))
	}
	r.w.Links.Disconnected(nil)
	r.step(0)
	if health(r) != "UNKNOWN laurel-disconnected" {
		t.Fatalf("health %q: the audit's reasons only where health would be OK", health(r))
	}
}

// The flag's 9 holds while it reads yes and fresh, and ends with it.
func TestOverflowHoldsWhileTheFlagReadsYes(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	healthy(r)
	f.set(func(f *auditFake) { f.overflow = true })
	stepFresh(r, f, 30*time.Second)
	if health(r) != auditOverflow {
		t.Fatalf("health %q", health(r))
	}
	f.set(func(f *auditFake) { f.overflow = false })
	stepFresh(r, f, time.Second)
	if health(r) != "OK" {
		t.Fatalf("health %q after the flag cleared", health(r))
	}
}

// A new auditd pid, not the first the collector sees, is 10 over any other reason until that auditd's first fresh
// state or 15 s; the first pid is not, nor a pid gone to 0.
func TestNewAuditdPIDHoldsUnknown(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	healthy(r)
	f.set(func(f *auditFake) { f.report.Seq++; f.report.Status.PID = 0 })
	r.step(time.Second)
	f.set(func(f *auditFake) { f.report.Seq++; f.report.Status.PID = 200 })
	r.w.Links.Disconnected(nil)
	r.step(time.Second)
	if health(r) != auditdRestarted {
		t.Fatalf("health %q after a new pid", health(r))
	}
	r.step(time.Second)
	if health(r) != auditdRestarted {
		t.Fatalf("health %q before the new auditd's state", health(r))
	}
	f.write()
	r.step(time.Second)
	if health(r) != "UNKNOWN laurel-disconnected" {
		t.Fatalf("health %q after the new auditd's first state", health(r))
	}
	f.set(func(f *auditFake) { f.report.Seq++; f.report.Status.PID = 300 })
	r.step(time.Second)
	for i := 1; i <= 15; i++ {
		f.set(func(f *auditFake) { f.report.Seq++ })
		r.step(time.Second)
		if (health(r) == auditdRestarted) != (i < 15) {
			t.Fatalf("health %q %d s after the third pid, without a state", health(r), i)
		}
	}
	if got := r.st.kinds("health"); !hasState(got, auditdRestarted) {
		t.Fatalf("no health record of the restart: %v", got)
	}
}

func hasState(records []map[string]any, state string) bool {
	for _, h := range records {
		if h["state"] == state {
			return true
		}
	}
	return false
}

// A new pid after a collector restart in the same boot is a restart too.
func TestNewPIDAcrossACollectorRestart(t *testing.T) {
	f := newAuditFake()
	path := seenPath(t)
	r := auditRig(t, f, path, "boot")
	stepFresh(r, f, time.Second)
	r.step(0)
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *auditFake) { f.report.Status.PID = 101 })
	if r = auditRig(t, f, path, "boot"); health(r) != auditdRestarted {
		t.Fatalf("health %q: a new pid after the collector's restart is a restart", health(r))
	}
	if r = auditRig(t, f, path, "boot"); health(r) == auditdRestarted {
		t.Fatal("the same pid after a restart is not")
	}
}

// The audit's health strings map to their reasons, and kernel and dispatcher losses to their stages.
func TestAuditHealthAndLossEntries(t *testing.T) {
	for h, want := range map[string]entry.Reason{auditStale: entry.ReasonAuditStale, auditOverflow: entry.ReasonDispatcher,
		auditdDown: entry.ReasonAuditd, auditdRestarted: entry.ReasonAuditd} {
		if e, err := healthEntry(h, 0); err != nil || e.State != entry.StateUnknown || e.Reason != want {
			t.Errorf("%s: %+v, %v", h, e, err)
		}
	}
	for stage, want := range map[Stage]entry.Loss{
		StageKernel:     {Seq: 9, Stage: entry.StageKernel, Records: 3},
		StageDispatcher: {Seq: 9, Stage: entry.StageDispatcher, Records: 1},
	} {
		data := `{"schema_version":1,"at":1,"note_seq":2,"kind":"lost","stage":"` + string(stage) +
			`","count":3,"bytes":0,"first_seq":0,"last_seq":0,"first_at":1,"last_at":1}`
		l, err := lossOf(shard.Leaf{Seq: 9, Provider: store.HealthProvider, Data: []byte(data)})
		if err != nil || l == nil || *l != want {
			t.Errorf("%s: %+v, %v", stage, l, err)
			continue
		}
		if _, err := (entry.Entry{At: 1, Body: *l}).Encode(); err != nil {
			t.Errorf("%s: the ledger would refuse %+v: %v", stage, *l, err)
		}
	}
}

// Without an audit source the collector does not start: its health would read OK blind to the kernel's loss (R6).
func TestRunRefusesNoAudit(t *testing.T) {
	err := Run(t.Context(), Config{})
	if err == nil || !strings.Contains(err.Error(), "no audit source") {
		t.Fatalf("Run without an audit source: %v", err)
	}
}

// A loss the last hand-over at stop gives the store is in the seen file once the Close committed it.
func TestStopStoresTheLastLossInTheSeenFile(t *testing.T) {
	f := newAuditFake()
	path := seenPath(t)
	r := auditRig(t, f, path, "boot")
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	f.set(func(f *auditFake) { f.report.Status.Lost = 4 })
	stepFresh(r, f, time.Second)
	r.st.set(func(s *fakeStore) { s.rejectNote = false })
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	if got := losses(r, StageKernel); len(got) != 1 || got[0] != 4 {
		t.Fatalf("kernel losses %v", got)
	}
	if s, err := readSeen(path); err != nil || s.Lost != 4 {
		t.Fatalf("seen after the stop: %+v, %v", s, err)
	}
}

// The first auditd pid the collector sees in a boot is no restart.
func TestFirstPIDIsNoRestart(t *testing.T) {
	r := auditRig(t, newAuditFake(), seenPath(t), "boot")
	healthy(r)
	if health(r) != "OK" {
		t.Fatalf("health %q with the boot's first auditd", health(r))
	}
}

// A new auditd starts with its flag at no: its own overflow is a loss even when the last auditd's read yes.
func TestNewAuditdOverflowIsItsOwnLoss(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	healthy(r)
	f.set(func(f *auditFake) { f.overflow = true })
	stepFresh(r, f, 6*time.Second)
	r.step(0)
	f.set(func(f *auditFake) { f.report.Seq++; f.report.Status.PID = 0; f.stateErr = os.ErrNotExist })
	r.step(time.Second)
	f.set(func(f *auditFake) { f.report.Seq++; f.report.Status.PID = 200 })
	r.step(time.Second)
	f.set(func(f *auditFake) { f.stateErr = nil })
	stepFresh(r, f, 10*time.Second)
	r.step(0)
	if got := losses(r, StageDispatcher); len(got) != 2 {
		t.Fatalf("dispatcher losses %v, want one per auditd", got)
	}
}

// The same across a collector restart: the seen file's yes was auditd 100's, auditd 200 now reads yes.
func TestNewAuditdOverflowAcrossACollectorRestart(t *testing.T) {
	f := newAuditFake()
	path := seenPath(t)
	f.set(func(f *auditFake) { f.overflow = true })
	r := auditRig(t, f, path, "boot")
	stepFresh(r, f, 6*time.Second)
	r.step(0)
	if err := stopRig(r); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *auditFake) { f.report.Status.PID = 200 })
	r = auditRig(t, f, path, "boot")
	stepFresh(r, f, 10*time.Second)
	r.step(0)
	if got := losses(r, StageDispatcher); len(got) != 1 {
		t.Fatalf("dispatcher losses %v after the restart, want auditd 200's", got)
	}
}

// A loss record the store refused waits among notes, and stays out of the seen file until it is stored.
func TestSeenFileWaitsForARefusedLossNote(t *testing.T) {
	f := newAuditFake()
	path := seenPath(t)
	r := auditRig(t, f, path, "boot")
	healthy(r)
	stepFresh(r, f, time.Second)
	r.st.set(func(s *fakeStore) { s.rejectNote = true })
	f.set(func(f *auditFake) { f.report.Status.Lost = 4 })
	for range 4 {
		stepFresh(r, f, time.Second)
	}
	if s, err := readSeen(path); err != nil || s.Lost != 0 {
		t.Fatalf("seen holds a loss whose record waits among notes: %+v, %v", s, err)
	}
}

// 10 needs a fresh report: a stale one that last showed no auditd is 8.
func TestStaleReportWithoutAuditdIsStale(t *testing.T) {
	f := newAuditFake()
	r := auditRig(t, f, seenPath(t), "boot")
	healthy(r)
	stepFresh(r, f, 15*time.Second)
	f.set(func(f *auditFake) { f.report.Seq++; f.report.Status.PID = 0 })
	r.step(time.Second)
	for range 4 {
		f.set(func(f *auditFake) { f.mtime++ })
		r.step(5 * time.Second)
	}
	if health(r) != auditStale {
		t.Fatalf("health %q with a stale report of pid 0", health(r))
	}
}
