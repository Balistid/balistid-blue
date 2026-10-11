package rangevm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A trial adds exactly its name and phase as fw_cfg credentials; the drives do not change.
func TestQemuArgvWithATrial(t *testing.T) {
	plain := qemuArgv(false, false, "", 0)
	want := append(slices.Clone(plain[:len(plain)-2]),
		"-fw_cfg", "name=opt/io.systemd.credentials/balistid.trial,string=rate-burst",
		"-fw_cfg", "name=opt/io.systemd.credentials/balistid.phase,string=2",
		"-serial", "stdio")
	if got := qemuArgv(false, false, "rate-burst", 2); !slices.Equal(got, want) {
		t.Fatalf("trial argv:\n got %q\nwant %q", got, want)
	}
}

// A scratch disk is exactly one more writable file and one more raw drive, and nothing else.
func TestScratchDiskArgv(t *testing.T) {
	plain := sandboxArgv("/img/base.raw", "/cache/run-1", 123, false, "/usr/bin/true")
	at := slices.Index(plain, "--remount-ro")
	want := slices.Concat(plain[:at], []string{"--bind", "/cache/run-1/scratch.raw", "/range/run/scratch.raw"}, plain[at:])
	if got := sandboxArgv("/img/base.raw", "/cache/run-1", 123, true, "/usr/bin/true"); !slices.Equal(got, want) {
		t.Errorf("sandbox argv with scratch:\n got %q\nwant %q", got, want)
	}
	vm := qemuArgv(false, false, "", 0)
	wantVM := slices.Concat(vm[:len(vm)-2], []string{
		"-drive", "if=none,id=scratch,format=raw,file=/range/run/scratch.raw",
		"-device", "virtio-blk-pci,drive=scratch,serial=balistid-scratch",
	}, vm[len(vm)-2:])
	if got := qemuArgv(false, true, "", 0); !slices.Equal(got, wantVM) {
		t.Errorf("qemu argv with scratch:\n got %q\nwant %q", got, wantVM)
	}
}

// The self-test and exec jobs keep their limits (ADR 0018, point 2).
func TestRunLimitsAreUnchanged(t *testing.T) {
	if want := (Limits{Wall: 10 * time.Minute, Serial: 1 << 20, Boots: 1}); runLimits != want {
		t.Errorf("runLimits = %+v, want %+v", runLimits, want)
	}
}

func TestDiskNeedCountsEveryFileQEMUCanWrite(t *testing.T) {
	base := int64(1 << 30)
	if got, want := runLimits.DiskNeed(base), 3*WriteCap(base); got != want {
		t.Errorf("without scratch: %d, want %d", got, want)
	}
	small := Limits{Scratch: 1 << 20}
	if got, want := small.DiskNeed(base), 4*WriteCap(base); got != want {
		t.Errorf("small scratch: %d, want %d", got, want)
	}
	big := Limits{Scratch: 4 << 30}
	if got, want := big.DiskNeed(base), int64(4*(4<<30)); got != want {
		t.Errorf("scratch over the cap: %d, want %d", got, want)
	}
}

func TestRunTrialRefusesLimitsOutsideTheirRange(t *testing.T) {
	ok := Limits{Trial: "reset-crash", Wall: time.Minute, Serial: 1 << 20, Boots: 2}
	cases := map[string]func(*Limits){
		"empty name":       func(l *Limits) { l.Trial = "" },
		"upper case":       func(l *Limits) { l.Trial = "Reset" },
		"option comma":     func(l *Limits) { l.Trial = "a,file=/etc/shadow" },
		"path":             func(l *Limits) { l.Trial = "../x" },
		"33 characters":    func(l *Limits) { l.Trial = strings.Repeat("a", 33) },
		"no wall clock":    func(l *Limits) { l.Wall = 0 },
		"setup over batch": func(l *Limits) { l.Wall = 30*time.Minute - setupTimeout + time.Second },
		"no serial":        func(l *Limits) { l.Serial = 0 },
		"negative serial":  func(l *Limits) { l.Serial = -1 },
		"no boot":          func(l *Limits) { l.Boots = 0 },
		"three boots":      func(l *Limits) { l.Boots = 3 },
		"negative scratch": func(l *Limits) { l.Scratch = -1 },
		"huge scratch":     func(l *Limits) { l.Scratch = MaxScratch + 1 },
	}
	for name, edit := range cases {
		lim := ok
		edit(&lim)
		_, err := RunTrial(t.Context(), "/nonexistent", t.TempDir(), io.Discard, lim)
		if err == nil || strings.Contains(err.Error(), "base image") {
			t.Errorf("%s: %v, want the limits refused before the run", name, err)
		}
		if err != nil && lim.Trial != "" && strings.Contains(err.Error(), lim.Trial) {
			t.Errorf("%s: error quotes the name: %v", name, err)
		}
	}
	if _, err := RunTrial(t.Context(), "/nonexistent", t.TempDir(), io.Discard, ok); err == nil || !strings.Contains(err.Error(), "base image") {
		t.Errorf("valid limits: %v, want only the missing base image", err)
	}
}

// bootCall is what one QEMU boot was given.
type bootCall struct {
	phase    string
	zeroed   bool
	timeout  time.Duration
	budget   int64
	deadline time.Time
	argv     []string
}

// fakeVM stands in for qemu-img and QEMU: boot i notes what it was given, then writes streams[i]
// to the results disk.
type fakeVM struct {
	streams [][]byte
	boots   []bootCall
	overlay []string
}

func (f *fakeVM) run(ctx context.Context, argv []string, timeout time.Duration, budget int64, _ io.Writer) string {
	if !slices.Contains(argv, qemuPath) {
		f.overlay = argv
		return ""
	}
	c := bootCall{phase: "none", timeout: timeout, budget: budget, argv: argv}
	for _, a := range argv {
		if v, ok := strings.CutPrefix(a, "name=opt/io.systemd.credentials/balistid.phase,string="); ok {
			c.phase = v
		}
	}
	c.deadline, _ = ctx.Deadline()
	path := argv[slices.Index(argv, inRun+"/"+results)-1]
	data, err := os.ReadFile(path) //nolint:gosec // the test's run directory
	c.zeroed = err == nil && len(data) == ResultsBytes && len(bytes.Trim(data, "\x00")) == 0
	f.boots = append(f.boots, c)
	i := len(f.boots) - 1
	if i >= len(f.streams) {
		return "exit: exit status 1"
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // the test's run directory
	if err != nil {
		return "exit: " + err.Error()
	}
	defer w.Close() //nolint:errcheck // test
	if _, err := w.WriteAt(f.streams[i], 0); err != nil {
		return "exit: " + err.Error()
	}
	return ""
}

func runFake(t *testing.T, lim Limits, run command) (Outcome, time.Time) {
	t.Helper()
	dir := t.TempDir()
	base, vars := filepath.Join(dir, "base.raw"), filepath.Join(dir, "vars.fd")
	for _, p := range []string{base, vars} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runs := filepath.Join(dir, "runs")
	if err := os.Mkdir(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, err := boot(t.Context(), base, runs, io.Discard, nil, lim, run, vars)
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(runs); len(left) != 0 {
		t.Errorf("run directory left behind: %v", left)
	}
	return out, start
}

// echo is how a trial boot opens its facts.
func echo(trial string, phase int) []Record {
	return []Record{fact(FactTrial, trial), fact(FactPhase, strconv.Itoa(phase))}
}

func facts(t *testing.T, recs ...Record) []byte {
	t.Helper()
	return stream(t, append(recs, end(len(recs)))...)
}

var resetTrial = Limits{Trial: "reset-crash", Wall: 7 * time.Minute, Serial: 3 << 20, Boots: 2}

func TestArmedResetBootsTheSameRunAgainOnAZeroedDisk(t *testing.T) {
	vm := &fakeVM{streams: [][]byte{
		facts(t, append(echo("reset-crash", 1), fact("acked", "41"), fact(FactResetArmed, "yes"))...),
		facts(t, append(echo("reset-crash", 2), fact("stored", "40"))...),
	}}
	out, start := runFake(t, resetTrial, vm.run)
	if out.Invalid != "" {
		t.Fatalf("Invalid = %q", out.Invalid)
	}
	if len(vm.boots) != 2 || len(out.FirstBoot) != 4 || out.FirstBoot[2].Value != "41" || out.Facts[2].Value != "40" {
		t.Fatalf("%d boots, FirstBoot %v, Facts %v", len(vm.boots), out.FirstBoot, out.Facts)
	}
	for i, b := range vm.boots {
		if b.phase != strconv.Itoa(i+1) || !b.zeroed || b.timeout != resetTrial.Wall || b.budget != resetTrial.Serial {
			t.Errorf("boot %d: %+v", i+1, b)
		}
		if d := b.deadline.Sub(start); d < resetTrial.Wall || d > resetTrial.Wall+time.Second {
			t.Errorf("boot %d deadline %s after start, want the trial's wall clock %s", i+1, d, resetTrial.Wall)
		}
	}
	if !vm.boots[0].deadline.Equal(vm.boots[1].deadline) {
		t.Errorf("deadlines %s and %s: one wall clock must bound both boots", vm.boots[0].deadline, vm.boots[1].deadline)
	}
}

func TestNoSecondBootWithoutAnEchoedArmedFirstBoot(t *testing.T) {
	for name, first := range map[string][]byte{
		"not armed":        facts(t, append(echo("reset-crash", 1), fact("acked", "41"))...),
		"armed with no":    facts(t, append(echo("reset-crash", 1), fact(FactResetArmed, "no"))...),
		"armed twice":      facts(t, append(echo("reset-crash", 1), fact(FactResetArmed, "no"), fact(FactResetArmed, "yes"))...),
		"no echo":          facts(t, fact(FactResetArmed, "yes")),
		"wrong trial":      facts(t, append(echo("rate-burst", 1), fact(FactResetArmed, "yes"))...),
		"wrong phase":      facts(t, append(echo("reset-crash", 2), fact(FactResetArmed, "yes"))...),
		"stream truncated": stream(t, append(echo("reset-crash", 1), fact(FactResetArmed, "yes"))...),
	} {
		vm := &fakeVM{streams: [][]byte{first, facts(t, echo("reset-crash", 2)...)}}
		out, _ := runFake(t, resetTrial, vm.run)
		if out.Invalid == "" || len(vm.boots) != 1 {
			t.Errorf("%s: Invalid %q after %d boots, want INVALID after one", name, out.Invalid, len(vm.boots))
		}
	}
}

func TestSecondBootMustEchoAndFinish(t *testing.T) {
	armedFirst := facts(t, append(echo("reset-crash", 1), fact(FactResetArmed, "yes"))...)
	for name, second := range map[string][][]byte{
		"exits badly":  nil,
		"echoes 1":     {facts(t, echo("reset-crash", 1)...)},
		"no echo":      {facts(t, fact("stored", "40"))},
		"empty stream": {facts(t)},
	} {
		vm := &fakeVM{streams: append([][]byte{armedFirst}, second...)}
		out, _ := runFake(t, resetTrial, vm.run)
		if out.Invalid == "" || len(out.FirstBoot) != 3 || len(vm.boots) != 2 {
			t.Errorf("%s: Invalid %q, FirstBoot %v, %d boots", name, out.Invalid, out.FirstBoot, len(vm.boots))
		}
	}
}

// Run boots once with its own limits, no fw_cfg credentials and no scratch disk; a one-boot trial
// boots once as well.
func TestOneBootRuns(t *testing.T) {
	for name, c := range map[string]struct {
		lim    Limits
		stream []byte
		phase  string
	}{
		"plain": {runLimits, facts(t, fact(FactResetArmed, "yes")), "none"},
		"trial": {Limits{Trial: "rate-burst", Wall: time.Minute, Serial: 1 << 20, Boots: 1}, facts(t, echo("rate-burst", 1)...), "1"},
	} {
		vm := &fakeVM{streams: [][]byte{c.stream, facts(t)}}
		out, _ := runFake(t, c.lim, vm.run)
		if out.Invalid != "" || out.FirstBoot != nil || len(vm.boots) != 1 || vm.boots[0].phase != c.phase {
			t.Fatalf("%s: Invalid %q, FirstBoot %v, boots %+v", name, out.Invalid, out.FirstBoot, vm.boots)
		}
		b := vm.boots[0]
		if b.timeout != c.lim.Wall || b.budget != c.lim.Serial {
			t.Errorf("%s: timeout %s budget %d", name, b.timeout, b.budget)
		}
		if c.lim.Trial == "" && slices.ContainsFunc(b.argv, func(a string) bool {
			return strings.Contains(a, "scratch") || strings.Contains(a, "credentials")
		}) {
			t.Errorf("plain run argv has a scratch disk or credential: %q", b.argv)
		}
	}
}

// The boots share the scratch disk, sized as asked, and prlimit lets QEMU write all of it; the
// overlay step gets neither the scratch disk nor its cap.
func TestScratchDiskOutlivesTheResetAndFitsTheSizeCap(t *testing.T) {
	lim := resetTrial
	lim.Scratch = 64 << 20
	vm := &fakeVM{streams: [][]byte{
		facts(t, append(echo("reset-crash", 1), fact(FactResetArmed, "yes"))...),
		facts(t, echo("reset-crash", 2)...),
	}}
	var sizes []int64
	var marks []bool
	out, _ := runFake(t, lim, func(ctx context.Context, argv []string, d time.Duration, b int64, w io.Writer) string {
		if slices.Contains(argv, qemuPath) {
			path := argv[slices.Index(argv, inRun+"/"+scratch)-1]
			data, err := os.ReadFile(path) //nolint:gosec // the test's run directory
			if err != nil {
				return "exit: no scratch disk"
			}
			sizes = append(sizes, int64(len(data)))
			marks = append(marks, data[4096] == 'x')
			if err := os.WriteFile(path, append(data[:4096:4096], append([]byte{'x'}, data[4097:]...)...), 0o600); err != nil { //nolint:gosec // the test's run directory
				return "exit: " + err.Error()
			}
		}
		return vm.run(ctx, argv, d, b, w)
	})
	if out.Invalid != "" {
		t.Fatalf("Invalid = %q", out.Invalid)
	}
	if !slices.Equal(sizes, []int64{lim.Scratch, lim.Scratch}) || !slices.Equal(marks, []bool{false, true}) {
		t.Errorf("scratch sizes %v, earlier boot's write seen %v; want the same disk in both boots", sizes, marks)
	}
	want := fmt.Sprintf("--fsize=%d", lim.Scratch)
	for i, b := range vm.boots {
		if b.argv[1] != want {
			t.Errorf("boot %d prlimit %s, want %s", i+1, b.argv[1], want)
		}
	}
	if slices.Contains(vm.overlay, inRun+"/"+scratch) || vm.overlay[1] != fmt.Sprintf("--fsize=%d", WriteCap(1)) {
		t.Errorf("overlay step argv %q: want no scratch disk and the plain cap", vm.overlay)
	}
}
