package rangerun

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// requireFilterTest names the env variable CI sets: there a missing python3, or an environment that
// masks every probed call, fails the test instead of skipping it, so the regression stays guarded.
const requireFilterTest = "BALISTID_REQUIRE_SECCOMP_TEST"

// filterChild names the env variable that makes the test binary a child that reports what
// filterInForce says. The parent runs it under a seccomp filter denying the listed syscall numbers
// with EPERM, as the tick unit's filter does.
const filterChild = "BALISTID_FILTER_CHILD"

// unitDenials is what the tick unit denies, one call per clause of its SystemCallFilter=~ line and
// ptrace, which no allowed group holds, kept apart from filterProbes so the test checks the tripwire
// against the unit, not against itself.
var unitDenials = []struct {
	clause, name string
	nr           uintptr
}{
	{"@keyring", "keyctl", syscall.SYS_KEYCTL},
	{"@aio", "io_setup", syscall.SYS_IO_SETUP},
	{"process_vm_readv", "process_vm_readv", 310},
	{"process_vm_writev", "process_vm_writev", 311},
	{"", "ptrace", syscall.SYS_PTRACE},
}

// The tripwire is checked at runtime, not only by its labels: under a filter that denies every call
// the unit denies it passes, and under one that misses any single call it stops the tick (Codex,
// #107 round 1).
func TestFilterInForceUnderARealFilter(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the probes are x86-64 syscall numbers")
	}
	var clauses []string
	for _, d := range unitDenials {
		clauses = append(clauses, d.clause)
	}
	for _, c := range append(deniedClauses(t), "") {
		if !slices.Contains(clauses, c) {
			t.Fatalf("unitDenials misses the unit's clause %q", c)
		}
	}
	all := make([]string, 0, len(unitDenials))
	for _, d := range unitDenials {
		all = append(all, strconv.FormatUint(uint64(d.nr), 10))
	}
	// A call the outer environment (a sandbox, a container) already answers with EPERM cannot show
	// that its own denial is checked; its missing-denial case is skipped, never passed.
	masked := child(t, "probe", nil)
	if out := child(t, "filter", all); out != "ok" {
		t.Fatalf("under the full filter: %s", out)
	}
	checked := 0
	defer func() {
		if checked == 0 && !t.Failed() {
			t.Fatal("every probed call is already denied here: no missing denial could be checked")
		}
	}()
	for i, d := range unitDenials {
		if slices.Contains(strings.Fields(masked), d.name) {
			t.Logf("%s: the environment already denies it; not checked", d.name)
			continue
		}
		checked++
		rest := slices.Delete(slices.Clone(all), i, i+1)
		if out := child(t, "filter", rest); out == "ok" {
			t.Errorf("a filter without %s: filterInForce passed", d.name)
		}
	}
}

// child runs the test binary as a filter child: mode probe reports which calls already get EPERM;
// mode filter runs filterInForce under a seccomp filter denying nrs, which tools/ci/seccomp_exec.py
// installs before it execs the child (the filter is passed by pointer, and Go here may not use unsafe).
func child(t *testing.T, mode string, nrs []string) string {
	t.Helper()
	argv := []string{os.Args[0], "-test.run=^TestFilterChild$"}
	if mode == "filter" {
		python, err := exec.LookPath("python3")
		if err != nil {
			if os.Getenv(requireFilterTest) != "" {
				t.Fatalf("python3 is not installed, and %s requires this test", requireFilterTest)
			}
			t.Skip("python3 is not installed: the filter cannot be applied without unsafe")
		}
		argv = append([]string{python, filepath.Join("..", "..", "tools", "ci", "seccomp_exec.py"), strings.Join(nrs, ",")}, argv...)
	}
	cmd := exec.CommandContext(t.Context(), argv[0], argv[1:]...) //nolint:gosec // python3 and the test binary itself
	cmd.Env = append(os.Environ(), filterChild+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("filter child %s: %v: %s", mode, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestFilterChild is the child's body; run on its own it does nothing.
func TestFilterChild(t *testing.T) {
	spec, ok := os.LookupEnv(filterChild)
	if !ok {
		return
	}
	if spec == "probe" {
		var b strings.Builder
		b.WriteString("masked: ")
		// Unfiltered, each call fails on its arguments (no such keyctl or ptrace request, a bad
		// pointer, flags 1); only an outer filter answers EPERM.
		for _, d := range unitDenials {
			if _, _, e := syscall.Syscall6(d.nr, uintptr(os.Getpid()), 0x7fffffff, 0, 0, 0, 1); e == syscall.EPERM {
				b.WriteString(d.name + " ")
			}
		}
		_, _ = os.Stdout.WriteString(b.String() + "\n")
		os.Exit(0)
	}
	if err := filterInForce(); err != nil {
		_, _ = os.Stdout.WriteString(err.Error() + "\n")
	} else {
		_, _ = os.Stdout.WriteString("ok\n")
	}
	os.Exit(0)
}
