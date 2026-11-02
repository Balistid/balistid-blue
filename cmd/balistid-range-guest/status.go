package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// The CLI as the image installs it, the unprivileged account it runs as, like an agent at the maintainer's uid,
// how long a break or a recovery may take to show, and how often the CLI is asked meanwhile.
const (
	statusCLI    = "/usr/local/bin/balistid"
	statusUser   = "balistid-job"
	statusWait   = 2 * time.Minute
	statusPoll   = 2 * time.Second
	maxStatusOut = 16 << 10
)

// statusRun is one measured run of the CLI: its exit and output, the guest's proof that the break held from
// before it to after it ("yes" or why not), when it returned, and the health the store must show then.
type statusRun struct {
	exit  int
	out   []byte
	proof string
	end   int64
	want  string // "OK", "UNKNOWN" or "" for a stopped unit, whose collector may be the stopped one
}

// cliRun runs the CLI once: its exit and output, or why it did not run to an exit.
type cliRun func(ctx context.Context) (int, []byte, error)

// runStatus breaks each floor-0 part in turn and runs the CLI unprivileged after each (status_false_ok, ADR 0048),
// then reads the store once, which stops the collector, for the health at each run's end.
func runStatus(ctx context.Context, r *report) error {
	cred, err := credential(statusUser)
	if err != nil {
		return r.fail(err.Error())
	}
	r.add(rangevm.FactStatusUID, strconv.FormatUint(uint64(cred.Uid), 10))
	r.add(rangevm.FactUnitsInstalled, balistidUnits(ctx))
	cli := func(ctx context.Context) (int, []byte, error) { return runCLI(ctx, cred) }
	runs := rangevm.StatusRuns()
	done := make([]statusRun, 0, len(runs))
	for _, run := range runs {
		res, err := breakAndRun(ctx, run, cli)
		if err != nil {
			return r.fail(run.Name + ": " + err.Error())
		}
		done = append(done, res)
	}
	var timeline healthTimeline
	if err := readStore(ctx, timeline.add, timeline.add); err != nil {
		return r.fail("store: " + err.Error())
	}
	for i, run := range runs {
		res := done[i]
		if res.proof == "yes" && res.want != "" {
			res.proof = timeline.proves(res.end, res.want)
		}
		r.add(rangevm.FactStatusRun+run.Name, fmt.Sprintf("%d %s %s", res.exit, base64.StdEncoding.EncodeToString(res.out), res.proof))
	}
	return r.send(r.facts)
}

// breakAndRun waits for a healthy floor, breaks what run names, runs the CLI between two proofs of the break,
// and undoes the break. A frozen process is shown only through the health, so the CLI is first asked until it
// shows not OK, at most statusWait: one that never does is measured anyway, and the judge sees it OK.
func breakAndRun(ctx context.Context, run rangevm.StatusRun, cli cliRun) (statusRun, error) {
	if err := untilCLI(ctx, cli, 0); err != nil {
		return statusRun{}, fmt.Errorf("the floor did not show healthy before the run: %w", err)
	}
	switch run.Kind {
	case rangevm.StatusHealthy:
		return measure(ctx, cli, func() string { return unitsActive(ctx) }, "OK"), nil
	case rangevm.StatusStopUnit:
		if err := systemctl(ctx, "mask", "--runtime", run.Name); err != nil {
			return statusRun{}, err
		}
		stopErr := systemctl(ctx, "stop", run.Name)
		res := measure(ctx, cli, func() string { return unitStopped(ctx, run.Name) }, "")
		if err := errors.Join(stopErr, restoreUnits(ctx, run.Name)); err != nil {
			return statusRun{}, err
		}
		return res, nil
	case rangevm.StatusFreezeAuditd, rangevm.StatusFreezeLaurel:
		pid, err := frozenTarget(ctx, run.Kind)
		if err != nil {
			return statusRun{}, err
		}
		if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
			return statusRun{}, fmt.Errorf("SIGSTOP %d: %w", pid, err)
		}
		_ = untilCLI(ctx, cli, 1) // a CLI that never shows the break is measured, not skipped
		res := measure(ctx, cli, func() string { return processStopped(pid) }, "UNKNOWN")
		if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
			return statusRun{}, fmt.Errorf("SIGCONT %d: %w", pid, err)
		}
		return res, nil
	}
	return statusRun{}, fmt.Errorf("no break of kind %s", run.Kind)
}

// measure runs the CLI once between two proofs; a CLI that did not exit is a proof that fails.
func measure(ctx context.Context, cli cliRun, prove func() string, want string) statusRun {
	before := prove()
	exit, out, err := cli(ctx)
	res := statusRun{exit: exit, out: out, end: time.Now().UnixNano(), want: want}
	after := prove()
	switch {
	case err != nil:
		res.proof = "the CLI did not run: " + err.Error()
	case before != "yes":
		res.proof = "before: " + before
	case after != "yes":
		res.proof = "after: " + after
	default:
		res.proof = "yes"
	}
	return res
}

// untilCLI asks the CLI until it exits with want, at most statusWait; a timeout names the parts it last showed not OK.
func untilCLI(ctx context.Context, cli cliRun, want int) error {
	deadline := time.Now().Add(statusWait)
	for {
		exit, out, err := cli(ctx)
		if err == nil && exit == want {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.Join(fmt.Errorf("the CLI did not exit %d within %s (last %d, not OK: %s)", want, statusWait, exit,
				notOK(out)), err)
		}
		if !pause(ctx, statusPoll) {
			return fmt.Errorf("waiting for the CLI: %w", ctx.Err())
		}
	}
}

// notOK lists the parts of the CLI's JSON that are not OK with their detail, or why it does not read.
func notOK(out []byte) string {
	var res struct {
		Parts []struct{ Part, State, Detail string }
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "unreadable output"
	}
	var bad []string
	for _, p := range res.Parts {
		if p.State != "OK" {
			bad = append(bad, fmt.Sprintf("%s %s %q", p.Part, p.State, p.Detail))
		}
	}
	return strings.Join(bad, ", ")
}

// runCLI runs `balistid status --json` as cred with an empty environment and returns its exit and output.
func runCLI(ctx context.Context, cred *syscall.Credential) (int, []byte, error) {
	cmd := exec.CommandContext(ctx, statusCLI, "status", "--json")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	cmd.Env, cmd.Dir = []string{}, "/"
	out, err := cmd.Output()
	var exitErr *exec.ExitError
	switch {
	case len(out) > maxStatusOut:
		return 0, nil, fmt.Errorf("%d bytes of output", len(out))
	case err == nil:
		return 0, out, nil
	case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
		return exitErr.ExitCode(), out, nil
	}
	return 0, nil, fmt.Errorf("balistid status: %w", err)
}

// restoreUnits unmasks the stopped unit and starts every floor-0 unit but auditd, which was never stopped.
func restoreUnits(ctx context.Context, unit string) error {
	units := slices.DeleteFunc(rangevm.StatusUnits(), func(u string) bool { return u == auditdUnitName })
	return errors.Join(systemctl(ctx, "unmask", "--runtime", unit), systemctl(ctx, "reset-failed"),
		systemctl(ctx, append([]string{"start"}, units...)...))
}

// unitsActive is "yes" when every floor-0 unit is active, else the first that is not.
func unitsActive(ctx context.Context) string {
	for _, u := range rangevm.StatusUnits() {
		if s := activeState(ctx, u); s != "active" {
			return fmt.Sprintf("%s is %q", u, s)
		}
	}
	return "yes"
}

// unitStopped is "yes" while unit is inactive or failed, never on its way up or down.
func unitStopped(ctx context.Context, unit string) string {
	if s := activeState(ctx, unit); s != "inactive" && s != "failed" {
		return fmt.Sprintf("%s is %q", unit, s)
	}
	return "yes"
}

func activeState(ctx context.Context, unit string) string {
	return strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", unit))
}

// frozenTarget is auditd's main pid or Laurel's, found as auditd's child.
func frozenTarget(ctx context.Context, kind string) (int, error) {
	v := laurelPID()
	if kind == rangevm.StatusFreezeAuditd {
		v = strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "MainPID", auditdUnitName))
	}
	pid, err := strconv.Atoi(v)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("no pid for %s: %q", kind, v)
	}
	return pid, nil
}

// processStopped is "yes" while pid is stopped by a signal.
func processStopped(pid int) string {
	state := rangeguest.StatusField(readTrim(fmt.Sprintf("/proc/%d/status", pid)), "State")
	if !strings.HasPrefix(state, "T") {
		return fmt.Sprintf("pid %d is %q", pid, state)
	}
	return "yes"
}

// balistidUnits lists the image's balistid unit files, comma-separated, for the judge to compare with its own.
func balistidUnits(ctx context.Context) string {
	var units []string
	for _, line := range strings.Split(output(ctx, "/usr/bin/systemctl", "list-unit-files", "--no-legend", "--plain", "balistid-*"), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			units = append(units, f[0])
		}
	}
	slices.Sort(units)
	return strings.Join(units, ",")
}

// healthTimeline is the collector's health records in the store, in the order it wrote them.
type healthTimeline []health

func (t *healthTimeline) add(x rawrecord.Record) error {
	if h, ok := decodeHealth(x.Data); ok && healthKind(x) == "health" {
		*t = append(*t, h)
	}
	return nil
}

// proves is "yes" when the last health the collector recorded at or before end is want (OK, or any UNKNOWN).
func (t healthTimeline) proves(end int64, want string) string {
	last := ""
	for _, h := range t {
		if h.at > 0 && h.at <= end {
			last = h.state
		}
	}
	switch {
	case last == "":
		return "no health stored before the run"
	case want == "OK" && last == "OK", want == "UNKNOWN" && strings.HasPrefix(last, "UNKNOWN"):
		return "yes"
	}
	return fmt.Sprintf("the store's health was %q", last)
}
