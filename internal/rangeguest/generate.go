package rangeguest

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Clock is the generator's time; tests replace it.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

type wallClock struct{}

func (wallClock) Now() time.Time        { return time.Now() }
func (wallClock) Sleep(d time.Duration) { time.Sleep(d) }

// WallClock is the real clock.
var WallClock Clock = wallClock{}

// window is the span in which a rate must hold (acceptance sustained_rate, burst_rate), and grace
// how late a number may be emitted and still count in the window it was due in: the sleep before it
// can overrun by a scheduler tick, which must not read as a rate not held.
const (
	window = 10 * time.Second
	grace  = 100 * time.Millisecond
)

// Generate emits 1, 2, ... rate × seconds through emit, one at a time, on a fixed schedule of rate
// per second, without pause while behind (ADR 0018, point 4). A number counts in the 10 s window it
// was due in if emitted at most grace after that window ends, else in the window it was emitted in;
// none is emitted later than grace after the schedule ends. It returns how many it emitted and the
// fewest counted in any window.
func Generate(rate, seconds int, emit func(seq uint64) error, clk Clock) (generated, windowMin uint64, err error) {
	if rate < 1 || seconds < 10 || seconds%10 != 0 {
		return 0, 0, errors.New("load must be a positive rate for whole 10 s windows")
	}
	span := time.Duration(seconds) * time.Second
	planned := uint64(rate) * uint64(seconds)
	counts := make([]uint64, seconds/10)
	start := clk.Now()
	for seq := uint64(1); seq <= planned; seq++ {
		due := time.Duration(seq-1) * time.Second / time.Duration(rate)
		elapsed := clk.Now().Sub(start)
		if elapsed >= span+grace {
			break
		}
		if due > elapsed {
			clk.Sleep(due - elapsed)
			elapsed = clk.Now().Sub(start)
		}
		if err := emit(seq); err != nil {
			return generated, 0, fmt.Errorf("event %d: %w", seq, err)
		}
		generated++
		w := int(due / window)
		if elapsed >= time.Duration(w+1)*window+grace {
			w = int(elapsed / window)
		}
		if w < len(counts) {
			counts[w]++
		}
	}
	windowMin = counts[0]
	for _, c := range counts {
		windowMin = min(windowMin, c)
	}
	return generated, windowMin, nil
}

// Execs starts /usr/bin/true with NumberPrefix and the number as its argument, at most limit at a
// time; its record is complete once exec returned, which os.StartProcess waits for.
type Execs struct {
	prog string
	sem  chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	errs []error
}

// NewExecs allows limit children at once.
func NewExecs(limit int) *Execs {
	return &Execs{prog: "/usr/bin/true", sem: make(chan struct{}, limit)}
}

// Emit starts one child for seq.
func (e *Execs) Emit(seq uint64) error {
	e.sem <- struct{}{}
	p, err := os.StartProcess(e.prog, []string{e.prog, NumberPrefix + strconv.FormatUint(seq, 10)}, &os.ProcAttr{})
	if err != nil {
		<-e.sem
		return fmt.Errorf("exec: %w", err)
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		st, err := p.Wait()
		if err == nil && !st.Success() {
			err = errors.New(st.String())
		}
		if err != nil {
			e.mu.Lock()
			e.errs = append(e.errs, err)
			e.mu.Unlock()
		}
		<-e.sem
	}()
	return nil
}

// Wait waits for every child and returns the first failure.
func (e *Execs) Wait() error {
	e.wg.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.errs) > 0 {
		return fmt.Errorf("%d execs failed, first: %w", len(e.errs), e.errs[0])
	}
	return nil
}

// Peek calls ptrace(PTRACE_PEEKDATA, NoPID, seq): no process has that pid, so it fails with ESRCH,
// and the audit rule without a success filter records it with seq as its third argument.
func Peek(seq uint64) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, PtracePeekData, NoPID, uintptr(seq), 0, 0, 0)
	if errno != syscall.ESRCH {
		return fmt.Errorf("ptrace: errno %d", int(errno))
	}
	return nil
}

// CPUTicks returns the total and steal ticks of all CPUs from /proc/stat: the sum of user through
// steal, and steal (guest time is already in user).
func CPUTicks(stat string) (total, steal uint64, err error) {
	line, _, _ := strings.Cut(stat, "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return 0, 0, errors.New("no cpu line in /proc/stat")
	}
	for i := 1; i <= 8; i++ {
		v, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("cpu field %d: %w", i, err)
		}
		total += v
		if i == 8 {
			steal = v
		}
	}
	return total, steal, nil
}

// TickDelta returns the total and steal ticks between two reads of /proc/stat; counters that went
// backwards are an error, never a small delta.
func TickDelta(before, after string) (total, steal uint64, err error) {
	t0, s0, err0 := CPUTicks(before)
	t1, s1, err1 := CPUTicks(after)
	switch {
	case errors.Join(err0, err1) != nil:
		return 0, 0, errors.Join(err0, err1)
	case t1 < t0 || s1 < s0:
		return 0, 0, errors.New("CPU tick counters went backwards")
	}
	return t1 - t0, s1 - s0, nil
}

// FreshState reads auditd's plugin-queue overflow flag from the state file at path, only once
// auditd rewrote it after signal asked it to: a file left from before would report "no" for an
// overflow it never saw, and auditd truncates the file before it writes it, so only "yes" or "no"
// ends the wait. No complete rewrite within wait reads "stale", which the host judges INVALID.
func FreshState(path string, signal func(), wait, poll time.Duration) string {
	old, errOld := os.Stat(path)
	signal()
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(poll) {
		now, err := os.Stat(path)
		if err != nil || errOld == nil && os.SameFile(old, now) && now.ModTime().Equal(old.ModTime()) && now.Size() == old.Size() {
			continue
		}
		data, err := os.ReadFile(path) //nolint:gosec // auditd's fixed state file, or a test's
		if v := OverflowDetected(string(data)); err == nil && (v == "yes" || v == "no") {
			return v
		}
	}
	return "stale"
}
