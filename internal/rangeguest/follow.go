package rangeguest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Numbered events of a trial's generator (ADR 0018, point 4): exec argv carries NumberPrefix and
// the number; ptrace(PTRACE_PEEKDATA) of the pid no process has carries it as the address.
const (
	NumberPrefix   = "balistid-n-"
	PtracePeekData = 2
	NoPID          = 0x7fffffff
	sysPtrace      = 101 // x86-64
	// MaxNumber caps what a reader keeps; higher numbers count as outside the generated set.
	MaxNumber = 1 << 24
	// generations is how far back a rotated log is looked for: deploy/laurel/config.toml keeps 10.
	generations = 10
)

// Numbers is the set of numbers a reader found, with every repeat and every record outside 1..MaxNumber
// or unreadable as a number counted.
type Numbers struct {
	bits      []uint64
	duplicate uint64
	outside   uint64
}

// Add records one number found in one record.
func (n *Numbers) Add(seq uint64) {
	if seq == 0 || seq > MaxNumber {
		n.outside++
		return
	}
	w := int(seq / 64)
	if w >= len(n.bits) {
		n.bits = append(n.bits, make([]uint64, w+1-len(n.bits))...)
	}
	if n.bits[w]&(1<<(seq%64)) != 0 {
		n.duplicate++
		return
	}
	n.bits[w] |= 1 << (seq % 64)
}

// Count compares the set with 1..generated: stored once, missing, repeated, and outside the set.
func (n *Numbers) Count(generated uint64) (stored, missing, duplicate, outside uint64) {
	var all uint64
	for _, w := range n.bits {
		all += uint64(bits.OnesCount64(w)) //nolint:gosec // a count of 0 to 64
	}
	for seq := uint64(1); seq <= generated && seq <= MaxNumber; seq++ {
		w := int(seq / 64)
		if w < len(n.bits) && n.bits[w]&(1<<(seq%64)) != 0 {
			stored++
		}
	}
	return stored, generated - stored, n.duplicate, n.outside + all - stored
}

// Follower reads a trial's numbered events from Laurel's log, from Start on and across rotation, so
// nothing the generator caused is lost to a file that was renamed meanwhile. It is the baseline
// reader: the collector's store reader replaces it for runs that pass a metric.
type Follower struct {
	tail logTail
	kind string
	skip uint64
	poll time.Duration

	mu      sync.Mutex
	nums    Numbers
	barrier string
	seen    bool
	err     error
	stop    chan struct{}
	stopped chan struct{}
}

// NewFollower follows the Laurel log at path for events of the load kind; skip, if not 0, is one
// number it drops on purpose, a control that must miss.
func NewFollower(path, kind string, skip uint64) *Follower {
	return &Follower{tail: logTail{path: path}, kind: kind, skip: skip, poll: 10 * time.Millisecond}
}

// Start opens the log at its end and follows it until Finish.
func (fl *Follower) Start() error {
	if fl.kind != rangejob.LoadExec && fl.kind != rangejob.LoadPtrace {
		return fmt.Errorf("unknown load %q", fl.kind)
	}
	if err := fl.tail.openAtEnd(); err != nil {
		return err
	}
	fl.stop, fl.stopped = make(chan struct{}), make(chan struct{})
	go fl.follow()
	return nil
}

// Finish runs mark, which must exec /usr/bin/true with barrier as an argument, and returns the
// numbers found once that exec's record arrives: Laurel writes events in order, so everything before
// it is then in the log (ADR 0018, point 4). No barrier within wait is an error.
func (fl *Follower) Finish(barrier string, mark func() error, wait time.Duration) (*Numbers, error) {
	fl.mu.Lock()
	fl.barrier = barrier
	fl.mu.Unlock()
	markErr := mark()
	deadline := time.Now().Add(wait)
	for markErr == nil && time.Now().Before(deadline) {
		fl.mu.Lock()
		done := fl.seen || fl.err != nil
		fl.mu.Unlock()
		if done {
			break
		}
		time.Sleep(fl.poll)
	}
	close(fl.stop)
	<-fl.stopped
	fl.tail.close()
	fl.mu.Lock()
	defer fl.mu.Unlock()
	switch {
	case markErr != nil:
		return nil, fmt.Errorf("barrier: %w", markErr)
	case fl.err != nil:
		return nil, fl.err
	case !fl.seen:
		return nil, errors.New("barrier missing")
	}
	return &fl.nums, nil
}

func (fl *Follower) follow() {
	defer close(fl.stopped)
	for {
		line, err := fl.tail.line()
		if err != nil {
			fl.mu.Lock()
			fl.err = err
			fl.mu.Unlock()
			return
		}
		if line == nil {
			select {
			case <-fl.stop:
				return
			case <-time.After(fl.poll):
			}
			continue
		}
		fl.mu.Lock()
		fl.record(line)
		seen := fl.seen
		fl.mu.Unlock()
		if seen {
			return // the run ends at the barrier; later records are not part of it
		}
	}
}

// record adds the numbers of one Laurel line. Laurel writes upper- and lower-case keys side by side
// (enrichment), so lines are read as maps, never into structs that match names case-insensitively.
func (fl *Follower) record(line []byte) {
	if fl.barrier != "" && bytes.Contains(line, []byte(fl.barrier)) && slices.Contains(execArgs(line), fl.barrier) {
		fl.seen = true
		return
	}
	var nums []uint64
	ok := true
	switch fl.kind {
	case rangejob.LoadExec:
		if !bytes.Contains(line, []byte(NumberPrefix)) {
			return
		}
		nums, ok = execNumbers(line)
	case rangejob.LoadPtrace:
		if !bytes.Contains(line, []byte(`"balistid-inject"`)) {
			return
		}
		nums, ok = ptraceNumber(line)
	}
	if !ok {
		fl.nums.outside++
	}
	for _, n := range nums {
		if n == fl.skip && fl.skip != 0 {
			fl.skip = 0
			continue
		}
		fl.nums.Add(n)
	}
}

// execArgs returns the EXECVE argv of a Laurel line (null arguments as ""), or nil.
func execArgs(line []byte) []string {
	var ev map[string]json.RawMessage
	var execve map[string]json.RawMessage
	var argv []*string
	if json.Unmarshal(line, &ev) != nil || json.Unmarshal(ev["EXECVE"], &execve) != nil ||
		json.Unmarshal(execve["ARGV"], &argv) != nil {
		return nil
	}
	args := make([]string, len(argv))
	for i, a := range argv {
		if a != nil {
			args[i] = *a
		}
	}
	return args
}

// execNumbers returns every argument of the EXECVE record that is NumberPrefix and a plain decimal;
// ok is false when the line names the prefix and has none, or one that is not a plain number.
func execNumbers(line []byte) (nums []uint64, ok bool) {
	ok = true
	for _, a := range execArgs(line) {
		digits, found := strings.CutPrefix(a, NumberPrefix)
		if !found {
			continue
		}
		n, err := strconv.ParseUint(digits, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != digits {
			ok = false
			continue
		}
		nums = append(nums, n)
	}
	return nums, ok && len(nums) > 0
}

// ptraceNumber returns the address of a PEEKDATA of NoPID recorded under the balistid-inject key.
// Laurel writes the registers as SYSCALL.ARGV, lower-case hex with a 0x prefix.
func ptraceNumber(line []byte) ([]uint64, bool) {
	var ev, sc map[string]json.RawMessage
	var key string
	var argv []string
	if json.Unmarshal(line, &ev) != nil || json.Unmarshal(ev["SYSCALL"], &sc) != nil ||
		json.Unmarshal(sc["key"], &key) != nil || key != "balistid-inject" {
		return nil, true // another record that only mentions the key
	}
	if json.Unmarshal(sc["ARGV"], &argv) != nil || len(argv) < 3 {
		return nil, false
	}
	if string(sc["syscall"]) != strconv.Itoa(sysPtrace) || argv[0] != "0x"+strconv.FormatUint(PtracePeekData, 16) ||
		argv[1] != "0x"+strconv.FormatUint(NoPID, 16) {
		return nil, true // ptrace that is not the generator's
	}
	digits, found := strings.CutPrefix(argv[2], "0x")
	n, err := strconv.ParseUint(digits, 16, 64)
	if !found || err != nil || strconv.FormatUint(n, 16) != digits {
		return nil, false
	}
	return []uint64{n}, true
}

// logTail reads whole lines of a log that Laurel rotates by renaming path to path.1, path.1 to
// path.2 and so on, and creates anew on its next write. A rotated file is read to its end before
// the one renamed right after it, so a reader that fell behind by several rotations still reads
// every file in order; one that fell behind past the last generation, a truncated file or a cut
// line is an error, never a silent gap.
type logTail struct {
	path   string
	f      *os.File
	offset int64
	buf    []byte
}

func (t *logTail) openAtEnd() error {
	f, err := os.Open(t.path)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("seek log: %w", err)
	}
	t.f, t.offset = f, off
	return nil
}

func (t *logTail) close() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}

// line returns the next whole line without its newline, or nil when there is none yet.
func (t *logTail) line() ([]byte, error) {
	for {
		i := bytes.IndexByte(t.buf, '\n')
		if i > maxLine || i < 0 && len(t.buf) > maxLine {
			return nil, fmt.Errorf("log line over %d bytes", maxLine)
		}
		if i >= 0 {
			line := t.buf[:i]
			t.buf = t.buf[i+1:]
			return line, nil
		}
		n, err := t.read()
		if err != nil {
			return nil, err
		}
		if n > 0 {
			continue
		}
		moved, err := t.next()
		if err != nil || !moved {
			return nil, err
		}
	}
}

func (t *logTail) read() (int, error) {
	chunk := make([]byte, 64<<10)
	n, err := t.f.Read(chunk)
	t.buf = append(t.buf, chunk[:n]...)
	t.offset += int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("read log: %w", err)
	}
	return n, nil
}

// next moves to the file renamed right after the current one, once the current one was rotated
// and read to its end; it reports whether it moved.
func (t *logTail) next() (bool, error) {
	cur, err := t.f.Stat()
	if err != nil {
		return false, fmt.Errorf("stat log: %w", err)
	}
	if now, err := os.Stat(t.path); err == nil && os.SameFile(cur, now) {
		if now.Size() < t.offset {
			return false, errors.New("log truncated")
		}
		return false, nil
	}
	// Rotated: Laurel renames only after a whole line, and never writes to it again, so whatever
	// is left now is its rest.
	if n, err := t.read(); err != nil || n > 0 {
		return false, err
	}
	if len(t.buf) > 0 {
		return false, errors.New("rotated log ends inside a line")
	}
	at := 0
	for k := 1; k <= generations && at == 0; k++ {
		if st, err := os.Stat(rotated(t.path, k)); err == nil && os.SameFile(cur, st) {
			at = k
		}
	}
	if at == 0 {
		return false, errors.New("reader fell behind the log's rotation")
	}
	f, err := os.Open(rotated(t.path, at-1))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // Laurel is between two renames, or creates the new log on its next write
	}
	if err != nil {
		return false, fmt.Errorf("open next log: %w", err)
	}
	// Another rotation between the scan and the open would make f the wrong file: try again.
	if st, err := os.Stat(rotated(t.path, at)); err != nil || !os.SameFile(cur, st) {
		_ = f.Close()
		return false, nil
	}
	_ = t.f.Close()
	t.f, t.offset = f, 0
	return true, nil
}

func rotated(path string, k int) string {
	if k == 0 {
		return path
	}
	return path + "." + strconv.Itoa(k)
}
