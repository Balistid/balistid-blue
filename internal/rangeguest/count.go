package rangeguest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/bits"
	"slices"
	"strconv"
	"strings"

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
	// keptOutside is how many records counted as outside a reader keeps, each cut to keptBytes, so a
	// run that counts one shows what Laurel wrote; the store is gone after the run.
	keptOutside = 3
	keptBytes   = 2000
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

// Above returns at most max numbers of the set above generated, lowest first: they count as outside.
func (n *Numbers) Above(generated uint64, max int) []uint64 {
	var out []uint64
	for w := (generated + 1) / 64; w < uint64(len(n.bits)) && len(out) < max; w++ {
		for b := uint64(0); b < 64 && len(out) < max; b++ {
			if seq := w*64 + b; seq > generated && n.bits[w]&(1<<b) != 0 {
				out = append(out, seq)
			}
		}
	}
	return out
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

// Counter counts a trial's numbered events (ADR 0018, point 4) in the Laurel lines the store reader
// hands it, and keeps the first records it counted as outside the set: the store is gone after the run.
type Counter struct {
	kind    string
	skip    uint64
	skipped bool
	nums    Numbers
	outside []string
}

// NewCounter counts events of the load kind; skip, if not 0, is one number it drops on purpose, a
// control that must miss.
func NewCounter(kind string, skip uint64) (*Counter, error) {
	if kind != rangejob.LoadExec && kind != rangejob.LoadPtrace {
		return nil, fmt.Errorf("unknown load %q", kind)
	}
	return &Counter{kind: kind, skip: skip}, nil
}

// Numbers is the set counted so far.
func (c *Counter) Numbers() *Numbers { return &c.nums }

// Outside returns the first records counted as outside the set, cut to keptBytes.
func (c *Counter) Outside() []string { return slices.Clone(c.outside) }

// Line adds the numbers of one Laurel line. Laurel writes upper- and lower-case keys side by side
// (enrichment), so lines are read as maps, never into structs that match names case-insensitively.
func (c *Counter) Line(line []byte) {
	before := c.nums.outside
	c.line(line)
	if c.nums.outside > before && len(c.outside) < keptOutside {
		c.outside = append(c.outside, string(line[:min(len(line), keptBytes)]))
	}
}

func (c *Counter) line(line []byte) {
	var nums []uint64
	ok := true
	switch c.kind {
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
		c.nums.outside++
	}
	for _, n := range nums {
		if c.skip != 0 && n == c.skip {
			// The dropped number stays dropped: a second record of it is a duplicate, never its stand-in.
			if c.skipped {
				c.nums.duplicate++
			}
			c.skipped = true
			continue
		}
		c.nums.Add(n)
	}
}

// IsBarrier reports whether a Laurel line is the exec of a barrier: token as one whole argument.
func IsBarrier(line []byte, token string) bool {
	return bytes.Contains(line, []byte(token)) && slices.Contains(execArgs(line), token)
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
