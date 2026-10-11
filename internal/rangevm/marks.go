package rangevm

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Failure trials (ADR 0018, point 3): just before it fails, the guest writes "balistid-fail <H>"
// straight to its serial console, H the end of the contiguous numbers returned 900 ms earlier; a kill
// trial then writes "balistid-killed". The host stamps each line as it arrives, and the run is
// INVALID unless QEMU exits (reset) or the kill line arrives within MarkWindow of the fail line.
const (
	FailReset  = rangejob.FailReset
	FailKill   = rangejob.FailKill
	MarkWindow = 100 * time.Millisecond

	markFail    = "balistid-fail"
	markKilled  = "balistid-killed"
	maxMarkLine = 64
)

// Marks are what the host saw of a failure trial's console marks, with the time each arrived and
// the time QEMU exited. Bad says why they cannot be trusted, "" when they can.
type Marks struct {
	H      uint64
	Fail   time.Time
	Killed time.Time
	Exited time.Time
	Bad    string
}

// markWriter passes serial output to w unchanged and stamps the marks it finds. The guest's console
// is hostile input (T30): a line starting with a mark's name must be exactly that mark, each mark
// may come once, the kill mark only after the fail mark, and a line is looked at only up to
// maxMarkLine bytes; anything else makes the marks Bad, never a mark.
type markWriter struct {
	w    io.Writer
	now  func() time.Time
	line []byte
	long bool
	m    Marks
}

func (s *markWriter) Write(p []byte) (int, error) {
	for _, c := range p {
		switch {
		case c == '\n':
			s.end()
		case len(s.line) < maxMarkLine:
			s.line = append(s.line, c)
		default:
			s.long = true
		}
	}
	n, err := s.w.Write(p)
	if err != nil {
		return n, fmt.Errorf("serial: %w", err)
	}
	return n, nil
}

func (s *markWriter) end() {
	line := strings.TrimSuffix(string(s.line), "\r")
	long := s.long
	s.line, s.long = s.line[:0], false
	isFail, isKilled := strings.HasPrefix(line, markFail), strings.HasPrefix(line, markKilled)
	if !isFail && !isKilled || s.m.Bad != "" {
		return
	}
	now := s.now()
	digits, spaced := strings.CutPrefix(line, markFail+" ")
	h, err := strconv.ParseUint(digits, 10, 64)
	switch {
	case long:
		s.m.Bad = fmt.Sprintf("a failure mark is over %d bytes", maxMarkLine)
	case isFail && !s.m.Fail.IsZero():
		s.m.Bad = "two fail marks"
	case isFail && (!spaced || err != nil || strconv.FormatUint(h, 10) != digits):
		s.m.Bad = "malformed fail mark"
	case isFail:
		s.m.H, s.m.Fail = h, now
	case line != markKilled:
		s.m.Bad = "malformed kill mark"
	case !s.m.Killed.IsZero():
		s.m.Bad = "two kill marks"
	case s.m.Fail.IsZero():
		s.m.Bad = "kill mark before the fail mark"
	default:
		s.m.Killed = now
	}
}

// failureInvalid is why the marks of a failure trial of kind make its run INVALID, or "".
func failureInvalid(kind string, m Marks) string {
	switch {
	case m.Bad != "":
		return "failure marks: " + m.Bad
	case m.Fail.IsZero():
		return "no fail mark"
	case kind == FailReset && !m.Killed.IsZero():
		return "a kill mark in a reset trial"
	case kind == FailReset && m.Exited.Sub(m.Fail) > MarkWindow:
		return fmt.Sprintf("QEMU exited %s after the fail mark, over %s", m.Exited.Sub(m.Fail), MarkWindow)
	case kind == FailKill && m.Killed.IsZero():
		return "no kill mark"
	case kind == FailKill && m.Killed.Sub(m.Fail) > MarkWindow:
		return fmt.Sprintf("kill mark %s after the fail mark, over %s", m.Killed.Sub(m.Fail), MarkWindow)
	}
	return ""
}
