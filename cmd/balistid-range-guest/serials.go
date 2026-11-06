package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// serialGapsShown bounds the gaps a scan shows: the host shows 400 lines of a run (tools/ci/range_kvm.py).
const serialGapsShown = 30

// serialScan is what Laurel's events in the store show of the kernel's event serials, one global counter
// per boot (#245, measurement only): whether a gap between them counts losses the kernel's lost does not.
// auditd's own events (DAEMON_*) take auditd's numbers, not the kernel's, so they are kept apart.
type serialScan struct {
	types                           map[uint64]string // a kernel event's serial and its record types
	daemon, unparsed, repeated, all int
}

func newSerialScan() *serialScan { return &serialScan{types: map[uint64]string{}} }

// add takes one Laurel line.
func (s *serialScan) add(line []byte) {
	s.all++
	var top map[string]json.RawMessage
	var id string
	if json.Unmarshal(line, &top) != nil || json.Unmarshal(top["ID"], &id) != nil {
		s.unparsed++
		return
	}
	_, serial, _ := strings.Cut(id, ":")
	n, err := strconv.ParseUint(serial, 10, 64)
	if _, ok := auditTime(id); !ok || err != nil {
		s.unparsed++
		return
	}
	var kinds []string
	for k := range top {
		if k == strings.ToUpper(k) && k != "ID" && k != "NODE" {
			kinds = append(kinds, k)
		}
	}
	slices.Sort(kinds)
	switch {
	case slices.ContainsFunc(kinds, func(k string) bool { return strings.HasPrefix(k, "DAEMON_") }):
		s.daemon++
	case s.types[n] != "":
		s.repeated++
	default:
		s.types[n] = strings.Join(kinds, "+")
	}
}

// report is the scan as console lines: a summary, then each gap with the events on either side.
func (s *serialScan) report(label string, limit int) []string {
	serials := slices.Sorted(maps.Keys(s.types))
	var gaps []string
	missing := uint64(0)
	for i := 1; i < len(serials); i++ {
		if d := serials[i] - serials[i-1]; d > 1 {
			missing += d - 1
			if len(gaps) < limit {
				gaps = append(gaps, fmt.Sprintf("serials: %s: gap %d-%d (%d) after %s before %s", label, serials[i-1]+1,
					serials[i]-1, d-1, s.types[serials[i-1]], s.types[serials[i]]))
			}
		}
	}
	first, last := uint64(0), uint64(0)
	if len(serials) > 0 {
		first, last = serials[0], serials[len(serials)-1]
	}
	summary := fmt.Sprintf("serials: %s: lines=%d events=%d daemon=%d unparsed=%d repeated=%d first=%d last=%d missing=%d",
		label, s.all, len(serials), s.daemon, s.unparsed, s.repeated, first, last, missing)
	return append([]string{summary}, gaps...)
}

// printSerials shows what scan found in the host's log, with the kernel's lost and backlog then.
func printSerials(ctx context.Context, label string, scan *serialScan) {
	for _, line := range scan.report(label, serialGapsShown) {
		hostLine(os.Stdout, "%s", line)
	}
	st := rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))
	hostLine(os.Stdout, "serials: %s: kernel lost=%s backlog=%s", label, valueOr(st["lost"]), valueOr(st["backlog"]))
}

// scanLines is a scan of Laurel lines already read, one per line.
func scanLines(lines []byte) *serialScan {
	s := newSerialScan()
	for line := range bytes.SplitSeq(bytes.TrimSuffix(lines, []byte("\n")), []byte("\n")) {
		if len(line) > 0 {
			s.add(line)
		}
	}
	return s
}

// scanning is next, which also scans each Laurel line it is handed.
func (s *serialScan) scanning(next func(rawrecord.Record) error) func(rawrecord.Record) error {
	return func(r rawrecord.Record) error {
		if r.Provider == store.SensorProvider {
			s.add(r.Data)
		}
		return next(r)
	}
}

// scanStore reads the store once and scans its Laurel lines without holding them: after the overflow
// experiment they are tens of MiB.
func scanStore(ctx context.Context) (*serialScan, error) {
	s := newSerialScan()
	err := readStore(ctx, s.scanning(func(rawrecord.Record) error { return nil }), nil)
	return s, err
}
