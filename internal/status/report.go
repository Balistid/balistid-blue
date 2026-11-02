// Package status is what `balistid status` shows without privilege (ADR 0048): each floor-0 unit as systemd
// reports it and the collector's health from the fixed-size report the collector publishes for every user.
package status

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// ReportPath is the collector's report: its unit's runtime directory, gone while the collector is stopped.
const ReportPath = "/run/balistid-collector/status"

// MaxAge is how old a report may be and still count: the collector rewrites it every second, so five missed
// rewrites mean a stopped or stuck writer, well before systemd's 10 s watchdog restarts it.
const MaxAge = 5 * time.Second

// Label names the report's encoding; a change of the layout needs a new label.
const Label = "balistid/collector-status/v1"

// healthBytes is a health entry's encoding (entry.Encode): label, terminator, type, At, state, reason, unstored.
const healthBytes = len(entry.Label) + 1 + 1 + 8 + 1 + 1 + 8

// ReportBytes is a report's size: the label and its terminator, the seq, the boot time and the health entry.
const ReportBytes = len(Label) + 1 + 8 + 8 + healthBytes

// Report is the collector's health as its writer last computed it. Seq counts the reports since the collector
// started; Boot is CLOCK_BOOTTIME at the write, which a reader of the same boot compares with its own to see
// a report that stopped changing.
type Report struct {
	Seq    uint64
	Boot   uint64
	Health entry.Health
	At     int64 // the host's wall time, information only (T22)
}

// Encode is r's fixed-size encoding; it refuses a health entry the decoder would refuse.
func (r Report) Encode() ([]byte, error) {
	h, err := entry.Entry{At: r.At, Body: r.Health}.Encode()
	if err != nil {
		return nil, fmt.Errorf("status: report: %w", err)
	}
	out := append(make([]byte, 0, ReportBytes), Label...)
	out = binary.BigEndian.AppendUint64(append(out, 0), r.Seq)
	out = binary.BigEndian.AppendUint64(out, r.Boot)
	if len(h) != healthBytes {
		return nil, errors.New("status: a health entry of another size")
	}
	return append(out, h...), nil
}

// DecodeReport is the report encoded in b, which must be exactly ReportBytes under the label with a valid health
// entry. Errors never quote b.
func DecodeReport(b []byte) (Report, error) {
	switch {
	case len(b) != ReportBytes:
		return Report{}, errors.New("status: a report of the wrong size")
	case string(b[:len(Label)+1]) != Label+"\x00":
		return Report{}, errors.New("status: not a balistid/collector-status/v1 report")
	}
	b = b[len(Label)+1:]
	e, err := entry.Decode(b[16:])
	if err != nil {
		return Report{}, fmt.Errorf("status: report: %w", err)
	}
	h, ok := e.Body.(entry.Health)
	if !ok {
		return Report{}, errors.New("status: a report without a health entry")
	}
	return Report{Seq: binary.BigEndian.Uint64(b), Boot: binary.BigEndian.Uint64(b[8:]), Health: h, At: e.At}, nil
}

// Boottime is CLOCK_BOOTTIME in ns: it runs through suspend and restarts at boot, when /run starts empty, so
// a report's Boot is comparable with the reader's within one boot only.
func Boottime() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, fmt.Errorf("status: CLOCK_BOOTTIME: %w", err)
	}
	return uint64(ts.Nano()), nil //nolint:gosec // the boot clock is never negative
}

// ReadReport is the report at path, read only as a regular file of uid, exactly ReportBytes long and not through
// a symlink.
func ReadReport(path string, uid int) (Report, error) {
	b, err := wholefile.ReadOwned(path, uid, ReportBytes)
	if err != nil {
		return Report{}, fmt.Errorf("status: %w", err)
	}
	return DecodeReport(b)
}
