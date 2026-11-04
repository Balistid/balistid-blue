package auditstat

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// ReportPath is where auditstat writes its report: its unit's runtime directory, 0750 to the report's group.
const ReportPath = "/run/balistid-auditstat/report"

// Label names the report's encoding; a change of the layout needs a new label.
const Label = "balistid/auditstat/v2"

// ReportBytes is a report's size: the label and its terminator, the seq, the status, the rule count and the rules'
// digest, big-endian.
const ReportBytes = len(Label) + 1 + 8 + statusBytes + 4 + sha256.Size

// Report is one answer of the kernel: Seq counts auditstat's polls since it started, so a report that stops
// changing tells the collector that auditstat stopped (ADR 0038 point 4); Rules is the loaded rule list (ADR 0059).
type Report struct {
	Seq    uint64
	Status Status
	Rules  Rules
}

// Encode is r's fixed-size encoding.
func (r Report) Encode() []byte {
	out := append(make([]byte, 0, ReportBytes), Label...)
	out = binary.BigEndian.AppendUint64(append(out, 0), r.Seq)
	for _, f := range r.Status.fields() {
		out = binary.BigEndian.AppendUint32(out, *f)
	}
	out = binary.BigEndian.AppendUint32(out, r.Rules.Count)
	return append(out, r.Rules.Digest[:]...)
}

// DecodeReport is the report encoded in b, which must be exactly ReportBytes under the label. Errors never quote b.
func DecodeReport(b []byte) (Report, error) {
	switch {
	case len(b) != ReportBytes:
		return Report{}, errors.New("auditstat: a report of the wrong size")
	case string(b[:len(Label)+1]) != Label+"\x00":
		return Report{}, errors.New("auditstat: not a " + Label + " report")
	}
	b = b[len(Label)+1:]
	r := Report{Seq: binary.BigEndian.Uint64(b)}
	for i, f := range r.Status.fields() {
		*f = binary.BigEndian.Uint32(b[8+4*i:])
	}
	b = b[8+statusBytes:]
	r.Rules.Count = binary.BigEndian.Uint32(b)
	copy(r.Rules.Digest[:], b[4:])
	return r, nil
}

// ReadReport is the report at path, read only as a regular file of uid, exactly ReportBytes long and not through a
// symlink (ADR 0038 point 2): the one way to read it.
func ReadReport(path string, uid int) (Report, error) {
	b, err := wholefile.ReadOwned(path, uid, ReportBytes)
	if err != nil {
		return Report{}, fmt.Errorf("auditstat: report: %w", err)
	}
	return DecodeReport(b)
}
