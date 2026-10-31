// Package auditstat reads the kernel's audit status for balistid-auditstat, the one long-running process with
// CAP_AUDIT_CONTROL (ADR 0007, ADR 0038 point 1), and encodes the fixed-size report the collector reads. It
// sends only AUDIT_GET and parses nothing but the kernel's fixed struct audit_status.
package auditstat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Status is the kernel's struct audit_status (linux/audit.h): eleven u32, in host byte order on netlink.
type Status struct {
	Mask, Enabled, Failure, PID, RateLimit, BacklogLimit, Lost, Backlog, FeatureBitmap uint32
	BacklogWaitTime, BacklogWaitTimeActual                                             uint32
}

const (
	statusBytes = 11 * 4
	// replyBytes is the whole reply: a netlink header and the status. A newer kernel's longer struct is refused
	// until the decoder knows it (T26).
	replyBytes = unix.SizeofNlMsghdr + statusBytes
)

// fields are s's fields in the struct's order.
func (s *Status) fields() [11]*uint32 {
	return [11]*uint32{&s.Mask, &s.Enabled, &s.Failure, &s.PID, &s.RateLimit, &s.BacklogLimit, &s.Lost, &s.Backlog,
		&s.FeatureBitmap, &s.BacklogWaitTime, &s.BacklogWaitTimeActual}
}

// request is AUDIT_GET with seq, without NLM_F_ACK, so the kernel's reply is the only message.
func request(seq uint32) []byte {
	b := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(b[0:], unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint16(b[4:], unix.AUDIT_GET)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(b[8:], seq)
	return b
}

// decodeReply is the status in b, the one datagram that came from netlink port port, as the answer to request
// seq: from the kernel (port 0), AUDIT_GET, no flags, exactly one header and one status. Errors never quote b.
func decodeReply(b []byte, port, seq uint32) (Status, error) {
	if port != 0 {
		return Status{}, errors.New("auditstat: a reply not from the kernel")
	}
	if len(b) >= unix.SizeofNlMsghdr+4 && binary.NativeEndian.Uint16(b[4:]) == unix.NLMSG_ERROR {
		code := binary.NativeEndian.Uint32(b[unix.SizeofNlMsghdr:]) // the kernel's errno, negated
		if code == 0 {
			return Status{}, errors.New("auditstat: an acknowledgement, not a reply")
		}
		return Status{}, fmt.Errorf("auditstat: the kernel refused AUDIT_GET: %w", syscall.Errno(^code+1))
	}
	switch {
	case len(b) != replyBytes:
		return Status{}, fmt.Errorf("auditstat: a reply of %d bytes, not %d", len(b), replyBytes)
	case binary.NativeEndian.Uint32(b[0:]) != replyBytes:
		return Status{}, errors.New("auditstat: a reply whose header length is not the datagram's")
	case binary.NativeEndian.Uint16(b[4:]) != unix.AUDIT_GET:
		return Status{}, errors.New("auditstat: a reply of another type")
	case binary.NativeEndian.Uint16(b[6:]) != 0:
		return Status{}, errors.New("auditstat: a reply with flags")
	case binary.NativeEndian.Uint32(b[8:]) != seq:
		return Status{}, errors.New("auditstat: a reply to another request")
	}
	var s Status
	for i, f := range s.fields() {
		*f = binary.NativeEndian.Uint32(b[unix.SizeofNlMsghdr+4*i:])
	}
	return s, nil
}
