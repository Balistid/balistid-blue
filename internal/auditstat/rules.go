package auditstat

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Bounds of the kernel's rule list (ADR 0059, point 1): one message holds one struct audit_rule_data and its
// strings, 1040 bytes and at most a few paths and keys; the shipped rules are a handful.
const (
	maxRuleMessage = 64 << 10
	maxRules       = 1024
	maxRuleBytes   = 1 << 20
)

// rulesLabel begins what the digest covers, so it names its own framing.
const rulesLabel = "balistid/auditstat/rules/v1"

// Rules is the kernel's loaded rule list as auditstat reports it: the count and the SHA-256 of the label, then each
// rule's payload, unparsed, as its big-endian u32 length and its bytes, in the kernel's order.
type Rules struct {
	Count  uint32
	Digest [sha256.Size]byte
}

// listRequest is AUDIT_LIST_RULES with seq, without NLM_F_ACK, so the kernel's list and its end are the only replies.
func listRequest(seq uint32) []byte {
	b := request(seq)
	binary.NativeEndian.PutUint16(b[4:], unix.AUDIT_LIST_RULES)
	return b
}

// readRules takes the kernel's answer to listRequest(seq) from next, one datagram at a time with its sender's port,
// up to its end: AUDIT_LIST_RULES messages, then NLMSG_DONE. It checks only the netlink framing and hashes each
// payload unread (ADR 0038, point 1; ADR 0059). Errors never quote a datagram.
func readRules(next func() ([]byte, uint32, error), seq uint32) (Rules, error) {
	h := sha256.New()
	h.Write([]byte(rulesLabel + "\x00"))
	var r Rules
	total := 0
	for {
		b, port, err := next()
		if err != nil {
			return Rules{}, err
		}
		payload, done, err := decodeRule(b, port, seq)
		switch {
		case err != nil:
			return Rules{}, err
		case done:
			h.Sum(r.Digest[:0])
			return r, nil
		case r.Count == maxRules || total+len(payload) > maxRuleBytes:
			return Rules{}, fmt.Errorf("auditstat: a rule list over %d rules or %d bytes", maxRules, maxRuleBytes)
		}
		r.Count++
		total += len(payload)
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(payload)))) //nolint:gosec // under maxRuleMessage
		h.Write(payload)
	}
}

// decodeRule is the payload of b, one datagram from netlink port port in the kernel's answer to listRequest(seq),
// or done at the list's end. Each is one message from the kernel (port 0 in the datagram and its header) with seq and
// exactly NLM_F_MULTI: AUDIT_LIST_RULES with a payload of at most maxRuleMessage, or an empty NLMSG_DONE. The
// datagram is the message padded to 4 bytes with zeros (nlmsg_put), and nothing after it.
func decodeRule(b []byte, port, seq uint32) (payload []byte, done bool, err error) {
	if port != 0 {
		return nil, false, errors.New("auditstat: a rule reply not from the kernel")
	}
	if err := kernelError(b, "AUDIT_LIST_RULES"); err != nil {
		return nil, false, err
	}
	if len(b) < unix.SizeofNlMsghdr {
		return nil, false, fmt.Errorf("auditstat: a rule reply of %d bytes", len(b))
	}
	n := int(binary.NativeEndian.Uint32(b[0:]))
	typ, flags := binary.NativeEndian.Uint16(b[4:]), binary.NativeEndian.Uint16(b[6:])
	switch {
	case n < unix.SizeofNlMsghdr || n > unix.SizeofNlMsghdr+maxRuleMessage:
		return nil, false, fmt.Errorf("auditstat: a rule reply whose header length is %d", n)
	case len(b) != nlmsgAlign(n):
		return nil, false, errors.New("auditstat: a rule reply whose datagram is not its message padded to 4 bytes")
	case string(b[n:]) != "\x00\x00\x00"[:len(b)-n]:
		return nil, false, errors.New("auditstat: a rule reply padded with other than zeros")
	case binary.NativeEndian.Uint32(b[8:]) != seq:
		return nil, false, errors.New("auditstat: a rule reply to another request")
	case binary.NativeEndian.Uint32(b[12:]) != 0:
		return nil, false, errors.New("auditstat: a rule reply whose header names a port")
	case flags != unix.NLM_F_MULTI:
		return nil, false, errors.New("auditstat: a rule reply without exactly NLM_F_MULTI")
	case typ == unix.NLMSG_DONE && n == unix.SizeofNlMsghdr:
		return nil, true, nil
	case typ == unix.AUDIT_LIST_RULES && n > unix.SizeofNlMsghdr:
		return b[unix.SizeofNlMsghdr:n], false, nil
	}
	return nil, false, errors.New("auditstat: a rule reply neither a rule nor the list's empty end")
}

// nlmsgAlign is NLMSG_ALIGN: n rounded up to 4 bytes.
func nlmsgAlign(n int) int { return (n + 3) &^ 3 }

// kernelError is the kernel's refusal of request in b, an NLMSG_ERROR with a non-zero errno; an acknowledgement is
// an error too, as no request asks for one. Anything else is nil.
func kernelError(b []byte, request string) error {
	if len(b) < unix.SizeofNlMsghdr+4 || binary.NativeEndian.Uint16(b[4:]) != unix.NLMSG_ERROR {
		return nil
	}
	code := binary.NativeEndian.Uint32(b[unix.SizeofNlMsghdr:]) // the kernel's errno, negated
	if code == 0 {
		return errors.New("auditstat: an acknowledgement, not a reply")
	}
	return fmt.Errorf("auditstat: the kernel refused %s: %w", request, syscall.Errno(^code+1))
}
