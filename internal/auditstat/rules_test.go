package auditstat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// testRules are payloads as the kernel sends them: a struct audit_rule_data of 1040 bytes and its strings, one
// whose length is no multiple of 4, so its datagram is padded.
var testRules = [][]byte{bytes.Repeat([]byte{1}, 1040+13), bytes.Repeat([]byte{2}, 1040+36), bytes.Repeat([]byte{3}, 1040)}

// message is one netlink message from the kernel, padded to 4 bytes with zeros as nlmsg_put pads it.
func message(typ, flags uint16, seq uint32, payload []byte) []byte {
	n := unix.SizeofNlMsghdr + len(payload)
	b := make([]byte, nlmsgAlign(n))
	binary.NativeEndian.PutUint32(b[0:], uint32(n)) //nolint:gosec // the tests' sizes
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], seq)
	copy(b[unix.SizeofNlMsghdr:], payload)
	return b
}

// rulesReply is the kernel's datagram for each rule of the list answering seq; done is the list's end.
func rulesReply(seq uint32, rules ...[]byte) [][]byte {
	var out [][]byte
	for _, r := range rules {
		out = append(out, message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, seq, r))
	}
	return out
}

func done(seq uint32) []byte { return message(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, nil) }

// testDigest is ADR 0059's digest, spelled out apart from readRules.
func testDigest(rules ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("balistid/auditstat/rules/v1\x00"))
	for _, r := range rules {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(r))) //nolint:gosec // the tests' sizes
		h.Write(n[:])
		h.Write(r)
	}
	var d [32]byte
	h.Sum(d[:0])
	return d
}

// from hands out datagrams one at a time, then the receive timeout.
func from(datagrams [][]byte) func() ([]byte, uint32, error) {
	return func() ([]byte, uint32, error) {
		if len(datagrams) == 0 {
			return nil, 0, syscall.EAGAIN
		}
		b := datagrams[0]
		datagrams = datagrams[1:]
		return b, 0, nil
	}
}

func TestListRequestIsAUDITLISTRULESWithoutAck(t *testing.T) {
	want := make([]byte, 16)
	binary.NativeEndian.PutUint32(want[0:], 16)
	binary.NativeEndian.PutUint16(want[4:], 1013) // AUDIT_LIST_RULES, linux/audit.h
	binary.NativeEndian.PutUint16(want[6:], 1)    // NLM_F_REQUEST only
	binary.NativeEndian.PutUint32(want[8:], 9)
	if b := listRequest(9); !bytes.Equal(b, want) {
		t.Fatalf("request %x, want %x", b, want)
	}
}

// The digest's layout spelled out on one input, so a change of it fails here and needs a new rules label.
func TestRulesDigestVector(t *testing.T) {
	r, err := readRules(from([][]byte{message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, 3, []byte("abc")), done(3)}), 3)
	// sha256("balistid/auditstat/rules/v1\x00" "\x00\x00\x00\x03" "abc"), computed apart from Go
	const want = "ac0e812cdf9a027c17697b7b93ab45e5ed178d520e174779b7ebe95a64be8bea"
	if err != nil || r.Count != 1 || r.Digest != testDigest([]byte("abc")) {
		t.Fatalf("%+v %v", r, err)
	}
	if got := hex.EncodeToString(r.Digest[:]); got != want {
		t.Errorf("digest %s, want %s", got, want)
	}
}

func TestReadRulesTakesTheKernelsList(t *testing.T) {
	r, err := readRules(from(append(rulesReply(5, testRules...), done(5))), 5)
	if err != nil || r != (Rules{Count: 3, Digest: testDigest(testRules...)}) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := readRules(from([][]byte{done(5)}), 5); err != nil || r != (Rules{Digest: testDigest()}) {
		t.Fatalf("no rules: %+v %v", r, err)
	}
	// Order is part of the list: the kernel matches rules in it.
	swapped := [][]byte{testRules[1], testRules[0], testRules[2]}
	if r, _ := readRules(from(append(rulesReply(5, swapped...), done(5))), 5); r.Digest == testDigest(testRules...) {
		t.Error("swapped rules give the same digest")
	}
}

func TestReadRulesRefusesAnythingElse(t *testing.T) {
	good := rulesReply(5, testRules[0])[0] // 1069 bytes in the header, 1072 in the datagram
	set32 := func(b []byte, off int, v uint32) []byte {
		b = bytes.Clone(b)
		binary.NativeEndian.PutUint32(b[off:], v)
		return b
	}
	set16 := func(b []byte, off int, v uint16) []byte {
		b = bytes.Clone(b)
		binary.NativeEndian.PutUint16(b[off:], v)
		return b
	}
	refused := make([]byte, unix.SizeofNlMsgerr+unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint16(refused[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(refused[16:], uint32(0xffffffff)) // -EPERM
	ack := set32(refused, 16, 0)
	many := make([][]byte, maxRules+1)
	for i := range many {
		many[i] = message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, 5, []byte{1})
	}
	big := bytes.Repeat([]byte{1}, maxRuleMessage)
	heavy := make([][]byte, maxRuleBytes/maxRuleMessage+1)
	for i := range heavy {
		heavy[i] = message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, 5, big)
	}
	for name, c := range map[string]struct {
		datagrams [][]byte
		port      uint32
		why       string
	}{
		"from a process":     {[][]byte{good, done(5)}, 77, "not from the kernel"},
		"a port in a header": {[][]byte{set32(good, 12, 1), done(5)}, 0, "names a port"},
		"another seq":        {[][]byte{set32(good, 8, 6), done(5)}, 0, "another request"},
		"the end's seq":      {[][]byte{good, done(6)}, 0, "another request"},
		"no flags":           {[][]byte{set16(good, 6, 0), done(5)}, 0, "NLM_F_MULTI"},
		"more flags":         {[][]byte{set16(good, 6, unix.NLM_F_MULTI|unix.NLM_F_ACK), done(5)}, 0, "NLM_F_MULTI"},
		"the end unflagged":  {[][]byte{good, set16(done(5), 6, 0)}, 0, "NLM_F_MULTI"},
		"a status reply":     {[][]byte{reply(5, sample), done(5)}, 0, "NLM_F_MULTI"},
		"another type":       {[][]byte{set16(good, 4, unix.AUDIT_GET), done(5)}, 0, "neither"},
		"an empty rule":      {[][]byte{message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, 5, nil), done(5)}, 0, "neither"},
		"an end with data":   {[][]byte{message(unix.NLMSG_DONE, unix.NLM_F_MULTI, 5, []byte{0, 0, 0, 0})}, 0, "neither"},
		"unpadded":           {[][]byte{good[:1069], done(5)}, 0, "padded to 4"},
		"padded twice":       {[][]byte{append(bytes.Clone(good), 0, 0, 0, 0), done(5)}, 0, "padded to 4"},
		"a second message":   {[][]byte{append(bytes.Clone(good), done(5)...)}, 0, "padded to 4"},
		"padding not zero":   {[][]byte{append(bytes.Clone(good[:1071]), 1), done(5)}, 0, "other than zeros"},
		"a header too long":  {[][]byte{set32(good, 0, 1073), done(5)}, 0, "padded to 4"},
		"a header too short": {[][]byte{set32(good, 0, 15), done(5)}, 0, "header length is 15"},
		"over 64 KiB":        {[][]byte{message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, 5, append(big, 1)), done(5)}, 0, "header length"},
		"short":              {[][]byte{good[:15]}, 0, "15 bytes"},
		"empty":              {[][]byte{nil}, 0, "0 bytes"},
		"refused":            {[][]byte{refused}, 0, "refused AUDIT_LIST_RULES"},
		"acknowledged":       {[][]byte{ack}, 0, "acknowledgement"},
		"over 1024 rules":    {append(many, done(5)), 0, "over 1024 rules"},
		"over 1 MiB":         {append(heavy, done(5)), 0, "1048576 bytes"},
		"no end":             {[][]byte{good}, 0, "receive"},
	} {
		next := from(c.datagrams)
		port := func() ([]byte, uint32, error) {
			b, _, err := next()
			if errors.Is(err, syscall.EAGAIN) {
				return nil, 0, errors.New("auditstat: receive: timeout")
			}
			return b, c.port, err
		}
		if r, err := readRules(port, 5); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %+v %v, want %q", name, r, err, c.why)
		}
	}
	if _, err := readRules(from([][]byte{refused}), 5); !errors.Is(err, syscall.EPERM) {
		t.Errorf("NLMSG_ERROR -1: %v", err)
	}
}

// Whatever readRules accepts is a list the kernel's framing gives byte for byte, and its digest that of its payloads.
// The input is datagrams, each behind a 2-byte length.
func FuzzReadRules(f *testing.F) {
	frame := func(datagrams ...[]byte) []byte {
		var out []byte
		for _, d := range datagrams {
			out = binary.BigEndian.AppendUint16(out, uint16(len(d))) //nolint:gosec // the seeds are small
			out = append(out, d...)
		}
		return out
	}
	f.Add(frame(append(rulesReply(5, testRules...), done(5))...))
	f.Add(frame(done(5)))
	f.Add(frame(message(unix.AUDIT_LIST_RULES, unix.NLM_F_MULTI, 5, []byte("abcde")), done(5)))
	f.Fuzz(func(t *testing.T, in []byte) {
		var datagrams [][]byte
		for len(in) >= 2 {
			n := int(binary.BigEndian.Uint16(in))
			in = in[2:]
			n = min(n, len(in))
			datagrams = append(datagrams, in[:n])
			in = in[n:]
		}
		var taken [][]byte
		next := from(datagrams)
		r, err := readRules(func() ([]byte, uint32, error) {
			b, p, err := next()
			if err == nil {
				taken = append(taken, b)
			}
			return b, p, err
		}, 5)
		if err != nil {
			return
		}
		var payloads [][]byte
		for _, d := range taken[:len(taken)-1] {
			payloads = append(payloads, d[unix.SizeofNlMsghdr:binary.NativeEndian.Uint32(d)])
		}
		want := append(rulesReply(5, payloads...), done(5))
		if len(want) != len(taken) || r.Count != uint32(len(payloads)) || r.Digest != testDigest(payloads...) { //nolint:gosec // under maxRules
			t.Fatalf("readRules took %x as %+v", taken, r)
		}
		for i := range want {
			if !bytes.Equal(want[i], taken[i]) {
				t.Fatalf("datagram %d %x is not the kernel's framing %x", i, taken[i], want[i])
			}
		}
	})
}
