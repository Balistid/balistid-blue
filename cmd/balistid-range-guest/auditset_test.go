package main

import (
	"encoding/binary"
	"maps"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// The child asks exactly the requests the host judges, so none is missing and none goes unjudged.
func TestAuditAsksAreTheJudgedOps(t *testing.T) {
	got := slices.Sorted(maps.Keys(auditAsks(&auditAsker{})))
	if want := slices.Sorted(slices.Values(rangevm.AuditSetOps())); !slices.Equal(got, want) {
		t.Errorf("child asks %v, host judges %v", got, want)
	}
}

// An errno the kernel returns is reported by its name, one x/sys does not name by its number.
func TestErrnoName(t *testing.T) {
	for e, want := range map[syscall.Errno]string{1: "EPERM", 17: "EEXIST", 4095: "E4095"} {
		if got := errnoName(e); got != want {
			t.Errorf("%d: %q, want %q", int(e), got, want)
		}
	}
}

// fakeKernel answers each request with the datagrams answer returns for it, in order; with refuse set, no
// request is sent.
type fakeKernel struct {
	sent   [][]byte
	queue  [][]byte
	answer func(req []byte) [][]byte
	refuse error
}

func (k *fakeKernel) asker() *auditAsker {
	return &auditAsker{
		send: func(m []byte) error {
			if k.refuse != nil {
				return k.refuse
			}
			k.sent = append(k.sent, slices.Clone(m))
			k.queue = append(k.queue, k.answer(m)...)
			return nil
		},
		recv: func(b []byte) (int, error) {
			if len(k.queue) == 0 {
				return 0, syscall.EAGAIN
			}
			d := k.queue[0]
			k.queue = k.queue[1:]
			return copy(b, d), nil
		},
	}
}

func nlmsg(typ uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b))) //nolint:gosec // a test message
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint32(b[8:], seq)
	copy(b[16:], payload)
	return b
}

func ack(seq uint32, code int32) []byte {
	p := make([]byte, 4)
	binary.NativeEndian.PutUint32(p, uint32(code)) //nolint:gosec // the kernel's signed errno
	return nlmsg(unix.NLMSG_ERROR, seq, p)
}

func seqOf(req []byte) uint32 { return binary.NativeEndian.Uint32(req[8:]) }

// A request that never left the child is no kernel answer, so it cannot read as the lock's EPERM.
func TestAuditAskUnsentIsNoErrno(t *testing.T) {
	k := &fakeKernel{refuse: syscall.EPERM}
	for op, ask := range auditAsks(k.asker()) {
		if got := ask(); got != "unsent" {
			t.Errorf("%s: %q, want unsent", op, got)
		}
	}
}

// Only the acknowledgement of the request's own seq answers it: zero or more is ok, a negative code its errno.
func TestAuditAskReadsItsAcknowledgement(t *testing.T) {
	for _, c := range []struct {
		answer func(seq uint32) [][]byte
		want   string
	}{
		{func(s uint32) [][]byte { return [][]byte{ack(s, 0)} }, "ok"},
		{func(s uint32) [][]byte { return [][]byte{ack(s, 7)} }, "ok"},
		{func(s uint32) [][]byte { return [][]byte{ack(s, -1)} }, "EPERM"},
		{func(s uint32) [][]byte { return [][]byte{ack(s+1, 0), nlmsg(unix.AUDIT_GET, s, nil), ack(s, -17)} }, "EEXIST"},
		{func(s uint32) [][]byte { return [][]byte{ack(s+1, -1)} }, "timeout"},
		{func(s uint32) [][]byte { return [][]byte{{1, 2, 3}} }, "timeout"},
		{func(uint32) [][]byte { return nil }, "timeout"},
	} {
		k := &fakeKernel{answer: func(req []byte) [][]byte { return c.answer(seqOf(req)) }}
		if got := k.asker().ask(unix.AUDIT_SET, nil); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

// The features reply comes from a kernel thread, after an acknowledgement or not; the child flips
// loginuid_immutable once from it and sends nothing more.
func TestToggleLoginuidFlipsOnceFromTheReply(t *testing.T) {
	features := func(f uint32) []byte {
		b := make([]byte, 16)
		binary.NativeEndian.PutUint32(b[8:], f)
		return b
	}
	answer := func(get [][]byte) func(req []byte) [][]byte {
		return func(req []byte) [][]byte {
			if binary.NativeEndian.Uint16(req[4:]) == unix.AUDIT_GET_FEATURE {
				return get
			}
			return [][]byte{ack(seqOf(req), -1)}
		}
	}
	k := &fakeKernel{}
	k.answer = answer([][]byte{ack(1, 0), nlmsg(unix.AUDIT_GET_FEATURE, 1, features(0b101))})
	if got := k.asker().toggleLoginuid(); got != "EPERM" || len(k.sent) != 2 {
		t.Fatalf("%q after %d requests, want EPERM after 2", got, len(k.sent))
	}
	set := k.sent[1]
	if binary.NativeEndian.Uint16(set[4:]) != unix.AUDIT_SET_FEATURE || binary.NativeEndian.Uint32(set[20:]) != loginuidImmutable ||
		binary.NativeEndian.Uint32(set[24:]) != 0b111 {
		t.Errorf("set request % x", set)
	}
	k = &fakeKernel{}
	k.answer = answer([][]byte{nlmsg(unix.AUDIT_GET_FEATURE, 1, features(0)[:8])})
	if got := k.asker().toggleLoginuid(); got != "short-reply" || len(k.sent) != 1 {
		t.Errorf("short reply: %q after %d requests", got, len(k.sent))
	}
	k = &fakeKernel{}
	k.answer = answer([][]byte{ack(1, -1)})
	if got := k.asker().toggleLoginuid(); got != "EPERM" || len(k.sent) != 1 {
		t.Errorf("refused read: %q after %d requests", got, len(k.sent))
	}
}
