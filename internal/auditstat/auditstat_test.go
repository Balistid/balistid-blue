package auditstat

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var sampleRules = Rules{Count: 7, Digest: [32]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab}}

var sample = Status{Mask: 0, Enabled: 2, Failure: 1, PID: 412, RateLimit: 0, BacklogLimit: 65536, Lost: 7, Backlog: 3,
	FeatureBitmap: 0x7f, BacklogWaitTime: 60000, BacklogWaitTimeActual: 12}

// reply is the kernel's answer to request seq carrying s, as linux/audit.h lays it out.
func reply(seq uint32, s Status) []byte {
	b := make([]byte, replyBytes)
	binary.NativeEndian.PutUint32(b[0:], replyBytes)
	binary.NativeEndian.PutUint16(b[4:], unix.AUDIT_GET)
	binary.NativeEndian.PutUint32(b[8:], seq)
	for i, f := range s.fields() {
		binary.NativeEndian.PutUint32(b[unix.SizeofNlMsghdr+4*i:], *f)
	}
	return b
}

func TestRequestIsAUDITGETWithoutAck(t *testing.T) {
	b := request(9)
	want := make([]byte, 16)
	binary.NativeEndian.PutUint32(want[0:], 16)
	binary.NativeEndian.PutUint16(want[4:], 1000) // AUDIT_GET, linux/audit.h
	binary.NativeEndian.PutUint16(want[6:], 1)    // NLM_F_REQUEST only
	binary.NativeEndian.PutUint32(want[8:], 9)
	if !bytes.Equal(b, want) {
		t.Fatalf("request %x, want %x", b, want)
	}
}

func TestDecodeReplyTakesTheKernelsAnswer(t *testing.T) {
	if replyBytes != 60 || statusBytes != 44 {
		t.Fatalf("sizes %d %d: struct audit_status is 11 u32 behind a 16-byte header", replyBytes, statusBytes)
	}
	s, err := decodeReply(reply(5, sample), 0, 5)
	if err != nil || s != sample {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestDecodeReplyRefusesAnythingElse(t *testing.T) {
	good := reply(5, sample)
	set := func(off int, v uint16) []byte {
		b := bytes.Clone(good)
		binary.NativeEndian.PutUint16(b[off:], v)
		return b
	}
	for name, c := range map[string]struct {
		b         []byte
		port, seq uint32
		why       string
	}{
		"from a process":       {good, 77, 5, "not from the kernel"},
		"another seq":          {good, 0, 6, "another request"},
		"another type":         {set(4, unix.AUDIT_SET), 0, 5, "another type"},
		"flags":                {set(6, unix.NLM_F_MULTI), 0, 5, "with flags"},
		"short":                {good[:59], 0, 5, "59 bytes"},
		"trailing byte":        {append(bytes.Clone(good), 0), 0, 5, "61 bytes"},
		"header longer":        {set(0, 61), 0, 5, "header length"},
		"a newer kernel's":     {append(bytes.Clone(good), 0, 0, 0, 0), 0, 5, "64 bytes"},
		"empty":                {nil, 0, 5, "0 bytes"},
		"a port in the header": {set(12, 1), 0, 5, "names a port"},
	} {
		if _, err := decodeReply(c.b, c.port, c.seq); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", name, err, c.why)
		}
	}
	refused := make([]byte, unix.SizeofNlMsgerr+unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint16(refused[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(refused[16:], uint32(0xffffffff)) // -EPERM
	if _, err := decodeReply(refused, 0, 5); !errors.Is(err, syscall.EPERM) {
		t.Errorf("NLMSG_ERROR -1: %v", err)
	}
	binary.NativeEndian.PutUint32(refused[16:], 0)
	if _, err := decodeReply(refused, 0, 5); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Errorf("NLMSG_ERROR 0: %v", err)
	}
}

// The report's encoding spelled out field by field, so a layout change fails here and needs a new label.
func TestReportVector(t *testing.T) {
	want := strings.Join([]string{
		hex.EncodeToString([]byte(Label)), "00", "0000000000000003", // label, seq
		"00000000", "00000002", "00000001", "0000019c", "00000000", "00010000", // mask enabled failure pid rate backlog_limit
		"00000007", "00000003", "0000007f", "0000ea60", "0000000c", // lost backlog features wait wait_actual
		"00000007", strings.Repeat("ab", 32), // rule count, digest
	}, "")
	b := Report{Seq: 3, Status: sample, Rules: sampleRules}.Encode()
	if hex.EncodeToString(b) != want || len(b) != ReportBytes || ReportBytes != 110 {
		t.Fatalf("report %x\nwant   %s", b, want)
	}
	if r, err := DecodeReport(b); err != nil || r != (Report{Seq: 3, Status: sample, Rules: sampleRules}) {
		t.Fatalf("%+v %v", r, err)
	}
	for name, bad := range map[string][]byte{
		"short":    b[:len(b)-1],
		"trailing": append(bytes.Clone(b), 0),
		"label":    append([]byte("balistid/auditstat/v1"), b[len(Label):]...),
		"empty":    nil,
	} {
		if _, err := DecodeReport(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// Whatever decodeReply accepts is the kernel's reply to that seq, byte for byte.
func FuzzDecodeReply(f *testing.F) {
	f.Add(reply(5, sample))
	f.Add(reply(5, Status{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := decodeReply(b, 0, 5)
		if err != nil {
			return
		}
		want := reply(5, s)
		if !bytes.Equal(want, b) {
			t.Fatalf("decodeReply(%x) = %+v, which encodes to %x", b, s, want)
		}
	})
}

// Whatever DecodeReport accepts, Encode gives back byte for byte.
func FuzzDecodeReport(f *testing.F) {
	f.Add(Report{Seq: 3, Status: sample, Rules: sampleRules}.Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeReport(b)
		if err != nil {
			return
		}
		if back := r.Encode(); !bytes.Equal(back, b) {
			t.Fatalf("DecodeReport(%x) = %+v, encodes to %x", b, r, back)
		}
	})
}

// kernel is a fake audit socket: each request is answered with what reply gives for its type and seq, a datagram
// at a time from port, or send fails with err.
func kernel(reply func(typ uint16, seq uint32) [][]byte, port uint32, err error) link {
	var queue [][]byte
	return link{
		send: func(req []byte) error {
			if err != nil {
				return err
			}
			queue = reply(binary.NativeEndian.Uint16(req[4:]), binary.NativeEndian.Uint32(req[8:]))
			return nil
		},
		recv: func() ([]byte, uint32, error) {
			if len(queue) == 0 {
				return nil, 0, syscall.EAGAIN // SO_RCVTIMEO's end
			}
			b := queue[0]
			queue = queue[1:]
			return b, port, nil
		},
	}
}

// shipped answers AUDIT_GET with sample and AUDIT_LIST_RULES with rules then the list's end.
func shipped(typ uint16, seq uint32) [][]byte {
	if typ == unix.AUDIT_GET {
		return [][]byte{reply(seq, sample)}
	}
	return append(rulesReply(seq, testRules...), done(seq))
}

// A poll writes the kernel's answer whole and group-readable; anything else leaves the report as it was, so it ages.
func TestPollWritesOnlyTheKernelsAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	if err := poll(t.Context(), kernel(shipped, 0, nil), 7, path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("report %v, %v", fi, err)
	}
	want := Report{Seq: 7, Status: sample, Rules: Rules{Count: uint32(len(testRules)), Digest: testDigest(testRules...)}}
	if r, err := ReadReport(path, os.Getuid()); err != nil || r != want {
		t.Fatalf("%+v %v", r, err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]link{
		"refused":      kernel(nil, 0, syscall.EPERM),
		"another port": kernel(shipped, 77, nil),
		"stale status": kernel(func(typ uint16, seq uint32) [][]byte { return shipped(typ, seq-2) }, 0, nil),
		"longer status": kernel(func(typ uint16, seq uint32) [][]byte {
			if typ == unix.AUDIT_GET {
				return [][]byte{append(reply(seq, sample), 0, 0, 0, 0)}
			}
			return shipped(typ, seq)
		}, 0, nil),
		"no list end": kernel(func(typ uint16, seq uint32) [][]byte {
			if typ == unix.AUDIT_GET {
				return shipped(typ, seq)
			}
			return rulesReply(seq, testRules...)
		}, 0, nil),
		"the status's seq on the list": kernel(func(typ uint16, seq uint32) [][]byte {
			if typ == unix.AUDIT_GET {
				return shipped(typ, seq)
			}
			return shipped(typ, seq-1)
		}, 0, nil),
	} {
		if err := poll(t.Context(), k, 8, path); err == nil {
			t.Errorf("%s: written", name)
		}
		if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) { //nolint:gosec // the test's own file
			t.Errorf("%s: the report changed, %v", name, err)
		}
	}
}

// The first failing poll is logged, as a missing capability or a newer kernel fails every poll from the start.
func TestLoopLogsTheFirstFailure(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	ctx, cancel := context.WithCancel(t.Context())
	polls := 0
	refuse := link{
		send: func([]byte) error {
			if polls++; polls == 2 {
				cancel()
			}
			return syscall.EPERM
		},
		recv: func() ([]byte, uint32, error) { return nil, 0, syscall.EAGAIN },
	}
	loop(ctx, refuse, filepath.Join(t.TempDir(), "report"), time.Millisecond)
	if n := strings.Count(logs.String(), "no report"); n != 1 || polls != 2 {
		t.Fatalf("%d failure lines over %d polls: %s", n, polls, logs.String())
	}
}

// The report is read only as the owner's regular file of its exact size, never through a symlink.
func TestReadReportRefusesAnythingElse(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "report")
	if err := os.WriteFile(good, Report{Seq: 1, Status: sample}.Encode(), 0o600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, Report{Seq: 1}.Encode()[1:], 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReport(good, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path string
		uid  int
	}{
		"another owner": {good, os.Getuid() + 1}, "symlink": {link, os.Getuid()}, "short": {short, os.Getuid()},
		"directory": {dir, os.Getuid()}, "missing": {filepath.Join(dir, "none"), os.Getuid()},
	} {
		if _, err := ReadReport(c.path, c.uid); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}
