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
	}, "")
	b := Report{Seq: 3, Status: sample}.Encode()
	if hex.EncodeToString(b) != want || len(b) != ReportBytes {
		t.Fatalf("report %x\nwant   %s", b, want)
	}
	if r, err := DecodeReport(b); err != nil || r != (Report{Seq: 3, Status: sample}) {
		t.Fatalf("%+v %v", r, err)
	}
	for name, bad := range map[string][]byte{
		"short":    b[:len(b)-1],
		"trailing": append(bytes.Clone(b), 0),
		"label":    append([]byte("balistid/auditstat/v2"), b[len(Label):]...),
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
	f.Add(Report{Seq: 3, Status: sample}.Encode())
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

// answer is a kernel that replies with make(seq) from port, or fails with err.
func answer(make func(seq uint32) []byte, port uint32, err error) exchange {
	return func(req []byte) ([]byte, uint32, error) {
		if err != nil {
			return nil, 0, err
		}
		return make(binary.NativeEndian.Uint32(req[8:])), port, nil
	}
}

// A poll writes the kernel's answer whole and group-readable; anything else leaves the report as it was, so it ages.
func TestPollWritesOnlyTheKernelsAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	ok := answer(func(seq uint32) []byte { return reply(seq, sample) }, 0, nil)
	if err := poll(t.Context(), ok, 7, path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("report %v, %v", fi, err)
	}
	if r, err := ReadReport(path, os.Getuid()); err != nil || r != (Report{Seq: 7, Status: sample}) {
		t.Fatalf("%+v %v", r, err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // the test's own file
	if err != nil {
		t.Fatal(err)
	}
	for name, ask := range map[string]exchange{
		"refused":      answer(nil, 0, syscall.EPERM),
		"stale":        answer(func(seq uint32) []byte { return reply(seq-1, sample) }, 0, nil),
		"another port": answer(func(seq uint32) []byte { return reply(seq, sample) }, 77, nil),
		"longer":       answer(func(seq uint32) []byte { return append(reply(seq, sample), 0, 0, 0, 0) }, 0, nil),
	} {
		if err := poll(t.Context(), ask, 8, path); err == nil {
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
	refuse := func([]byte) ([]byte, uint32, error) {
		if polls++; polls == 2 {
			cancel()
		}
		return nil, 0, syscall.EPERM
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
