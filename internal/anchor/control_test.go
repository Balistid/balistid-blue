package anchor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
)

// served runs Serve with a control socket on l until the test ends, and returns both socket paths and a
// function that stops Serve and returns its journal.
type served struct {
	sock, control string
	stop          func() string
}

func serve(t *testing.T, l *Log, collectorUID, controlUID int) served {
	t.Helper()
	dir := t.TempDir()
	s := served{sock: filepath.Join(dir, "ledger.sock"), control: filepath.Join(dir, "control.sock")}
	listen := func(path string) *net.UnixListener {
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		unixSockets(t, err)
		if err != nil {
			t.Fatal(err)
		}
		return ln
	}
	ln, ctl := listen(s.sock), listen(s.control)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	var journal bytes.Buffer // read only after Serve returned
	log := slog.New(slog.NewJSONHandler(&journal, nil))
	go func() { done <- Serve(ctx, ln, Control{Listener: ctl, UID: controlUID}, l, collectorUID, Relay{}, log) }()
	stopped := false
	s.stop = func() string {
		if !stopped {
			stopped = true
			cancel()
			if err := result(t, done); !errors.Is(err, context.Canceled) {
				t.Fatalf("Serve = %v", err)
			}
		}
		return journal.String()
	}
	t.Cleanup(func() { s.stop() })
	return s
}

func TestControlTakesOnlyTheLedgersUID(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	defer closeLog(t, l)
	s := serve(t, l, os.Getuid()+1, os.Getuid()+1)
	if _, err := Ask(t.Context(), s.control, entry.Announce{Kind: entry.AnnounceShutdown}); err == nil {
		t.Fatal("another uid's announcement was answered")
	}
	if !strings.Contains(s.stop(), `"control-uid":1`) {
		t.Fatal("the refusal was not summed")
	}
	if got, _ := logged(t, dir, k); len(got) != 0 {
		t.Fatalf("a refused peer logged %v", got)
	}
}

func TestControlLogsAnAnnouncementAndAFinal(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	records(t, l, 1, 2)
	s := serve(t, l, os.Getuid()+1, os.Getuid())
	if size, err := Ask(t.Context(), s.control, entry.Announce{Kind: entry.AnnounceSuspend}); err != nil || size != 2 {
		t.Fatalf("announce: size %d, %v", size, err)
	}
	if _, err := Ask(t.Context(), s.control, entry.Final{NextOrigin: origin}); err == nil {
		t.Fatal("a final naming this log was answered as logged")
	}
	if size, err := Ask(t.Context(), s.control, entry.Final{NextOrigin: next}); err != nil || size != 3 {
		t.Fatalf("final: size %d, %v", size, err)
	}
	s.stop()
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	if len(got) != 3 || got[1] != (entry.Announce{Kind: entry.AnnounceSuspend}) || got[2] != (entry.Final{NextOrigin: next}) {
		t.Fatalf("log %v", got)
	}
}

func TestCollectorRefusedAfterFinal(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	defer closeLog(t, l)
	if _, err := l.Final(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	s := serve(t, l, os.Getuid(), os.Getuid())
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // test end
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if m, err := link.Read(conn); !errors.Is(err, io.EOF) {
		t.Fatalf("the collector got %+v, %v after the final entry", m, err)
	}
	if !strings.Contains(s.stop(), `"final":1`) {
		t.Fatal("the refusal was not summed")
	}
}

func TestAnnounceCosignedBeforeStop(t *testing.T) {
	f := cosigntest.New(t)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	at := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if err := os.WriteFile(relay.Path, f.Cosigned(t, 4, at), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cp, err := WaitCosigned(ctx, relay, 5, 10*time.Millisecond, time.Minute)
		if err == nil && cp.Size != 5 {
			err = errors.New("returned before the size was cosigned")
		}
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("returned on a checkpoint short of the announcement: %v", err)
	default:
	}
	if err := os.WriteFile(relay.Path, f.Cosigned(t, 5, at.Add(5*time.Second)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceAppendedWhenWitnessAway(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	s := serve(t, l, os.Getuid()+1, os.Getuid())
	size, err := Ask(t.Context(), s.control, entry.Announce{Kind: entry.AnnounceShutdown})
	if err != nil {
		t.Fatal(err)
	}
	f := cosigntest.New(t)
	relay := Relay{Path: filepath.Join(t.TempDir(), cosign.Name), Keys: f.Keys}
	if err := os.WriteFile(relay.Path, f.Cosigned(t, size-1, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(relay.Path, old, old); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for _, r := range []Relay{relay, {Path: relay.Path + ".missing", Keys: f.Keys}} {
		if _, err := WaitCosigned(t.Context(), r, size, time.Second, time.Minute); !errors.Is(err, ErrWitnessAway) {
			t.Fatalf("%s: %v", r.Path, err)
		}
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("waited %v for a witness that is away", waited)
	}
	s.stop()
	closeLog(t, l)
	if got, _ := logged(t, dir, k); len(got) != 1 || got[0] != (entry.Announce{Kind: entry.AnnounceShutdown}) {
		t.Fatalf("the announcement is not in the log: %v", got)
	}
}

func TestReadRequestTakesOnlyWhatRequestWrites(t *testing.T) {
	for _, body := range []entry.Body{entry.Announce{Kind: entry.AnnounceShutdown}, entry.Final{NextOrigin: next}} {
		b, err := Request(body)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ReadRequest(bytes.NewReader(b)); err != nil || got != body {
			t.Fatalf("round trip of %+v: %+v, %v", body, got, err)
		}
	}
	if _, err := Request(entry.Health{State: entry.StateOK}); err == nil {
		t.Fatal("a health request was encoded")
	}
	timed, err := entry.Entry{At: 1, Body: entry.Announce{Kind: entry.AnnounceSuspend}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	health, err := entry.Entry{Body: entry.Health{State: entry.StateOK}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	frame := func(b []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...) } //nolint:gosec // entries are at most 256 bytes
	for name, b := range map[string][]byte{
		"a time":       frame(timed),
		"health":       frame(health),
		"empty":        {0, 0},
		"over the cap": append([]byte{1, 1}, make([]byte, 257)...),
		"short":        frame(timed)[:5],
	} {
		if got, err := ReadRequest(bytes.NewReader(b)); err == nil {
			t.Errorf("%s: read %+v", name, got)
		}
	}
}

func FuzzControlRequest(f *testing.F) {
	for _, body := range []entry.Body{entry.Announce{Kind: entry.AnnounceShutdown}, entry.Final{NextOrigin: next}} {
		b, err := Request(body)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		body, err := ReadRequest(bytes.NewReader(b))
		if err != nil {
			return
		}
		again, err := Request(body)
		if err != nil || !bytes.HasPrefix(b, again) {
			t.Fatalf("read %+v from %x, which encodes as %x, %v", body, b, again, err)
		}
	})
}
