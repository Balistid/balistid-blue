package anchor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// unixSockets skips a test where an agent sandbox denies unix sockets; in CI that is a failure.
func unixSockets(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, syscall.EPERM) {
		return
	}
	if os.Getenv("CI") == "true" {
		t.Fatalf("unix sockets denied in CI: %v", err)
	}
	t.Skipf("unix sockets denied here: %v", err)
}

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	unixSockets(t, err)
	if err != nil {
		t.Fatal(err)
	}
	conns := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "pair")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c.(*net.UnixConn) //nolint:forcetypeassert // a unix socketpair
		t.Cleanup(func() { _ = c.Close() })
	}
	return conns[0], conns[1]
}

// session runs serveConn on one end of a pair and returns the collector's end, the hello it read and
// a channel with serveConn's result.
func session(t *testing.T, l *Log) (*net.UnixConn, link.Hello, <-chan error) {
	return sessionWith(t, l, &cosignFeed{log: slog.New(slog.DiscardHandler)})
}

func sessionWith(t *testing.T, l *Log, f *cosignFeed) (*net.UnixConn, link.Hello, <-chan error) {
	t.Helper()
	server, collector := socketPair(t)
	done := make(chan error, 1)
	go func() { done <- serveConn(t.Context(), server, l, f) }()
	m, err := link.Read(collector)
	hello, ok := m.(link.Hello)
	if err != nil || !ok {
		t.Fatalf("hello: %+v, %v", m, err)
	}
	return collector, hello, done
}

func send(t *testing.T, c *net.UnixConn, ms ...link.Message) {
	t.Helper()
	for _, m := range ms {
		if err := link.Write(c, m); err != nil {
			t.Fatal(err)
		}
	}
}

func result(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("serveConn did not return")
		return nil
	}
}

func recs(first, last uint64) link.Records {
	var out link.Records
	for s := first; s <= last; s++ {
		out = append(out, link.Record{Seq: s, Leaf: leaf(s)})
	}
	return out
}

func TestAConnectionStreamsIntoTheLog(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	seal := entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("shard"))}
	health := entry.Health{State: entry.StateOK}
	conn, hello, done := session(t, l)
	if hello != (link.Hello{}) {
		t.Fatalf("hello of an empty log: %+v", hello)
	}
	send(t, conn, recs(1, 3), seal, health, recs(4, 5))
	_ = conn.Close()
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
	conn, hello, done = session(t, l) // the next connection resumes after what the first logged
	if hello != (link.Hello{Last: 5, First: 4, Root: rootOver(t, 4, 5)}) {
		t.Fatalf("hello %+v", hello)
	}
	_ = conn.Close()
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	want := []entry.Body{entry.Batch{First: 1, Last: 3, Root: rootOver(t, 1, 3)}, seal, health,
		entry.Batch{First: 4, Last: 5, Root: rootOver(t, 4, 5)}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("log %v, want %v", got, want)
	}
}

func TestAConnectionCutsBatchesOnItsTick(t *testing.T) {
	dir, k := t.TempDir(), newKeys(t)
	c := &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	conn, _, done := session(t, l)
	send(t, conn, recs(1, 2))
	c.advance(CutEvery)
	time.Sleep(5 * TickEvery) // a tick cuts 1-2 now; without it, the end of the connection would cut 1-3
	send(t, conn, recs(3, 3))
	_ = conn.Close()
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	want := []entry.Body{entry.Batch{First: 1, Last: 2, Root: rootOver(t, 1, 2)}, entry.Batch{First: 3, Last: 3, Root: rootOver(t, 3, 3)}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("log %v, want %v", got, want)
	}
}

func TestAStreamErrorEndsTheConnectionNotTheLog(t *testing.T) {
	for name, m := range map[string]link.Message{
		"a gap":                   recs(3, 3),
		"a hello from the client": link.Hello{},
	} {
		t.Run(name, func(t *testing.T) {
			dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
			l := openLog(t, config(dir, k, c))
			defer closeLog(t, l)
			conn, _, done := session(t, l)
			send(t, conn, recs(1, 1), m)
			if err := result(t, done); !errors.Is(err, ErrStream) || l.Broken() != nil {
				t.Fatalf("serveConn = %v, log broken: %v", err, l.Broken())
			}
			if l.Resume().Last != 1 { // what came before the error is logged
				t.Fatalf("resume %+v", l.Resume())
			}
		})
	}
}

func TestAMalformedFrameEndsTheConnection(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	defer closeLog(t, l)
	conn, _, done := session(t, l)
	if _, err := conn.Write([]byte{0, 0, 0, 1, 9}); err != nil {
		t.Fatal(err)
	}
	if err := result(t, done); err == nil || l.Broken() != nil {
		t.Fatalf("serveConn = %v, log broken: %v", err, l.Broken())
	}
}

func TestAConflictingSealBreaksTheLog(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	defer func() { _ = l.Close(t.Context()) }()
	conn, _, done := session(t, l)
	send(t, conn, recs(1, 3), entry.Seal{First: 1, Last: 3, SHA256: leaf(1)}, entry.Seal{First: 1, Last: 3, SHA256: leaf(2)})
	if err := result(t, done); err == nil || l.Broken() == nil {
		t.Fatalf("serveConn = %v, log broken: %v", err, l.Broken())
	}
}

func TestAdmit(t *testing.T) {
	for _, c := range []struct {
		peer unixsock.Peer
		err  error
		want string
	}{
		{unixsock.Peer{UID: 7}, nil, ""},
		{unixsock.Peer{UID: 0}, nil, CauseUID},
		{unixsock.Peer{UID: 8}, nil, CauseUID},
		{unixsock.Peer{UID: 7}, errors.New("no creds"), CausePeerError},
	} {
		if got := admit(c.peer, c.err, 7); got != c.want {
			t.Errorf("admit(%+v, %v) = %q, want %q", c.peer, c.err, got, c.want)
		}
	}
}

// Serve refuses a peer that is not the collector without a hello, then serves the collector.
func TestServeTakesOnlyTheCollector(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	sock := filepath.Join(t.TempDir(), "ledger.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	unixSockets(t, err)
	if err != nil {
		t.Fatal(err)
	}
	for name, uid := range map[string]int{"another uid": os.Getuid() + 1, "the collector": os.Getuid()} {
		t.Run(name, func(t *testing.T) {
			l := openLog(t, config(dir, k, c))
			defer closeLog(t, l)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			var journal bytes.Buffer // read only after Serve returned
			go func() {
				done <- Serve(ctx, ln, Control{}, l, uid, Relay{}, slog.New(slog.NewJSONHandler(&journal, nil)))
			}()
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close() //nolint:errcheck // test end
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			m, err := link.Read(conn)
			if refused := uid != os.Getuid(); refused != errors.Is(err, io.EOF) || (!refused && m == nil) {
				t.Fatalf("read %+v, %v", m, err)
			}
			cancel()
			if err := result(t, done); !errors.Is(err, context.Canceled) {
				t.Fatalf("Serve = %v", err)
			}
			admitted := strings.Contains(journal.String(), "admitted the collector") &&
				strings.Contains(journal.String(), `"rule_version":"`+RuleVersion+`"`)
			if refused := uid != os.Getuid(); admitted == refused {
				t.Fatalf("journal %s: admitted %v for a refused peer %v", journal.String(), admitted, refused)
			}
		})
		ln, err = net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"}) // Serve closed it
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = ln.Close()
}

func TestRefusalSummaryNamesItsRule(t *testing.T) {
	var buf bytes.Buffer
	ref := &refusals{causes: map[string]uint64{}}
	ref.add(CauseUID, 1000)
	ref.add(CauseUID, 1001)
	ref.report(slog.New(slog.NewJSONHandler(&buf, nil)))
	got := buf.String()
	for _, want := range []string{`"uid":2`, `"last_uid":1001`, `"rule_version":"` + RuleVersion + `"`} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %s lacks %s", got, want)
		}
	}
	buf.Reset()
	ref.report(slog.New(slog.NewJSONHandler(&buf, nil)))
	if buf.Len() != 0 {
		t.Errorf("a minute without refusals logged %s", buf.String())
	}
}

func TestAConnectionSendsTheCoveredSealOnce(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	defer l.Close(t.Context()) //nolint:errcheck // test end
	f := cosigntest.New(t)
	path := filepath.Join(t.TempDir(), cosign.Name)
	feed := &cosignFeed{relay: Relay{Path: path, Keys: f.Keys}, log: slog.New(slog.DiscardHandler)}
	conn, _, done := sessionWith(t, l, feed)
	seal := entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("shard"))}
	send(t, conn, recs(1, 3), seal) // a batch and the seal: the log holds 2 entries
	note := f.Cosigned(t, 2, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC))
	if err := os.WriteFile(path, note, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := link.Read(conn)
	if got, ok := m.(link.Cosigned); err != nil || !ok || got.Seal != seal || !bytes.Equal(got.Note, note) {
		t.Fatalf("read %+v, %v", m, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)) // a second read of the same file sends nothing
	if m, err := link.Read(conn); err == nil {
		t.Fatalf("sent again: %+v", m)
	}
	_ = conn.Close()
	if err := result(t, done); err != nil {
		t.Fatal(err)
	}
}
