package collector

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// pair returns a connected socket pair: the collector's end as a *net.UnixConn and the peer's end.
func pair(t *testing.T) (*net.UnixConn, net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int, name string) net.Conn {
		f := os.NewFile(uintptr(fd), name)
		defer f.Close() //nolint:errcheck // FileConn holds its own copy
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	server, ok := conn(fds[0], "collector").(*net.UnixConn)
	if !ok {
		t.Fatal("not a unix connection")
	}
	return server, conn(fds[1], "laurel")
}

// fakeListener hands out queued connections and blocks while none is queued.
type fakeListener chan *net.UnixConn

func (l fakeListener) AcceptUnix() (*net.UnixConn, error) {
	c, ok := <-l
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func startAcceptor(t *testing.T, ln fakeListener, uid int, peer func(*net.UnixConn) (unixsock.Peer, error)) (*Acceptor, *Refusals) {
	t.Helper()
	refused := &Refusals{}
	a := NewAcceptor(ln, uid, refused, clock)
	if peer != nil {
		a.peer = peer
	}
	go func() { _ = a.Run(t.Context()) }()
	t.Cleanup(func() { close(ln) })
	return a, refused
}

func next(t *testing.T, a *Acceptor) Conn {
	t.Helper()
	select {
	case c := <-a.Conns():
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection admitted")
		return Conn{}
	}
}

func TestLaurelAdmittedWithItsPeer(t *testing.T) {
	ln := make(fakeListener, 1)
	a, refused := startAcceptor(t, ln, os.Getuid(), nil)
	server, _ := pair(t)
	ln <- server
	c := next(t, a)
	if c.Peer.UID != os.Getuid() || c.Peer.PID != os.Getpid() || refused.Take().Count != 0 {
		t.Fatalf("peer %+v", c.Peer)
	}
}

func TestPeerOtherUidRefusedAndCounted(t *testing.T) {
	ln := make(fakeListener, 1)
	_, refused := startAcceptor(t, ln, os.Getuid()+1, nil)
	server, client := pair(t)
	ln <- server
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := client.Read(make([]byte, 1)); n != 0 || err == nil || os.IsTimeout(err) {
		t.Fatalf("the refused peer read %d bytes, %v; want the connection closed", n, err)
	}
	if got := refused.Take(); got.Count != 1 || got.LastUID != os.Getuid() || got.First != noon || got.Causes[CauseUID] != 1 {
		t.Fatalf("refusals %+v", got)
	}
	if got := refused.Take(); got.Count != 0 || got.Causes != nil {
		t.Fatalf("Take did not reset: %+v", got)
	}
}

func TestUnresolvedLaurelRefusesEveryone(t *testing.T) {
	ln := make(fakeListener, 1)
	_, refused := startAcceptor(t, ln, -1, func(*net.UnixConn) (unixsock.Peer, error) { return unixsock.Peer{UID: -1}, nil })
	server, client := pair(t)
	ln <- server
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Read(make([]byte, 1))
	if got := refused.Take(); got.Count != 1 || len(got.Causes) != 1 || got.Causes[CauseUnresolved] != 1 {
		t.Fatalf("refusals %+v", got)
	}
}

// Each refused peer is counted under its one cause, and Laurel's uid under none.
func TestRefusalCause(t *testing.T) {
	for _, c := range []struct {
		peer      unixsock.Peer
		err       error
		laurelUID int
		want      string
	}{
		{unixsock.Peer{UID: 7}, nil, 7, ""},
		{unixsock.Peer{UID: 0}, nil, 7, CauseUID},
		{unixsock.Peer{UID: -1}, errors.New("no creds"), 7, CausePeerError},
		{unixsock.Peer{UID: 7}, nil, -1, CauseUnresolved},
		{unixsock.Peer{UID: -1}, errors.New("no creds"), -1, CausePeerError},
	} {
		if got := refusal(c.peer, c.err, c.laurelUID); got != c.want {
			t.Errorf("refusal(%+v, %v, %d) = %q, want %q", c.peer, c.err, c.laurelUID, got, c.want)
		}
	}
}

func TestRefusalWhileLaurelConnected(t *testing.T) {
	ln := make(fakeListener, 2)
	var calls atomic.Int32
	a, refused := startAcceptor(t, ln, os.Getuid(), func(c *net.UnixConn) (unixsock.Peer, error) {
		if calls.Add(1) == 1 {
			return unixsock.PeerCred(c)
		}
		return unixsock.Peer{UID: os.Getuid() + 1, PID: 1}, nil
	})
	first, _ := pair(t)
	ln <- first
	held := next(t, a)
	other, client := pair(t)
	ln <- other
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Read(make([]byte, 1))
	if got := refused.Take(); got.Count != 1 || held.UnixConn != first {
		t.Fatalf("refusals %+v while Laurel's connection is held", got)
	}
}

func TestThirdConnectionWaits(t *testing.T) {
	ln := make(fakeListener, 3)
	a, _ := startAcceptor(t, ln, os.Getuid(), nil)
	for range 3 {
		c, _ := pair(t)
		ln <- c
	}
	next(t, a)
	next(t, a)
	time.Sleep(100 * time.Millisecond)
	if len(ln) != 1 {
		t.Fatalf("%d connections left in the backlog, want the third", len(ln))
	}
	a.Done()
	next(t, a)
	if len(ln) != 0 {
		t.Fatal("the third connection was not taken after a slot freed")
	}
}
