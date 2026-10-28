package unixsock

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
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

func TestPeerCred(t *testing.T) {
	a, _ := socketPair(t)
	p, err := PeerCred(a)
	if err != nil {
		t.Fatal(err)
	}
	if p.UID != os.Getuid() || p.PID != os.Getpid() {
		t.Fatalf("peer %+v, want uid %d pid %d", p, os.Getuid(), os.Getpid())
	}
}

func TestPeerCredOfClosedConnFails(t *testing.T) {
	a, _ := socketPair(t)
	_ = a.Close()
	if p, err := PeerCred(a); err == nil || p.UID != -1 {
		t.Fatalf("closed conn: %+v, %v", p, err)
	}
}

func TestNotify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	unixSockets(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_SOCKET", path)
	if err := Notify("WATCHDOG=1"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "WATCHDOG=1" {
		t.Fatalf("read %q, %v", b[:n], err)
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("without NOTIFY_SOCKET: %v", err)
	}
}
