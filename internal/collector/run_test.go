package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// closingListener is a fakeListener its owner can close once.
type closingListener struct {
	fakeListener
	once sync.Once
}

func (l *closingListener) Close() error {
	l.once.Do(func() { close(l.fakeListener) })
	return nil
}

// runCollector starts Run on a fake listener and store; cancel stops it and returns Run's error.
func runCollector(t *testing.T) (*closingListener, *fakeStore, *sync.Map, func() error) {
	t.Helper()
	ln := &closingListener{fakeListener: make(fakeListener, 2)}
	st := &fakeStore{}
	var notified sync.Map
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Listener: ln, LaurelUID: os.Getuid(), CanaryDir: t.TempDir(),
			OpenStore: func(context.Context) (Store, error) { return st, nil },
			Notify:    func(s string) error { notified.Store(s, true); return nil },
			Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()
	return ln, st, &notified, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not stop")
			return nil
		}
	}
}

// Lines Laurel already wrote when the collector is told to stop are read, stored and the store closed.
func TestRunStoresWhatLaurelSentBeforeStop(t *testing.T) {
	ln, st, notified, stop := runCollector(t)
	server, client := pair(t)
	ln.fakeListener <- server
	for i := 1; i <= 50; i++ {
		if _, err := fmt.Fprintln(client, event(i, "")); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond) // the store opens and the reader starts
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, ok := notified.Load("READY=1"); !ok {
		t.Fatal("READY=1 was not sent")
	}
	if n := len(st.appended) + len(st.committed); n != 50 || st.closed != 1 || len(st.kinds("stopping")) != 1 {
		t.Fatalf("stored %d of 50 lines, closed %d", n, st.closed)
	}
	if conns := st.kinds("connection"); len(conns) == 0 || conns[0]["causes"].(map[string]any)["collector-start"] != 1.0 {
		t.Fatalf("connection records %v", conns)
	}
}

func TestRunStopsWithLaurelStillConnected(t *testing.T) {
	ln, _, _, stop := runCollector(t)
	server, _ := pair(t) // Laurel connected, writing nothing
	ln.fakeListener <- server
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("stop took %v with an idle connection", took)
	}
}

func TestListenFDRefusesWithoutSystemd(t *testing.T) {
	t.Setenv("LISTEN_PID", "1")
	t.Setenv("LISTEN_FDS", "1")
	if _, err := ListenFD(); err == nil {
		t.Fatal("accepted descriptors passed for another pid")
	}
	if os.Getenv("LISTEN_FDS") != "" {
		t.Fatal("LISTEN_FDS left set")
	}
}

// unixSockets skips where the sandbox denies socket(AF_UNIX); in CI that is a failure, not a skip.
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

func TestListenFD(t *testing.T) {
	if os.Getenv("BALISTID_LISTENFD_CHILD") == "1" {
		t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		ln, err := ListenFD()
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		c, err := ln.AcceptUnix()
		if err == nil {
			_, err = c.Write([]byte("ok"))
		}
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "collector.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unixSockets(t, err)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ln.File()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestListenFD$") //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), "BALISTID_LISTENFD_CHILD=1", "LISTEN_FDS=1")
	cmd.ExtraFiles = []*os.File{f}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "ok" {
		t.Fatalf("child said %q, %v", got, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
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
