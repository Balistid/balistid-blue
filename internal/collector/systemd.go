package collector

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// listenFDStart is the first descriptor systemd passes (sd_listen_fds).
const listenFDStart = 3

// ListenFD returns the one socket systemd passed for this process (LISTEN_PID, LISTEN_FDS) and unsets
// the variables, so nothing this process starts inherits them. Anything else is an error: the
// collector never binds a socket itself (ADR 0016, point 1).
func ListenFD() (*net.UnixListener, error) {
	pid, fds := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	if err := errors.Join(os.Unsetenv("LISTEN_PID"), os.Unsetenv("LISTEN_FDS"), os.Unsetenv("LISTEN_FDNAMES")); err != nil {
		return nil, fmt.Errorf("collector: listen fds: %w", err)
	}
	if pid != strconv.Itoa(os.Getpid()) || fds != "1" {
		return nil, fmt.Errorf("collector: want one socket from systemd for pid %d, got LISTEN_PID=%q LISTEN_FDS=%q",
			os.Getpid(), pid, fds)
	}
	syscall.CloseOnExec(listenFDStart)
	f := os.NewFile(listenFDStart, "collector.sock")
	defer f.Close() //nolint:errcheck // FileListener holds its own copy
	ln, err := net.FileListener(f)
	if err != nil {
		return nil, fmt.Errorf("collector: listen fds: %w", err)
	}
	ul, ok := ln.(*net.UnixListener)
	if !ok {
		return nil, errors.Join(errors.New("collector: the passed socket is not a unix socket"), ln.Close())
	}
	return ul, nil
}
