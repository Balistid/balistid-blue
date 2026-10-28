// Package unixsock holds what every Balistid Blue service needs from its local sockets: the peer's
// credentials from the kernel (ADR 0007, point 2) and the readiness and watchdog messages to systemd.
package unixsock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// Peer is what the kernel reports about the process at the other end of a connection.
type Peer struct{ UID, PID int }

// PeerCred asks the kernel for the peer's credentials (SO_PEERCRED).
func PeerCred(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{UID: -1}, fmt.Errorf("unixsock: peer: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{UID: -1}, fmt.Errorf("unixsock: peer: %w", err)
	}
	if credErr != nil {
		return Peer{UID: -1}, fmt.Errorf("unixsock: peer: %w", credErr)
	}
	if cred == nil {
		return Peer{UID: -1}, errors.New("unixsock: peer: no credentials")
	}
	return Peer{UID: int(cred.Uid), PID: int(cred.Pid)}, nil
}

// Notify sends state to systemd over NOTIFY_SOCKET (sd_notify); without the variable it does nothing.
func Notify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("unixsock: notify: %w", err)
	}
	_, err = c.Write([]byte(state))
	return errors.Join(err, c.Close())
}
