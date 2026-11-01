package auditstat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// Interval is how often auditstat asks the kernel (ADR 0038 point 1).
const Interval = 5 * time.Second

// maxDrain bounds the stale datagrams dropped before a request: a socket bound to no group gets only replies.
const maxDrain = 64

// exchange sends a request to the kernel and returns the one datagram that came back and its sender's port.
type exchange func(req []byte) ([]byte, uint32, error)

// Run writes a report to path every Interval until ctx ends. A failed poll writes nothing, so the report stops
// changing and the collector names it (ADR 0038 point 4).
func Run(ctx context.Context, path string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		return fmt.Errorf("auditstat: netlink socket: %w", err)
	}
	defer unix.Close(fd) //nolint:errcheck // nothing was written through it that a close could lose
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("auditstat: receive timeout: %w", err)
	}
	loop(ctx, netlinkExchange(fd), path, Interval)
	return nil
}

// loop polls every interval until ctx ends; it logs the first poll and each change between failing and working.
func loop(ctx context.Context, ask exchange, path string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	failing := false
	for seq := uint64(1); ; seq++ {
		err := poll(ctx, ask, seq, path)
		switch {
		case err != nil && !failing:
			slog.ErrorContext(ctx, "auditstat: no report", "version", Label, "seq", seq, "err", err)
		case err == nil && (failing || seq == 1):
			slog.InfoContext(ctx, "auditstat: reporting", "version", Label, "path", path, "seq", seq)
		}
		failing = err != nil
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// netlinkExchange asks the kernel over the audit netlink socket fd, after dropping what a late reply left there.
func netlinkExchange(fd int) exchange {
	buf := make([]byte, replyBytes+1) // one byte more tells a longer reply apart
	return func(req []byte) ([]byte, uint32, error) {
		for range maxDrain {
			if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
				break
			}
		}
		if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return nil, 0, fmt.Errorf("auditstat: send: %w", err)
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, 0, fmt.Errorf("auditstat: receive: %w", err)
		}
		nl, ok := from.(*unix.SockaddrNetlink)
		if !ok {
			return nil, 0, errors.New("auditstat: a reply from no netlink address")
		}
		return bytes.Clone(buf[:n]), nl.Pid, nil
	}
}

// poll asks the kernel once and writes its answer to path, group-readable for the report's group.
func poll(ctx context.Context, ask exchange, seq uint64, path string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("auditstat: %w", err)
	}
	b, port, err := ask(request(uint32(seq))) //nolint:gosec // a seq wraps after 680 years
	if err != nil {
		return err
	}
	s, err := decodeReply(b, port, uint32(seq)) //nolint:gosec // as above
	if err != nil {
		return err
	}
	if err := wholefile.Write(path, Report{Seq: seq, Status: s}.Encode(), 0o640); err != nil { // group-readable for balistid-collector
		return fmt.Errorf("auditstat: report: %w", err)
	}
	return nil
}
