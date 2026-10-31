package auditstat

import (
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

// Run writes a report to path every Interval until ctx ends. A failed poll writes nothing, so the report stops
// changing and the collector names it (ADR 0038 point 4); only a change between failing and working is logged.
func Run(ctx context.Context, path string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		return fmt.Errorf("auditstat: netlink socket: %w", err)
	}
	defer unix.Close(fd) //nolint:errcheck // nothing was written through it that a close could lose
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("auditstat: receive timeout: %w", err)
	}
	t := time.NewTicker(Interval)
	defer t.Stop()
	failing := true // the first poll that works is logged too
	for seq := uint64(1); ; seq++ {
		err := poll(ctx, fd, seq, path)
		switch {
		case err != nil && !failing:
			slog.ErrorContext(ctx, "auditstat: no report", "seq", seq, "err", err)
		case err == nil && failing:
			slog.InfoContext(ctx, "auditstat: reporting", "path", path, "seq", seq)
		}
		failing = err != nil
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// poll asks the kernel once and writes its answer to path, group-readable for the report's group.
func poll(ctx context.Context, fd int, seq uint64, path string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("auditstat: %w", err)
	}
	buf := make([]byte, replyBytes+1) // one byte more tells a longer reply apart
	for range maxDrain {
		if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
			break
		}
	}
	if err := unix.Sendto(fd, request(uint32(seq)), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil { //nolint:gosec // a seq wraps after 680 years
		return fmt.Errorf("auditstat: send: %w", err)
	}
	n, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return fmt.Errorf("auditstat: receive: %w", err)
	}
	nl, ok := from.(*unix.SockaddrNetlink)
	if !ok {
		return errors.New("auditstat: a reply from no netlink address")
	}
	s, err := decodeReply(buf[:n], nl.Pid, uint32(seq)) //nolint:gosec // as above
	if err != nil {
		return err
	}
	if err := wholefile.Write(path, Report{Seq: seq, Status: s}.Encode(), 0o640); err != nil { // group-readable for balistid-collector
		return fmt.Errorf("auditstat: report: %w", err)
	}
	return nil
}
