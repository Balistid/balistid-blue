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
const maxDrain = 2 * maxRules

// link is the audit netlink socket as a poll uses it: send drops what a late reply left and sends a request, recv
// returns the next datagram and its sender's port.
type link struct {
	send func(req []byte) error
	recv func() ([]byte, uint32, error)
}

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
	loop(ctx, netlinkLink(fd), path, Interval)
	return nil
}

// loop polls every interval until ctx ends; it logs the first poll and each change between failing and working.
func loop(ctx context.Context, l link, path string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	failing := false
	for seq := uint64(1); ; seq++ {
		err := poll(ctx, l, seq, path)
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

// netlinkLink asks the kernel over the audit netlink socket fd.
func netlinkLink(fd int) link {
	buf := make([]byte, nlmsgAlign(unix.SizeofNlMsghdr+maxRuleMessage)+1) // one byte more tells a longer reply apart
	return link{
		send: func(req []byte) error {
			for range maxDrain {
				if _, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err != nil {
					break
				}
			}
			if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
				return fmt.Errorf("auditstat: send: %w", err)
			}
			return nil
		},
		recv: func() ([]byte, uint32, error) {
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				return nil, 0, fmt.Errorf("auditstat: receive: %w", err)
			}
			nl, ok := from.(*unix.SockaddrNetlink)
			if !ok {
				return nil, 0, errors.New("auditstat: a reply from no netlink address")
			}
			return bytes.Clone(buf[:n]), nl.Pid, nil
		},
	}
}

// poll asks the kernel for its status and then, not before the status came, for its rules, each under its own seq,
// and writes both to path, group-readable for the report's group.
func poll(ctx context.Context, l link, seq uint64, path string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("auditstat: %w", err)
	}
	getSeq, listSeq := uint32(2*seq), uint32(2*seq+1) //nolint:gosec // a seq wraps after 340 years
	if err := l.send(request(getSeq)); err != nil {
		return err
	}
	b, port, err := l.recv()
	if err != nil {
		return err
	}
	s, err := decodeReply(b, port, getSeq)
	if err != nil {
		return err
	}
	if err := l.send(listRequest(listSeq)); err != nil {
		return err
	}
	rules, err := readRules(l.recv, listSeq)
	if err != nil {
		return err
	}
	if err := wholefile.Write(path, Report{Seq: seq, Status: s, Rules: rules}.Encode(), 0o640); err != nil { // group-readable for balistid-collector
		return fmt.Errorf("auditstat: report: %w", err)
	}
	return nil
}
