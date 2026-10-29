package anchor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// controlTimeout bounds one control connection: the request, the append and the answer.
	controlTimeout = 5 * time.Second
	// answerBytes is the control answer: a status byte, then the log's size big-endian.
	answerBytes   = 9
	statusLogged  = 0
	statusRefused = 1
)

// Control is the ledger's control socket (ADR 0030, point 1) and the one uid it admits, the ledger's own.
type Control struct {
	Listener *net.UnixListener
	UID      int
}

// Request encodes a control request: a two-byte length, then the entry with its body and no time; the
// ledger stamps the time when it logs it.
func Request(body entry.Body) ([]byte, error) {
	switch body.(type) {
	case entry.Announce, entry.Final:
	default:
		return nil, errors.New("anchor: a control request is an announcement or a final entry")
	}
	b, err := entry.Entry{Body: body}.Encode()
	if err != nil {
		return nil, err //nolint:wrapcheck // entry errors carry their context
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...), nil //nolint:gosec // Encode bounds b by entry.MaxBytes
}

// ReadRequest takes one control request off r: anything Request could not have produced is refused.
func ReadRequest(r io.Reader) (entry.Body, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("anchor: control request: %w", err)
	}
	n := binary.BigEndian.Uint16(head[:])
	if n == 0 || int(n) > entry.MaxBytes {
		return nil, fmt.Errorf("anchor: control request of %d bytes", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("anchor: control request: %w", err)
	}
	e, err := entry.Decode(b)
	if err != nil {
		return nil, err //nolint:wrapcheck // entry errors carry their context and never quote b
	}
	switch e.Body.(type) {
	case entry.Announce, entry.Final:
		if e.At == 0 {
			return e.Body, nil
		}
	}
	return nil, errors.New("anchor: a control request is an announcement or a final entry without a time")
}

// serveControl takes the ledger's own control requests one at a time until ctx ends; any other peer is
// refused and summed with the collector socket's refusals.
func serveControl(ctx context.Context, ctl Control, l *Log, ref *refusals, log *slog.Logger) {
	for {
		c, err := ctl.Listener.AcceptUnix()
		if err != nil {
			if ctx.Err() == nil {
				log.Error("control socket stopped", "err", err)
			}
			return
		}
		p, err := unixsock.PeerCred(c)
		if cause := admit(p, err, ctl.UID); cause != "" {
			ref.add("control-"+cause, p.UID)
			_ = c.Close()
			continue
		}
		if err := answer(ctx, c, l); err != nil {
			log.Warn("control request not answered", "err", err, "peer_pid", p.PID)
		}
	}
}

func answer(ctx context.Context, c *net.UnixConn, l *Log) error {
	defer c.Close() //nolint:errcheck // one request per connection
	if err := c.SetDeadline(time.Now().Add(controlTimeout)); err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	body, err := ReadRequest(c)
	if err != nil {
		return err
	}
	var size uint64
	switch b := body.(type) {
	case entry.Announce:
		size, err = l.Announce(ctx, b.Kind)
	case entry.Final:
		size, err = l.Final(ctx, b.NextOrigin)
	}
	status := byte(statusLogged)
	if err != nil {
		status, size = statusRefused, 0
	}
	if _, werr := c.Write(binary.BigEndian.AppendUint64([]byte{status}, size)); werr != nil {
		return errors.Join(err, fmt.Errorf("anchor: control answer: %w", werr))
	}
	return err
}

// Ask sends one control request to the socket at path and returns the log's size once the entry is in.
func Ask(ctx context.Context, path string, body entry.Body) (uint64, error) {
	req, err := Request(body)
	if err != nil {
		return 0, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return 0, fmt.Errorf("anchor: control socket: %w", err)
	}
	defer conn.Close() //nolint:errcheck // one request per connection
	if err := conn.SetDeadline(time.Now().Add(controlTimeout)); err != nil {
		return 0, fmt.Errorf("anchor: %w", err)
	}
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("anchor: control request: %w", err)
	}
	var a [answerBytes]byte
	if _, err := io.ReadFull(conn, a[:]); err != nil {
		return 0, fmt.Errorf("anchor: control answer: %w", err)
	}
	if a[0] != statusLogged {
		return 0, errors.New("anchor: the ledger did not log the request; its journal says why")
	}
	return binary.BigEndian.Uint64(a[1:]), nil
}

// ErrWitnessAway is a relay checkpoint older than the gap WaitCosigned was given: the witness is not
// cosigning, so waiting would only delay the stop.
var ErrWitnessAway = errors.New("anchor: the witness cosigned nothing lately")

// WaitCosigned reads the relay's cosigned checkpoint every poll until its size reaches size, and returns
// it (ADR 0030, point 2). It gives up when ctx ends, and at once when the relay's file is older than gap
// by the host's clock: the relay rewrites it with every cosignature, at least every canary record.
func WaitCosigned(ctx context.Context, relay Relay, size uint64, poll, gap time.Duration) (cosign.Checkpoint, error) {
	if relay.Path == "" {
		return cosign.Checkpoint{}, errors.New("anchor: no relay checkpoint to wait for")
	}
	if fi, err := os.Lstat(relay.Path); err != nil || time.Since(fi.ModTime()) > gap {
		return cosign.Checkpoint{}, errors.Join(ErrWitnessAway, err)
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		cp, err := cosign.Read(relay.Path, relay.Keys)
		if err == nil && cp.Size >= size {
			return cp, nil
		}
		select {
		case <-ctx.Done():
			return cosign.Checkpoint{}, fmt.Errorf("anchor: size %d not cosigned: %w", size, errors.Join(ctx.Err(), err))
		case <-t.C:
		}
	}
}
