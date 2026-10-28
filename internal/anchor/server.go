package anchor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// TickEvery is how often a connection checks for a batch to cut (CutEvery).
	TickEvery = 100 * time.Millisecond
	// idleTimeout drops a connection that sent nothing: the canary commits a record every 30 s, so a
	// live collector is never idle this long, and it reconnects at once.
	idleTimeout  = 5 * time.Minute
	writeTimeout = 5 * time.Second
)

// Refusal causes, as the journal's summary names them.
const (
	CauseUID       = "uid"
	CausePeerError = "peer-error"
)

// admit names why a peer is refused, or "" for the collector.
func admit(p unixsock.Peer, err error, collectorUID int) string {
	switch {
	case err != nil:
		return CausePeerError
	case p.UID != collectorUID:
		return CauseUID
	}
	return ""
}

// refusals sums refused connections for the journal, once a minute (ADR 0027, point 2).
type refusals struct {
	mu     sync.Mutex
	causes map[string]uint64
	uid    int
}

func (r *refusals) add(cause string, uid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.causes[cause]++
	r.uid = uid
}

func (r *refusals) report(log *slog.Logger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.causes) > 0 {
		log.Warn("ledger socket refused connections", "causes", r.causes, "last_uid", r.uid)
		r.causes = map[string]uint64{}
	}
}

// Serve takes the collector's connections on ln, one at a time, and feeds each stream into l until ctx
// ends or l breaks (ADR 0027, points 2 to 4). Any other peer is refused and summed in the journal.
func Serve(ctx context.Context, ln *net.UnixListener, l *Log, collectorUID int, log *slog.Logger) error {
	ref := &refusals{causes: map[string]uint64{}}
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				ref.report(log)
				return
			case <-t.C:
				ref.report(log)
			}
		}
	})
	defer wg.Wait()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("anchor: serve: %w", ctx.Err())
			}
			return fmt.Errorf("anchor: accept: %w", err)
		}
		p, err := unixsock.PeerCred(c)
		if cause := admit(p, err, collectorUID); cause != "" {
			ref.add(cause, p.UID)
			_ = c.Close()
			continue
		}
		err = serveConn(ctx, c, l)
		if l.Broken() != nil {
			return l.Broken()
		}
		log.Info("collector disconnected", "err", err, "resume", l.Resume().Last)
	}
}

// serveConn sends the resume point, then feeds the collector's messages into l, cutting batches on a
// tick, until the connection ends; the waiting batch is then logged.
func serveConn(ctx context.Context, c *net.UnixConn, l *Log) error {
	defer c.Close() //nolint:errcheck // the stream ends here either way
	r := l.Resume()
	if err := c.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	if err := link.Write(c, link.Hello{Last: r.Last, First: r.First, Root: r.Root}); err != nil {
		return fmt.Errorf("anchor: hello: %w", err)
	}
	msgs, errs, done := make(chan link.Message), make(chan error, 1), make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			if err := c.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				errs <- err
				return
			}
			m, err := link.Read(c)
			if err != nil {
				errs <- err
				return
			}
			select {
			case msgs <- m:
			case <-done:
				return
			}
		}
	})
	defer wg.Wait()
	defer c.Close() //nolint:errcheck // unblocks the reader before wg.Wait
	defer close(done)
	tick := time.NewTicker(TickEvery)
	defer tick.Stop()
	for {
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-tick.C:
			if err = l.Tick(ctx); err == nil {
				continue
			}
		case err = <-errs:
			if errors.Is(err, io.EOF) {
				err = nil
			}
		case m := <-msgs:
			if err = feed(ctx, l, m); err == nil {
				continue
			}
		}
		return errors.Join(err, l.Flush(ctx))
	}
}

func feed(ctx context.Context, l *Log, m link.Message) error {
	switch m := m.(type) {
	case link.Records:
		for _, r := range m {
			if err := l.Record(ctx, r); err != nil {
				return err
			}
		}
		return nil
	case entry.Seal:
		return l.Seal(ctx, m)
	case entry.Health:
		return l.Health(ctx, m)
	}
	return fmt.Errorf("%w: %T from the collector", ErrStream, m)
}
