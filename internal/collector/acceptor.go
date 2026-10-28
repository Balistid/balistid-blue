package collector

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// maxLaurelConns is how many of Laurel's connections are held at once: an old one still being read and
// a new one (ADR 0016, point 1). Further connections wait in the listen backlog.
const maxLaurelConns = 2

// Listener yields the connections systemd's socket accepts; *net.UnixListener satisfies it.
type Listener interface {
	AcceptUnix() (*net.UnixConn, error)
}

// Conn is one of Laurel's connections with the peer the kernel reported for it.
type Conn struct {
	*net.UnixConn
	Peer unixsock.Peer
}

// socketName names the one socket the collector accepts on (ADR 0016, point 1) in its refusal summaries,
// which acceptance counts per socket.
const socketName = "collector.sock"

// Why a peer is refused, each counted on its own in the summary (refusal_summary_s): another uid, no
// credentials from the kernel, or no `_laurel` account to admit.
const (
	CauseUID        = "uid"
	CausePeerError  = "peer_error"
	CauseUnresolved = "laurel_unresolved"
)

// Refusals counts connections from other uids, for one health summary per minute (refusal_summary_s).
type Refusals struct {
	mu        sync.Mutex
	count     uint64
	causes    map[string]uint64
	first     int64
	last      int64
	lastUID   int
	lastError string
}

// Refused is a summary of the refusals since the last Take: how many, how many per cause, and the
// newest one's uid and error as a sample.
type Refused struct {
	Count       uint64
	Causes      map[string]uint64
	First, Last int64
	LastUID     int
	LastError   string
}

func (r *Refusals) add(at time.Time, uid int, cause string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		r.first, r.causes = at.UnixNano(), map[string]uint64{}
	}
	r.count++
	r.causes[cause]++
	r.last, r.lastUID = at.UnixNano(), uid
	if err != nil {
		r.lastError = err.Error()
	}
}

// Take returns the refusals counted since the last Take and starts afresh.
func (r *Refusals) Take() Refused {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Refused{Count: r.count, Causes: r.causes, First: r.first, Last: r.last, LastUID: r.lastUID, LastError: r.lastError}
	r.count, r.causes, r.lastError = 0, nil, ""
	return s
}

// refusal is why the peer p is refused, or "" for Laurel's uid.
func refusal(p unixsock.Peer, err error, laurelUID int) string {
	switch {
	case err != nil:
		return CausePeerError
	case laurelUID < 0:
		return CauseUnresolved
	case p.UID != laurelUID:
		return CauseUID
	}
	return ""
}

// Acceptor admits Laurel's uid only, checked with SO_PEERCRED on every accepted connection, and hands
// at most maxLaurelConns connections at a time to the reader (ADR 0016, point 1).
type Acceptor struct {
	ln        Listener
	laurelUID int
	peer      func(*net.UnixConn) (unixsock.Peer, error)
	now       func() time.Time
	refused   *Refusals
	slots     chan struct{}
	conns     chan Conn
}

// NewAcceptor returns an acceptor for ln that admits laurelUID. A negative uid admits nobody: the
// account could not be resolved, so every peer is refused (R6).
func NewAcceptor(ln Listener, laurelUID int, refused *Refusals, now func() time.Time) *Acceptor {
	return &Acceptor{
		ln: ln, laurelUID: laurelUID, peer: unixsock.PeerCred, now: now, refused: refused,
		slots: make(chan struct{}, maxLaurelConns), conns: make(chan Conn, maxLaurelConns),
	}
}

// Conns delivers admitted connections in the order they were accepted.
func (a *Acceptor) Conns() <-chan Conn { return a.conns }

// Done gives back the slot of a connection the reader finished, so the acceptor takes the next one.
func (a *Acceptor) Done() { <-a.slots }

// Run accepts until ctx is done or the listener fails. It takes a connection only while fewer than
// maxLaurelConns are held, so a further one of Laurel's waits in the backlog instead of being closed.
// The owner closes the listener after cancelling ctx, which ends a pending accept.
func (a *Acceptor) Run(ctx context.Context) error {
	defer close(a.conns)
	for {
		select {
		case a.slots <- struct{}{}:
		case <-ctx.Done():
			return fmt.Errorf("collector: accept: %w", ctx.Err())
		}
		c, err := a.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("collector: accept: %w", ctx.Err())
			}
			return fmt.Errorf("collector: accept: %w", err)
		}
		p, err := a.peer(c)
		if cause := refusal(p, err, a.laurelUID); cause != "" {
			a.refused.add(a.now(), p.UID, cause, err)
			_ = c.Close()
			<-a.slots
			continue
		}
		a.conns <- Conn{UnixConn: c, Peer: p}
	}
}
