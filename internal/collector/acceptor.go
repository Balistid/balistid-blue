package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// maxLaurelConns is how many of Laurel's connections are held at once: an old one still being read and
// a new one (ADR 0016, point 1). Further connections wait in the listen backlog.
const maxLaurelConns = 2

// Peer is what the kernel reports about the process at the other end of a connection.
type Peer struct{ UID, PID int }

// Listener yields the connections systemd's socket accepts; *net.UnixListener satisfies it.
type Listener interface {
	AcceptUnix() (*net.UnixConn, error)
}

// Conn is one of Laurel's connections with the peer the kernel reported for it.
type Conn struct {
	*net.UnixConn
	Peer Peer
}

// Refusals counts connections from other uids, for one health summary per minute (refusal_summary_s).
type Refusals struct {
	mu        sync.Mutex
	count     uint64
	first     int64
	last      int64
	lastUID   int
	lastError string
}

// Refused is a summary of the refusals since the last Take.
type Refused struct {
	Count       uint64
	First, Last int64
	LastUID     int
	LastError   string
}

func (r *Refusals) add(at time.Time, uid int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		r.first = at.UnixNano()
	}
	r.count++
	r.last, r.lastUID = at.UnixNano(), uid
	if err != nil {
		r.lastError = err.Error()
	}
}

// Take returns the refusals counted since the last Take and starts afresh.
func (r *Refusals) Take() Refused {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Refused{Count: r.count, First: r.first, Last: r.last, LastUID: r.lastUID, LastError: r.lastError}
	r.count, r.lastError = 0, ""
	return s
}

// Acceptor admits Laurel's uid only, checked with SO_PEERCRED on every accepted connection, and hands
// at most maxLaurelConns connections at a time to the reader (ADR 0016, point 1).
type Acceptor struct {
	ln        Listener
	laurelUID int
	peer      func(*net.UnixConn) (Peer, error)
	now       func() time.Time
	refused   *Refusals
	slots     chan struct{}
	conns     chan Conn
}

// NewAcceptor returns an acceptor for ln that admits laurelUID. A negative uid admits nobody: the
// account could not be resolved, so every peer is refused (R6).
func NewAcceptor(ln Listener, laurelUID int, refused *Refusals, now func() time.Time) *Acceptor {
	return &Acceptor{
		ln: ln, laurelUID: laurelUID, peer: peerCred, now: now, refused: refused,
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
		if err != nil || a.laurelUID < 0 || p.UID != a.laurelUID {
			a.refused.add(a.now(), p.UID, err)
			_ = c.Close()
			<-a.slots
			continue
		}
		a.conns <- Conn{UnixConn: c, Peer: p}
	}
}

// peerCred asks the kernel for the peer's credentials (SO_PEERCRED).
func peerCred(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{UID: -1}, fmt.Errorf("collector: peer: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{UID: -1}, fmt.Errorf("collector: peer: %w", err)
	}
	if credErr != nil {
		return Peer{UID: -1}, fmt.Errorf("collector: peer: %w", credErr)
	}
	if cred == nil {
		return Peer{UID: -1}, errors.New("collector: peer: no credentials")
	}
	return Peer{UID: int(cred.Uid), PID: int(cred.Pid)}, nil
}
