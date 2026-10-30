package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

const (
	maxBundle   = layout.EntryBundleWidth * (2 + entry.MaxBytes)
	maxInFlight = 4
	// maxConns caps open connections, idle ones too: each holds memory under the unit's MemoryMax.
	maxConns   = 16
	entriesDir = "/tile/entries/"
)

// Server serves the log's entry bundles, and nothing else, to the Pi (ADR 0031): a path counts only in
// Tessera's canonical form, read inside an os.Root of the log without following a link out of it, capped,
// a regular file only. It records in its served file how many of the log's first entries it served in
// full, which the announce client waits for (ADR 0030, point 4).
type Server struct {
	root   *os.Root
	path   string // the served record
	origin string
	slots  chan struct{}

	now func() time.Time

	mu     sync.Mutex
	served uint64
	counts map[string]int // decisions since logged
	logged time.Time
}

// serveRule names the rules a serving decision follows, in its log line.
const serveRule = "balistid/relay-serve v1"

// NewServer opens the log read-only and starts the served record at zero: a new start may follow a
// rollover, and the Pi has to read the new log's entries again.
func NewServer(logDir, state, origin string) (*Server, error) {
	if !filepath.IsAbs(logDir) || !filepath.IsAbs(state) || origin == "" {
		return nil, errors.New("relay: server: an absolute log, state and an origin")
	}
	root, err := os.OpenRoot(logDir)
	if err != nil {
		return nil, err //nolint:wrapcheck // names the directory
	}
	s := &Server{root: root, path: filepath.Join(state, cosign.ServedName), origin: origin, slots: make(chan struct{}, maxInFlight),
		now: time.Now, counts: map[string]int{}}
	if err := s.record(0); err != nil {
		_ = root.Close()
		return nil, err
	}
	return s, nil
}

// Close logs the decisions not yet summarized and releases the log.
func (s *Server) Close() error {
	s.mu.Lock()
	s.summarize()
	s.mu.Unlock()
	return s.root.Close() //nolint:wrapcheck // read-only
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.decide("busy")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		s.decide("method")
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	n, p, end, ok := bundlePath(r.URL)
	if !ok {
		s.decide("path")
		http.NotFound(w, r)
		return
	}
	b, err := s.bundle(n, p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.decide("missing")
		http.NotFound(w, r)
		return
	case err != nil:
		s.decide("unreadable")
		slog.ErrorContext(r.Context(), "relay: bundle not read", "err", err)
		http.Error(w, "not read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	// counted only once the kernel took the whole answer: a Write alone may still sit in a buffer
	_, err = w.Write(b) //nolint:gosec // the log's bytes, as octet-stream with nosniff, to the Pi only
	if err == nil {
		err = http.NewResponseController(w).Flush()
	}
	if err != nil {
		s.decide("unsent")
		return
	}
	if err := s.grow(end); err != nil {
		slog.ErrorContext(r.Context(), "relay: served record not written", "err", err)
		return
	}
	s.decide("served")
}

// bundle reads bundle n of width p (0: full). A partial one that Tessera already replaced by its full
// bundle is served as that bundle's first p entries: a reader gets, and is recorded for, what it asked.
func (s *Server) bundle(n uint64, p uint8) ([]byte, error) {
	b, err := cosign.ReadFile(s.root, layout.EntriesPath(n, p), maxBundle)
	if p == 0 || !errors.Is(err, fs.ErrNotExist) {
		return b, err //nolint:wrapcheck // names the file
	}
	full, err := cosign.ReadFile(s.root, layout.EntriesPath(n, 0), maxBundle)
	if err != nil {
		return nil, err //nolint:wrapcheck // as above
	}
	return prefix(full, int(p))
}

// prefix is the first n entries of a bundle, each a 2-byte length and its bytes.
func prefix(b []byte, n int) ([]byte, error) {
	off := 0
	for range n {
		if len(b)-off < 2 {
			return nil, errors.New("relay: bundle shorter than its prefix")
		}
		off += 2 + int(binary.BigEndian.Uint16(b[off:]))
		if off > len(b) {
			return nil, errors.New("relay: bundle shorter than its prefix")
		}
	}
	return b[:off], nil
}

// bundlePath accepts only /tile/entries/<N>[.p/<W>] exactly as Tessera writes it, with no query, and
// returns the bundle, its width (0: full) and the number of entries it ends at.
func bundlePath(u *url.URL) (uint64, uint8, uint64, bool) {
	p := u.EscapedPath()
	if u.RawQuery != "" || u.ForceQuery || !strings.HasPrefix(p, entriesDir) {
		return 0, 0, 0, false
	}
	n, w, err := layout.ParseTileIndexPartial(strings.TrimPrefix(p, entriesDir))
	if err != nil || "/"+layout.EntriesPath(n, w) != p || n > (1<<63)/layout.EntryBundleWidth {
		return 0, 0, 0, false
	}
	width := uint64(w)
	if w == 0 {
		width = layout.EntryBundleWidth
	}
	return n, w, n*layout.EntryBundleWidth + width, true
}

// decide counts a serving decision and logs the counts at most once a minute, with the rule they follow
// (ENGINEERING.md 3): a peer cannot flood the journal by asking.
func (s *Server) decide(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[reason]++
	if s.now().Sub(s.logged) >= time.Minute {
		s.summarize()
	}
}

// summarize logs the decisions counted since the last summary, if any; s.mu is held.
func (s *Server) summarize() {
	if len(s.counts) == 0 {
		return
	}
	args := []any{"rule", serveRule, "entries_served", s.served}
	for _, k := range slices.Sorted(maps.Keys(s.counts)) {
		args = append(args, k, s.counts[k])
	}
	slog.Info("relay: bundle decisions", args...)
	s.logged = s.now()
	clear(s.counts)
}

// grow records end when it passes what was served before; the file is written only then.
func (s *Server) grow(end uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if end <= s.served {
		return nil
	}
	return s.recordLocked(end)
}

func (s *Server) record(end uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordLocked(end)
}

func (s *Server) recordLocked(end uint64) error {
	// The announce client reads it through the relay's group (ADR 0030, point 2).
	if err := wholefile.Write(s.path, cosign.AppendServed(nil, s.origin, end), 0o640); err != nil {
		return err //nolint:wrapcheck // names the file
	}
	s.served = end
	return nil
}

// Listen opens addr, an IPv4 address and port, never a wildcard or a name, for the server with
// IP_FREEBIND, so the relay starts before WireGuard has the address and its submitting does not wait on it.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().Is4() || ap.Addr().IsUnspecified() {
		return nil, errors.New("relay: -listen must be one IPv4 address and port")
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1) })
		return errors.Join(err, serr)
	}}
	ln, err := lc.Listen(ctx, "tcp4", addr)
	if err != nil {
		return nil, err //nolint:wrapcheck // names the address
	}
	return &capped{Listener: ln, slots: make(chan struct{}, maxConns), closed: make(chan struct{})}, nil
}

// capped accepts a connection only while fewer than its slots are open; the rest wait in the backlog.
// Closing it ends a wait for a slot too, so a server shutting down never hangs in Accept.
type capped struct {
	net.Listener
	slots  chan struct{}
	closed chan struct{}
	once   sync.Once
}

func (l *capped) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close() //nolint:wrapcheck // the listener's own error
}

func (l *capped) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err //nolint:wrapcheck // the listener's own error
	}
	return &slotConn{Conn: c, free: func() { <-l.slots }}, nil
}

type slotConn struct {
	net.Conn
	once sync.Once
	free func()
}

func (c *slotConn) Close() error {
	c.once.Do(c.free)
	return c.Conn.Close() //nolint:wrapcheck // the connection's own error
}

// Serve serves h on ln until ctx ends, with the timeouts and header cap a server facing the network
// needs (ENGINEERING.md 7).
func Serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 4 << 10} // a bundle is at most 66 KB
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		err := srv.Shutdown(sctx)
		if serr := <-done; !errors.Is(serr, http.ErrServerClosed) {
			err = errors.Join(err, serr)
		}
		return err
	case err := <-done:
		return err
	}
}
