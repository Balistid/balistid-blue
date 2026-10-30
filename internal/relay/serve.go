package relay

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	entriesDir  = "/tile/entries/"
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

	mu     sync.Mutex
	served uint64
}

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
	s := &Server{root: root, path: filepath.Join(state, cosign.ServedName), origin: origin, slots: make(chan struct{}, maxInFlight)}
	if err := s.record(0); err != nil {
		_ = root.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the log.
func (s *Server) Close() error { return s.root.Close() } //nolint:wrapcheck // read-only

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	name, end, ok := bundlePath(r.URL)
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := cosign.ReadFile(s.root, name, maxBundle)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		http.NotFound(w, r)
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "relay: bundle not read", "err", err)
		http.Error(w, "not read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	if _, err := w.Write(b); err != nil { //nolint:gosec // the log's bytes, as octet-stream with nosniff, to the Pi only
		return
	}
	if err := s.grow(end); err != nil {
		slog.ErrorContext(r.Context(), "relay: served record not written", "err", err)
	}
}

// bundlePath accepts only /tile/entries/<N>[.p/<W>] exactly as Tessera writes it, with no query, and
// returns the file's name in the log and the number of entries the bundle ends at.
func bundlePath(u *url.URL) (string, uint64, bool) {
	p := u.EscapedPath()
	if u.RawQuery != "" || u.ForceQuery || !strings.HasPrefix(p, entriesDir) {
		return "", 0, false
	}
	n, w, err := layout.ParseTileIndexPartial(strings.TrimPrefix(p, entriesDir))
	if err != nil || "/"+layout.EntriesPath(n, w) != p || n > (1<<63)/layout.EntryBundleWidth {
		return "", 0, false
	}
	width := uint64(w)
	if w == 0 {
		width = layout.EntryBundleWidth
	}
	return strings.TrimPrefix(p, "/"), n*layout.EntryBundleWidth + width, true
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

// Listen opens addr (ip:port) for the server with IP_FREEBIND, so the relay starts before WireGuard
// has the address and its submitting does not wait on it.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) { serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1) })
		return errors.Join(err, serr)
	}}
	ln, err := lc.Listen(ctx, "tcp4", addr)
	if err != nil {
		return nil, err //nolint:wrapcheck // names the address
	}
	return ln, nil
}

// Serve serves h on ln until ctx ends, with the timeouts and header cap a server facing the network
// needs (ENGINEERING.md 7).
func Serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 4 << 10}
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
