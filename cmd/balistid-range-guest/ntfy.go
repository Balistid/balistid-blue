package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	ntfySinkArg   = "ntfy-sink"
	ntfySinkAddr  = "127.0.0.1:7382"
	ntfySinkTopic = "/balistid-range"
	ntfyPosts     = "/run/balistid-range-ntfy/posts"
	// ntfyToken is the token range/balistid-pi-range.conf gives the watcher (SetCredential).
	ntfyToken    = "range-only"
	sinkMaxBody  = 4 << 10
	sinkMaxLines = 4096
	sinkTimeout  = 10 * time.Second
)

// sink stands in for ntfy behind the Pi's watcher (ADR 0036): per POST to the topic it appends the guest's
// uptime in ms, the alert's tag and whether the range token came. It answers 200 to the token, so the watcher
// never backs off, and 401 without it, until max lines. An alarm trial reads the file against its own uptime.
type sink struct {
	mu    sync.Mutex
	w     io.Writer
	lines int
	max   int
	now   func() (time.Duration, error)
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != ntfySinkTopic {
		http.NotFound(w, r)
		return
	}
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, sinkMaxBody)); err != nil {
		http.Error(w, "body", http.StatusRequestEntityTooLarge)
		return
	}
	at, err := s.now()
	if err != nil {
		http.Error(w, "clock", http.StatusInternalServerError)
		return
	}
	tag := r.Header.Get("Tags")
	if !sinkTag(tag) {
		tag = "-"
	}
	auth := "bad"
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+ntfyToken)) == 1 {
		auth = "ok"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lines >= s.max {
		http.Error(w, "full", http.StatusInsufficientStorage)
		return
	}
	if _, err := fmt.Fprintf(s.w, "%d %s %s\n", at.Milliseconds(), tag, auth); err != nil {
		http.Error(w, "write", http.StatusInternalServerError)
		return
	}
	s.lines++
	if auth != "ok" { // as ntfy refuses a wrong token: the watcher must not count it as sent
		http.Error(w, "token", http.StatusUnauthorized)
	}
}

// sinkTag: an alert key as the watcher sends it, else the line says "-".
func sinkTag(s string) bool {
	if len(s) == 0 || len(s) > 16 {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz") == ""
}

// ntfySinkMain runs the sink in its unit (range/balistid-range-ntfy.service), in the Pi's namespace. The file
// is new for each boot: a restarted sink fails rather than hide the posts before it.
func ntfySinkMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + ntfySinkArg + " (no arguments): " + strings.Join(args, " "))
	}
	f, err := os.OpenFile(ntfyPosts, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("ntfy sink: %w", err)
	}
	defer f.Close() //nolint:errcheck // the process ends
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", ntfySinkAddr)
	if err != nil {
		return fmt.Errorf("ntfy sink: %w", err)
	}
	srv := &http.Server{Handler: &sink{w: f, max: sinkMaxLines, now: uptime}, ReadHeaderTimeout: sinkTimeout,
		ReadTimeout: sinkTimeout, WriteTimeout: sinkTimeout, IdleTimeout: sinkTimeout, MaxHeaderBytes: 8 << 10}
	if err := unixsock.Notify("READY=1"); err != nil {
		return fmt.Errorf("ntfy sink: %w", err)
	}
	return fmt.Errorf("ntfy sink: %w", srv.Serve(ln))
}
