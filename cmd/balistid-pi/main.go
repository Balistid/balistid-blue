// Command balistid-pi watches the host's log from the maintainer's Raspberry Pi (ADR 0031): it follows
// what the Pi's own litewitness cosigned, verifies the relay's entry bundles against it and pushes alerts
// to the phone through ntfy. The token comes from a systemd credential, never from argv or environment.
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/unixsock"
	"github.com/Balistid/balistid-blue/internal/watch"
)

const (
	// memLimit keeps the heap under the unit's MemoryMax.
	memLimit    = 96 << 20
	httpTimeout = 10 * time.Second
	poll        = time.Second
	tokenName   = "ntfy-token"
	maxTokenBuf = 512
	// maxHeader caps a response's status line and headers: the relay's are the host's (Go's default is 10 MiB).
	maxHeader = 16 << 10
)

func main() { os.Exit(run()) }

func run() int {
	origin := flag.String("origin", "", "the log's origin, as the witness lists it")
	witnessURL := flag.String("witness", "", "the Pi's litewitness index page")
	relayURL := flag.String("relay", "", "the relay's base URL, ending with /")
	state := flag.String("state", "/var/lib/balistid-pi", "the Pi's own directory")
	ntfy := flag.String("ntfy", "", "the ntfy topic URL")
	failed := flag.Bool("alert-failed", false, "send one alert that the watching unit failed, then exit")
	quiet := flag.Duration("quiet", 0, "range only (ADR 0036): a shorter announced-quiet cap; 0 keeps announced_quiet_max_h")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	lim := watch.DefaultLimits
	if *quiet != 0 {
		var err error
		if lim, err = lim.WithQuiet(*quiet); err != nil {
			log.Error("pi refused its flags", "err", err)
			return 2
		}
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	token, err := readToken()
	if err != nil {
		log.Error("pi stopped", "err", err)
		return 1
	}
	client := newClient()
	push, err := watch.NewPusher(*ntfy, token, client, time.Now)
	if err != nil {
		log.Error("pi stopped", "err", err)
		return 1
	}
	if *failed {
		if err := push.Send(ctx, watch.KeyFailed, "balistid-pi failed and is restarting: see its journal on the Pi"); err != nil {
			log.Error("alert not sent", "err", err)
			return 1
		}
		return 0
	}
	if err := serve(ctx, push, lim, *origin, *witnessURL, *relayURL, *state, client); err != nil {
		log.Error("pi stopped", "err", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, push *watch.Pusher, lim watch.Limits, origin, witnessURL, relayURL, state string, client *http.Client) error {
	if err := watch.CheckURLs(witnessURL, relayURL); err != nil {
		return err //nolint:wrapcheck // watch errors carry their context
	}
	store, err := watch.OpenStore(state, origin)
	if err != nil {
		return err //nolint:wrapcheck // as above
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Go(func() { push.Run(pctx) })
	if err := unixsock.Notify("READY=1"); err != nil {
		slog.ErrorContext(ctx, "ready notify failed", "err", err)
	}
	return watch.Run(ctx, watch.Config{Origin: origin, Source: watch.Source{Witness: witnessURL, Relay: relayURL, HTTP: client}, //nolint:wrapcheck // as above
		Store: store, Push: push, Limits: lim, Poll: poll, Now: time.Now, Notify: unixsock.Notify})
}

// readToken reads the ntfy token from systemd's credential directory (LoadCredential=).
func readToken() (string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", errors.New("no CREDENTIALS_DIRECTORY: run under the unit's LoadCredential")
	}
	f, err := os.OpenFile(filepath.Join(dir, tokenName), os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // systemd's own directory
	if err != nil {
		return "", err //nolint:wrapcheck // names the file
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxTokenBuf))
	if err != nil {
		return "", err //nolint:wrapcheck // as above
	}
	return strings.TrimSpace(string(b)), nil
}

// newClient reaches the witness, the relay and ntfy directly: no proxy from the environment, no redirect.
func newClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's own type
	t.Proxy = nil
	t.MaxResponseHeaderBytes = maxHeader
	return &http.Client{Timeout: httpTimeout, CheckRedirect: noRedirect, Transport: t}
}

// noRedirect keeps every request on the URL it was given: a redirect could point the Pi elsewhere.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
