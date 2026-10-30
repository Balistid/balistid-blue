// Command balistid-relay carries the ledger's checkpoints to the witness and keeps the cosigned one
// (ADR 0006, 0026). It runs as its own uid, reads the ledger's log through the ledger's group, holds
// only public keys and reaches only the witness (ADR 0007).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/relay"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// memLimit keeps the heap under the unit's MemoryMax.
	memLimit    = 24 << 20
	every       = time.Second // a new checkpoint every 5 s; cosign_gap_s is 60 s
	httpTimeout = 10 * time.Second
)

func main() { os.Exit(run()) }

func run() int {
	logDir := flag.String("log", "/var/lib/balistid/ledger/log", "the ledger's log directory (read only)")
	state := flag.String("state", "/var/lib/balistid/relay", "the relay's own directory")
	logKey := flag.String("log-key", "/etc/balistid/ledger-key.pub", "the ledger's checkpoint verifier key")
	witnessKey := flag.String("witness-key", "/etc/balistid/witness.vkey", "the witness's cosignature/v1 verifier key")
	submit := flag.String("submit", "", "the witness's add-checkpoint URL")
	listen := flag.String("listen", "", "ip:port where the Pi fetches entry bundles")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	if err := serve(*logDir, *state, *logKey, *witnessKey, *submit, *listen); err != nil {
		log.Error("relay stopped", "err", err)
		return 1
	}
	return 0
}

func serve(logDir, state, logKeyPath, witnessKeyPath, submit, listen string) error {
	keys, err := cosign.ReadKeys(logKeyPath, witnessKeyPath)
	if err != nil {
		return err //nolint:wrapcheck // cosign errors carry their context
	}
	r, err := relay.New(relay.Config{Log: logDir, State: state, Origin: keys.Origin, LogKey: keys.Log, Witness: keys.Witness,
		Submit: submit, HTTP: newClient()})
	if err != nil {
		return err //nolint:wrapcheck // relay errors carry their context
	}
	if listen == "" {
		return errors.New("no -listen: the Pi reads the log's bundles there (ADR 0031)")
	}
	srv, err := relay.NewServer(logDir, state, keys.Origin)
	if err != nil {
		return err //nolint:wrapcheck // relay errors carry their context
	}
	defer srv.Close() //nolint:errcheck // read-only
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ln, err := relay.Listen(ctx, listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	// a server that stops ends the relay too, so the unit restarts rather than submitting unseen by the Pi
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- relay.Serve(runCtx, ln, srv); cancel() }()
	if err := unixsock.Notify("READY=1"); err != nil {
		slog.Error("ready notify failed", "err", err)
	}
	r.Run(runCtx, every)
	if err := <-served; err != nil || ctx.Err() == nil {
		return errors.Join(errors.New("the bundle server stopped"), err)
	}
	return nil
}

// newClient reaches the witness directly: no proxy from the environment, no redirect.
func newClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the standard library's own type
	t.Proxy = nil
	return &http.Client{Timeout: httpTimeout, CheckRedirect: noRedirect, Transport: t}
}

// noRedirect keeps the relay on the one witness URL it was given: a redirect would send the checkpoint
// to a host the unit's address allowlist then has to catch.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
