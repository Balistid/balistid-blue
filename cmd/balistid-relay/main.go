// Command balistid-relay carries the ledger's checkpoints to the witness and keeps the cosigned one
// (ADR 0006, 0026). It runs as its own uid, reads the ledger's log through the ledger's group, holds
// only public keys and reaches only the witness (ADR 0007).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/relay"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// memLimit keeps the heap under the unit's MemoryMax.
	memLimit    = 24 << 20
	every       = time.Second // a new checkpoint every 5 s; cosign_gap_s is 60 s
	httpTimeout = 10 * time.Second
	maxKeyBytes = 4 << 10
)

func main() { os.Exit(run()) }

func run() int {
	logDir := flag.String("log", "/var/lib/balistid/ledger/log", "the ledger's log directory (read only)")
	state := flag.String("state", "/var/lib/balistid/relay", "the relay's own directory")
	logKey := flag.String("log-key", "/etc/balistid/ledger-key.pub", "the ledger's checkpoint verifier key")
	witnessKey := flag.String("witness-key", "/etc/balistid/witness.vkey", "the witness's cosignature/v1 verifier key")
	submit := flag.String("submit", "", "the witness's add-checkpoint URL")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	if err := serve(*logDir, *state, *logKey, *witnessKey, *submit); err != nil {
		log.Error("relay stopped", "err", err)
		return 1
	}
	return 0
}

func serve(logDir, state, logKeyPath, witnessKeyPath, submit string) error {
	lv, err := readVerifier(logKeyPath, note.NewVerifier)
	if err != nil {
		return err
	}
	wv, err := readVerifier(witnessKeyPath, fnote.NewVerifierForCosignatureV1)
	if err != nil {
		return err
	}
	r, err := relay.New(relay.Config{Log: logDir, State: state, Origin: lv.Name(), LogKey: lv, Witness: wv,
		Submit: submit, HTTP: &http.Client{Timeout: httpTimeout, CheckRedirect: noRedirect}})
	if err != nil {
		return err //nolint:wrapcheck // relay errors carry their context
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := unixsock.Notify("READY=1"); err != nil {
		slog.Error("ready notify failed", "err", err)
	}
	r.Run(ctx, every)
	return nil
}

// noRedirect keeps the relay on the one witness URL it was given: a redirect would send the checkpoint
// to a host the unit's address allowlist then has to catch.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// readVerifier reads a public verifier key: no secret, but a size cap and no symlink (ENGINEERING 7).
func readVerifier(path string, parse func(string) (note.Verifier, error)) (note.Verifier, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the key's path is configuration
	if err != nil {
		return nil, fmt.Errorf("verifier key: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	if err != nil || len(b) > maxKeyBytes {
		return nil, errors.Join(fmt.Errorf("verifier key %s: unreadable or too large", path), err)
	}
	v, err := parse(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("verifier key %s: %w", path, err)
	}
	return v, nil
}
