// Command balistid-ledger appends the collector's stream to the anchored log and signs its checkpoints
// (ADR 0006, 0026, 0027). It runs as its own uid, without network or privilege (ADR 0007).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// memLimit keeps the heap under the unit's MemoryMax, its share of rss_mib (512 MiB for floor 0).
	memLimit = 96 << 20
	// capBytes is host_log_cap_gib.
	capBytes        = 10 << 30
	checkpointEvery = 5 * time.Second
	// closeTimeout leaves Tessera its 60 s to publish a checkpoint covering the last batch.
	closeTimeout = 70 * time.Second
	maxKeyBytes  = 4 << 10
)

// notices names what the binary links under a licence other than Apache-2.0, MIT, BSD or ISC (ADR 0026,
// point 3; MPL-2.0 section 3.2).
const notices = "balistid-ledger links github.com/hashicorp/golang-lru/v2 v2.0.7, unmodified, under the Mozilla " +
	"Public License 2.0 (https://mozilla.org/MPL/2.0/); its source: https://github.com/hashicorp/golang-lru/tree/v2.0.7"

func main() { os.Exit(run()) }

func run() int {
	dir := flag.String("log", "/var/lib/balistid/ledger/log", "the log's directory")
	sock := flag.String("socket", "/run/balistid-ledger/ledger.sock", "the socket the collector connects to")
	keyPath := flag.String("key", "", "the checkpoint signing key; default $CREDENTIALS_DIRECTORY/ledger-key")
	showNotices := flag.Bool("notices", false, "print the third-party licence notices and exit")
	flag.Parse()
	if *showNotices {
		fmt.Println(notices)
		return 0
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	if err := serve(*dir, *sock, *keyPath, log); err != nil {
		log.Error("ledger stopped", "err", err)
		return 1
	}
	return 0
}

func serve(dir, sock, keyPath string, log *slog.Logger) error {
	if keyPath == "" {
		creds := os.Getenv("CREDENTIALS_DIRECTORY")
		if creds == "" {
			return errors.New("no -key and no CREDENTIALS_DIRECTORY")
		}
		keyPath = filepath.Join(creds, "ledger-key")
	}
	signer, err := readSigner(keyPath)
	if err != nil {
		return err
	}
	collectorUID, err := unixsock.LookupUID("balistid-collector")
	if err != nil {
		log.Error("collector account not resolved, refusing every peer", "err", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	l, err := anchor.Open(ctx, anchor.Config{Dir: dir, Signer: signer, CapBytes: capBytes,
		CheckpointInterval: checkpointEvery, Now: time.Now})
	if err != nil {
		return err //nolint:wrapcheck // anchor errors carry their context
	}
	ln, err := listen(sock)
	if err == nil {
		if nerr := unixsock.Notify("READY=1"); nerr != nil {
			log.Error("ready notify failed", "err", nerr)
		}
		err = anchor.Serve(ctx, ln, l, collectorUID, log)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
	defer cancel()
	return errors.Join(err, l.Close(closeCtx))
}

// readSigner reads the note signing key from path, a regular file no one else may read (ENGINEERING 3).
func readSigner(path string) (note.Signer, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the key's path is configuration
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, fmt.Errorf("signing key: %w", err)
	case !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("signing key %s is not a regular file only its owner reads (%v)", path, fi.Mode())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	if err != nil || len(b) > maxKeyBytes {
		return nil, errors.Join(errors.New("signing key: unreadable or too large"), err)
	}
	s, err := note.NewSigner(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, errors.New("signing key: not a note signer key") // the error could quote the key
	}
	return s, nil
}

// listen binds the socket, then opens it to its group (the collector's, by the unit): it starts as the
// umask leaves it, closed to the group, so it is never more open than that.
func listen(path string) (*net.UnixListener, error) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // the collector connects through the group; SO_PEERCRED decides
		return nil, errors.Join(fmt.Errorf("listen: %w", err), ln.Close())
	}
	return ln, nil
}
