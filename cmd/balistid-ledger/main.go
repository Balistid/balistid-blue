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
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/unixsock"
	"github.com/Balistid/balistid-blue/internal/wholefile"
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
	// announceWait bounds how long a stop waits for its announcement's cosignature (ADR 0030, point 2):
	// a checkpoint every 5 s and the relay's request each second cosign it in about 6 s.
	announceWait = 20 * time.Second
	// finalWait is the install step's: it may wait for the witness a while longer.
	finalWait = time.Minute
	// cosignGap is cosign_gap_s: a relay file older than this means the witness is away.
	cosignGap = time.Minute
	// logRetention is log_retention_days; old logs are checked at start and then hourly.
	logRetention = 400 * 24 * time.Hour
	retireEvery  = time.Hour
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
	relayFile := flag.String("relay", "/var/lib/balistid/relay/"+cosign.Name, "the checkpoint the witness cosigned, as the relay keeps it")
	logKey := flag.String("log-key", "/etc/balistid/ledger-key.pub", "the ledger's checkpoint verifier key")
	witnessKey := flag.String("witness-key", "/etc/balistid/witness.vkey", "the witness's cosignature/v1 verifier key")
	control := flag.String("control", "/run/balistid-ledger/control.sock", "the ledger's control socket (ADR 0030)")
	announce := flag.String("announce", "", "announce shutdown or suspend to the running ledger, wait for the cosignature and exit")
	final := flag.String("final", "", "end the running ledger's log naming this next origin, wait for the cosignature, save it beside the log and exit")
	rollover := flag.String("rollover-from", "", "start the empty -log as the next yearly log after the old log in this directory, then exit")
	flag.Parse()
	if *showNotices {
		fmt.Println(notices)
		return 0
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	// Anchoring never waits for the witness's keys: without them the collector only retires nothing.
	var relay anchor.Relay
	if keys, err := cosign.ReadKeys(*logKey, *witnessKey); err != nil {
		log.Error("verifier keys not read, no cosigned frames for the collector", "err", err)
	} else {
		relay = anchor.Relay{Path: *relayFile, Keys: keys}
	}
	if modes := countSet(*rollover, *announce, *final); modes > 1 {
		log.Error("-rollover-from, -announce and -final exclude each other")
		return 2
	}
	if *rollover != "" {
		if err := rolloverFrom(*dir, *rollover, *keyPath, *witnessKey); err != nil {
			log.Error("rollover refused", "err", err)
			return 1
		}
		return 0
	}
	if *announce != "" || *final != "" {
		if err := ask(*control, *announce, *final, *dir, *logKey, relay); err != nil {
			log.Error("not cosigned", "err", err)
			return 1
		}
		return 0
	}
	if err := serve(*dir, *sock, *control, *keyPath, *witnessKey, relay, log); err != nil {
		log.Error("ledger stopped", "err", err)
		return 1
	}
	return 0
}

// countSet counts the non-empty values.
func countSet(values ...string) int {
	n := 0
	for _, v := range values {
		if v != "" {
			n++
		}
	}
	return n
}

// ask is the client of the control socket (ADR 0030, point 2): it sends one announcement or final entry,
// then waits for a cosigned checkpoint covering it; a cosigned final is saved beside the log with the
// key that verifies it. Whatever the wait gives, the entry stays in the log.
func ask(control, announce, final, dir, logKey string, relay anchor.Relay) error {
	var body entry.Body
	wait := announceWait
	switch {
	case announce != "" && final != "":
		return errors.New("-announce and -final together")
	case announce == "shutdown":
		body = entry.Announce{Kind: entry.AnnounceShutdown}
	case announce == "suspend":
		body = entry.Announce{Kind: entry.AnnounceSuspend}
	case announce != "":
		return fmt.Errorf("-announce %q: shutdown or suspend", announce)
	default:
		body, wait = entry.Final{NextOrigin: final}, finalWait
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	size, err := anchor.Ask(ctx, control, body)
	if err != nil {
		return err //nolint:wrapcheck // anchor errors carry their context
	}
	cp, err := anchor.WaitCosigned(ctx, relay, size, time.Second, cosignGap)
	if err != nil || final == "" {
		return err //nolint:wrapcheck // anchor errors carry their context
	}
	key, err := os.ReadFile(logKey) //nolint:gosec // the key's path is configuration; ReadKeys verified it
	if err != nil {
		return fmt.Errorf("verifier key: %w", err)
	}
	if err := wholefile.Write(filepath.Join(dir, anchor.FinalKeyName), key, 0o640); err != nil {
		return err //nolint:wrapcheck // wholefile errors carry their context
	}
	return wholefile.Write(filepath.Join(dir, anchor.FinalCosignedName), cp.Note, 0o640) //nolint:wrapcheck // as above
}

// rolloverFrom starts dir, empty, as the yearly log after the one in previous, whose saved verifier key
// and the witness's verify its cosigned final entry (ADR 0030, point 6).
func rolloverFrom(dir, previous, keyPath, witnessKey string) error {
	signer, err := signerFrom(keyPath)
	if err != nil {
		return err
	}
	keys, err := cosign.ReadKeys(filepath.Join(previous, anchor.FinalKeyName), witnessKey)
	if err != nil {
		return err //nolint:wrapcheck // cosign errors carry their context
	}
	return anchor.Rollover(context.Background(), anchor.Config{Dir: dir, Signer: signer, CapBytes: capBytes, //nolint:wrapcheck // as above
		CheckpointInterval: checkpointEvery, Now: time.Now}, previous, keys)
}

// signerFrom reads the signing key at keyPath, by default systemd's credential.
func signerFrom(keyPath string) (note.Signer, error) {
	creds := os.Getenv("CREDENTIALS_DIRECTORY")
	if keyPath == "" {
		if creds == "" {
			return nil, errors.New("no -key and no CREDENTIALS_DIRECTORY")
		}
		keyPath = filepath.Join(creds, "ledger-key")
	}
	return readSigner(keyPath, creds)
}

func serve(dir, sock, control, keyPath, witnessKey string, relay anchor.Relay, log *slog.Logger) error {
	signer, err := signerFrom(keyPath)
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
	var wg sync.WaitGroup
	defer wg.Wait()
	retireCtx, stopRetire := context.WithCancel(ctx)
	defer stopRetire() // before wg.Wait, also when serve returns without a signal
	wg.Go(func() {
		retire(retireCtx, anchor.Retirement{Dir: dir, Relay: relay, WitnessKey: witnessKey, Keep: logRetention, Now: time.Now}, log)
	})
	ln, err := listen(sock, 0o666)
	var ctl *net.UnixListener
	if err == nil {
		if ctl, err = listen(control, 0o600); err != nil {
			err = errors.Join(err, ln.Close())
		}
	}
	if err == nil {
		if nerr := unixsock.Notify("READY=1"); nerr != nil {
			log.Error("ready notify failed", "err", nerr)
		}
		err = anchor.Serve(ctx, ln, anchor.Control{Listener: ctl, UID: os.Getuid()}, l, collectorUID, relay, log)
		if errors.Is(err, context.Canceled) {
			err = nil
		}
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
	defer cancel()
	return errors.Join(err, l.Close(closeCtx))
}

// retire deletes old yearly logs past their retention at start and every hour until ctx ends (ADR 0030,
// point 7); what it keeps for want of a verified final, or deletes, is journaled.
func retire(ctx context.Context, r anchor.Retirement, log *slog.Logger) {
	t := time.NewTicker(retireEvery)
	defer t.Stop()
	for {
		retired, err := r.Run()
		if len(retired) > 0 {
			log.Info("old logs deleted", "logs", retired)
		}
		if err != nil {
			log.Warn("old logs", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// readSigner reads the note signing key from path, a regular file only its owner may read and write
// (ENGINEERING 3). In creds, systemd's credentials directory, group read stays: systemd grants a credential
// to the service's uid by an ACL on a 0400 file, whose mask shows as the group's bits.
func readSigner(path, creds string) (note.Signer, error) {
	closed := os.FileMode(0o077)
	if creds != "" && filepath.Dir(path) == filepath.Clean(creds) {
		closed = 0o037
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the key's path is configuration
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	switch {
	case err != nil:
		return nil, fmt.Errorf("signing key: %w", err)
	case !fi.Mode().IsRegular() || fi.Mode().Perm()&closed != 0:
		return nil, fmt.Errorf("signing key %s is not a regular file closed to other users (%v)", path, fi.Mode())
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

// listen binds a socket with mode: the collector's lets any uid connect, SO_PEERCRED decides right after
// accept, before a byte is read, and counts the refusals (ADR 0007, point 2), since the collector's unit has
// no group to share; the control socket is the ledger uid's alone (ADR 0030, point 1).
func listen(path string, mode os.FileMode) (*net.UnixListener, error) {
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return nil, errors.Join(fmt.Errorf("listen: %w", err), ln.Close())
	}
	return ln, nil
}
