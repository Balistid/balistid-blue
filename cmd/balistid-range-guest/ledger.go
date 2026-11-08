package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
)

const (
	ledgerKeyArg = "ledger-key"
	ledgerKeyDir = "/etc/balistid"
	ledgerLog    = "/var/lib/balistid/ledger/log"
	ledgerSocket = "/run/balistid-ledger/ledger.sock"
	// ledgerOrigin names the range's log; the host's comes from balistid-install.
	ledgerOrigin = "balistid-range/log"
	// ledgerBundleBytes caps a bundle file: a full bundle of entries at their largest, each after its length.
	ledgerBundleBytes = layout.EntryBundleWidth * (2 + entry.MaxBytes)
)

// ledgerKey writes the range's checkpoint key into dir before the ledger starts (range unit
// balistid-range-ledger-key): the range has no balistid-install, and a key made in the VM leaves none
// in the image. The private key is root's 0600 file the ledger's unit loads as a credential.
func ledgerKey(dir string) error {
	skey, vkey, err := note.GenerateKey(rand.Reader, ledgerOrigin)
	if err != nil {
		return fmt.Errorf("ledger key: %w", err)
	}
	if err := mkdirOpen(dir); err != nil {
		return fmt.Errorf("ledger key: %w", err)
	}
	for _, f := range []struct {
		name, body string
		mode       os.FileMode
	}{{"ledger-key", skey, 0o600}, {"ledger-key.pub", vkey, 0o644}} {
		if err := writeNew(filepath.Join(dir, f.name), f.body+"\n", f.mode); err != nil {
			return fmt.Errorf("ledger key: %w", err)
		}
	}
	return nil
}

// ledgerAnchored is "yes" once the ledger's log, under a checkpoint the range key signed, has batches
// from seq 1 without a gap or an overlap through what the collector last committed; else an error.
func ledgerAnchored(ctx context.Context) string {
	committed := rangeguest.LastCommitted(output(ctx, "/usr/bin/journalctl", "-u", "balistid-collector.service", "-o", "cat", "--no-pager"))
	if committed == 0 {
		return "error: the collector journaled no commit"
	}
	v, err := note.NewVerifier(readTrim(filepath.Join(ledgerKeyDir, "ledger-key.pub")))
	if err != nil {
		return "error: range ledger key: " + err.Error()
	}
	for deadline := time.Now().Add(waitLimit); ; time.Sleep(time.Second) {
		last, err := ledgerBatches(ctx, ledgerLog, v)
		if err == nil && last >= committed {
			return "yes"
		}
		if time.Now().After(deadline) {
			if err != nil {
				return "error: " + err.Error()
			}
			return fmt.Sprintf("error: batches end at %d, the collector committed %d", last, committed)
		}
	}
}

// ledgerBatches checks the batches of the log at root under its signed checkpoint and returns their
// last seq: each must start where the one before ended.
func ledgerBatches(ctx context.Context, root string, v note.Verifier) (uint64, error) {
	next, gap := uint64(1), error(nil)
	_, err := eachEntry(ctx, root, v, func(_ uint64, e entry.Entry) {
		batch, ok := e.Body.(entry.Batch)
		switch {
		case !ok || gap != nil:
		case batch.First != next:
			gap = fmt.Errorf("batch %d-%d after %d", batch.First, batch.Last, next-1)
		default:
			next = batch.Last + 1
		}
	})
	if err := errors.Join(err, gap); err != nil {
		return 0, err
	}
	return next - 1, nil
}

func ledgerKeyMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + ledgerKeyArg + " (no arguments): " + strings.Join(args, " "))
	}
	return ledgerKey(ledgerKeyDir)
}
