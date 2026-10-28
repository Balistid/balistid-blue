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
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangeguest"
)

const (
	ledgerKeyArg = "ledger-key"
	ledgerKeyDir = "/etc/balistid"
	ledgerLog    = "/var/lib/balistid/ledger/log"
	// ledgerOrigin names the range's log; the host's comes from balistid-install.
	ledgerOrigin = "balistid-range/log"
)

// ledgerKey writes the range's checkpoint key into dir before the ledger starts (range unit
// balistid-range-ledger-key): the range has no balistid-install, and a key made in the VM leaves none
// in the image. The private key is root's 0600 file the ledger's unit loads as a credential.
func ledgerKey(dir string) error {
	skey, vkey, err := note.GenerateKey(rand.Reader, ledgerOrigin)
	if err != nil {
		return fmt.Errorf("ledger key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // root's /etc, readable as /etc is
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
	f := client.FileFetcher{Root: root}
	cp, _, _, err := client.FetchCheckpoint(ctx, f.ReadCheckpoint, v, ledgerOrigin)
	if err != nil {
		return 0, fmt.Errorf("checkpoint: %w", err)
	}
	next := uint64(1)
	for idx := uint64(0); idx*layout.EntryBundleWidth < cp.Size; idx++ {
		b, err := client.GetEntryBundle(ctx, f.ReadEntryBundle, idx, cp.Size)
		if err != nil {
			return 0, fmt.Errorf("bundle %d: %w", idx, err)
		}
		for _, raw := range b.Entries {
			e, err := entry.Decode(raw)
			if err != nil {
				return 0, fmt.Errorf("bundle %d: %w", idx, err)
			}
			if batch, ok := e.Body.(entry.Batch); ok {
				if batch.First != next {
					return 0, fmt.Errorf("batch %d-%d after %d", batch.First, batch.Last, next-1)
				}
				next = batch.Last + 1
			}
		}
	}
	return next - 1, nil
}

func ledgerKeyMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + ledgerKeyArg + " (no arguments): " + strings.Join(args, " "))
	}
	return ledgerKey(ledgerKeyDir)
}
