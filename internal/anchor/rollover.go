package anchor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
)

// Beside a log once its final entry is cosigned (ADR 0030, point 5): the note, and the key it verifies with.
const (
	FinalCosignedName = "final.cosigned"
	FinalKeyName      = "ledger.vkey"
)

// Rollover starts the next yearly log in cfg.Dir from the old one in previous (ADR 0030, point 6). The
// new log must be empty. previous must hold FinalCosignedName, which keys (the old log's and the
// witness's) verify, and end with the final entry naming cfg's origin; inclusion proofs against the
// cosigned root must hold for it and for the tail from the old log's last batch, which is copied byte for
// byte as the new log's first entries, so the stream resumes as if the log had not changed.
func Rollover(ctx context.Context, cfg Config, previous string, keys cosign.Keys) error {
	cp, err := cosign.Read(filepath.Join(previous, FinalCosignedName), keys)
	if err != nil {
		return fmt.Errorf("anchor: rollover: %w", err)
	}
	tail, err := readTail(ctx, previous, cp, cfg.Signer.Name())
	if err != nil {
		return fmt.Errorf("anchor: rollover from %s: %w", previous, err)
	}
	l, err := Open(ctx, cfg)
	if err != nil {
		return err
	}
	l.mu.Lock()
	switch {
	case l.size != 0:
		err = fmt.Errorf("anchor: rollover into a log of %d entries", l.size)
	case uint64(len(tail)) > l.maxSize-2:
		err = errors.New("anchor: rollover tail over the cap")
	}
	for _, b := range tail {
		if err != nil {
			break
		}
		err = l.appendEncoded(ctx, b)
	}
	l.mu.Unlock()
	return errors.Join(err, l.Close(ctx))
}

// readTail returns the old log's entries from its last batch up to its final entry, without
// announcements or the cap's UNKNOWN, each proven included in cp; the final entry must be cp's last and name next.
func readTail(ctx context.Context, dir string, cp cosign.Checkpoint, next string) ([][]byte, error) {
	p, err := cosign.OpenProven(ctx, dir, cp)
	if err != nil {
		return nil, err //nolint:wrapcheck // cosign errors carry their context
	}
	defer p.Close()   //nolint:errcheck // read-only
	var tail [][]byte // newest first
	for end, n := cp.Size, 0; end > 0; n++ {
		if n == tailBundles {
			return nil, fmt.Errorf("no batch in the last %d bundles", tailBundles)
		}
		idx := (end - 1) / layout.EntryBundleWidth
		b, err := p.Bundle(ctx, idx)
		if err != nil {
			return nil, err //nolint:wrapcheck // as above
		}
		for i := len(b) - 1; i >= 0; i-- {
			at := idx*layout.EntryBundleWidth + uint64(i)
			e, err := p.Prove(ctx, at, b[i])
			if err != nil {
				return nil, err //nolint:wrapcheck // as above
			}
			f, isFinal := e.Body.(entry.Final)
			switch {
			case at == cp.Size-1 && (!isFinal || f.NextOrigin != next):
				return nil, fmt.Errorf("the cosigned log does not end with a final entry naming %q", next)
			case at == cp.Size-1:
				continue
			case isFinal:
				return nil, fmt.Errorf("a final entry at %d before the last", at)
			}
			// The old log's cap stays its own: copied, it would alarm on the new one (ADR 0036, point 5).
			_, announce := e.Body.(entry.Announce)
			if !announce && e.Body != entry.Body(capHealth) {
				tail = append(tail, b[i])
			}
			if _, ok := e.Body.(entry.Batch); ok {
				return reversed(tail), nil
			}
		}
		end = idx * layout.EntryBundleWidth
	}
	return reversed(tail), nil
}

func reversed(b [][]byte) [][]byte {
	out := make([][]byte, 0, len(b))
	for i := len(b) - 1; i >= 0; i-- {
		out = append(out, b[i])
	}
	return out
}
