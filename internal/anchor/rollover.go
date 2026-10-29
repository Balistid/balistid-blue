package anchor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
)

// Beside a log once its final entry is cosigned (ADR 0030, point 5): the note, and the key it verifies with.
const (
	FinalCosignedName = "final.cosigned"
	FinalKeyName      = "ledger.vkey"
)

const (
	maxTileBytes   = layout.TileWidth * 32
	maxBundleBytes = layout.EntryBundleWidth * (2 + entry.MaxBytes)
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
	case uint64(len(tail)) >= l.maxSize:
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
// announcements, each proven included in cp; the final entry must be cp's last and name next.
func readTail(ctx context.Context, dir string, cp cosign.Checkpoint, next string) ([][]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller names the directory
	}
	defer root.Close() //nolint:errcheck // read-only
	if cp.Size == 0 {
		return nil, errors.New("cosigned checkpoint of an empty log")
	}
	pb, err := client.NewProofBuilder(ctx, cp.Size, func(_ context.Context, level, index uint64, p uint8) ([]byte, error) {
		return readPartial(root, p, maxTileBytes, func(p uint8) string { return layout.TilePath(level, index, p) })
	})
	if err != nil {
		return nil, fmt.Errorf("proof: %w", err)
	}
	included := func(idx uint64, b []byte) error {
		p, err := pb.InclusionProof(ctx, idx)
		if err == nil {
			err = proof.VerifyInclusion(rfc6962.DefaultHasher, idx, cp.Size, rfc6962.DefaultHasher.HashLeaf(b), p, cp.Root)
		}
		if err != nil {
			return fmt.Errorf("entry %d not in the cosigned log: %w", idx, err)
		}
		return nil
	}
	var tail [][]byte // newest first
	for end, n := cp.Size, 0; end > 0; n++ {
		if n == tailBundles {
			return nil, fmt.Errorf("no batch in the last %d bundles", tailBundles)
		}
		idx := (end - 1) / layout.EntryBundleWidth
		b, err := client.GetEntryBundle(ctx, func(_ context.Context, i uint64, p uint8) ([]byte, error) {
			return readPartial(root, p, maxBundleBytes, func(p uint8) string { return layout.EntriesPath(i, p) })
		}, idx, cp.Size)
		if err != nil {
			return nil, fmt.Errorf("read the log's tail: %w", err)
		}
		if uint64(len(b.Entries)) != end-idx*layout.EntryBundleWidth {
			return nil, fmt.Errorf("bundle %d holds %d entries", idx, len(b.Entries))
		}
		for i := len(b.Entries) - 1; i >= 0; i-- {
			at := idx*layout.EntryBundleWidth + uint64(i)
			e, err := entry.Decode(b.Entries[i])
			if err == nil {
				err = included(at, b.Entries[i])
			}
			if err != nil {
				return nil, fmt.Errorf("log entry %d: %w", at, err)
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
			if _, ok := e.Body.(entry.Announce); !ok {
				tail = append(tail, b.Entries[i])
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

// readPartial reads a tile or bundle as Tessera's FileFetcher does, a partial one falling back to the
// full one, inside root (no link out) and capped.
func readPartial(root *os.Root, p uint8, limit int, path func(uint8) string) ([]byte, error) {
	b, err := readRooted(root, path(p), limit)
	if errors.Is(err, fs.ErrNotExist) && p > 0 {
		return readRooted(root, path(0), limit)
	}
	return b, err
}

func readRooted(root *os.Root, name string, limit int) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err //nolint:wrapcheck // readTail names the entry
	}
	defer f.Close() //nolint:errcheck // read-only
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("%s is not a regular file", name), err)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err //nolint:wrapcheck // as above
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", name, limit)
	}
	return b, nil
}
