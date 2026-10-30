package cosign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"

	"github.com/Balistid/balistid-blue/internal/entry"
)

const (
	maxTileBytes   = layout.TileWidth * 32
	maxBundleBytes = layout.EntryBundleWidth * (2 + entry.MaxBytes)
)

// Proven reads a log directory's bundles and tiles inside an os.Root, capped and without blocking on
// a FIFO, and proves each entry it returns included in a cosigned checkpoint: the bytes on disk count
// only as far as the witness's checkpoint vouches for them.
type Proven struct {
	root *os.Root
	cp   Checkpoint
	pb   *client.ProofBuilder
}

func OpenProven(ctx context.Context, dir string, cp Checkpoint) (*Proven, error) {
	if cp.Size == 0 {
		return nil, errors.New("cosigned checkpoint of an empty log")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller names the directory
	}
	p := &Proven{root: root, cp: cp}
	p.pb, err = client.NewProofBuilder(ctx, cp.Size, func(_ context.Context, level, index uint64, part uint8) ([]byte, error) {
		return p.read(part, maxTileBytes, func(part uint8) string { return layout.TilePath(level, index, part) })
	})
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("proof: %w", err)
	}
	return p, nil
}

// Close releases the log's directory.
func (p *Proven) Close() error { return p.root.Close() } //nolint:wrapcheck // read-only

// Bundle returns the entries of bundle idx under the checkpoint's size, not yet proven. A log that grew
// past the checkpoint may hold only the full bundle (Tessera removes partial ones): its prefix is taken.
func (p *Proven) Bundle(ctx context.Context, idx uint64) ([][]byte, error) {
	b, err := client.GetEntryBundle(ctx, func(_ context.Context, i uint64, part uint8) ([]byte, error) {
		return p.read(part, maxBundleBytes, func(part uint8) string { return layout.EntriesPath(i, part) })
	}, idx, p.cp.Size)
	if err != nil {
		return nil, fmt.Errorf("bundle %d: %w", idx, err)
	}
	want := min(p.cp.Size-idx*layout.EntryBundleWidth, layout.EntryBundleWidth)
	if uint64(len(b.Entries)) < want {
		return nil, fmt.Errorf("bundle %d holds %d entries, want %d", idx, len(b.Entries), want)
	}
	return b.Entries[:want], nil
}

// Prove checks that raw is the entry at index at of the cosigned log, and decodes it.
func (p *Proven) Prove(ctx context.Context, at uint64, raw []byte) (entry.Entry, error) {
	path, err := p.pb.InclusionProof(ctx, at)
	if err == nil {
		err = proof.VerifyInclusion(rfc6962.DefaultHasher, at, p.cp.Size, rfc6962.DefaultHasher.HashLeaf(raw), path, p.cp.Root)
	}
	if err != nil {
		return entry.Entry{}, fmt.Errorf("entry %d not in the cosigned log: %w", at, err)
	}
	e, err := entry.Decode(raw)
	if err != nil {
		return entry.Entry{}, fmt.Errorf("entry %d: %w", at, err)
	}
	return e, nil
}

// Consistent checks that root is the root of the cosigned log's first size entries: equal at the
// cosigned size, by a consistency proof from the log's tiles below it.
func (p *Proven) Consistent(ctx context.Context, size uint64, root []byte) error {
	switch {
	case size > p.cp.Size || size == 0:
		return fmt.Errorf("cosign: size %d is not within the cosigned %d", size, p.cp.Size)
	case size == p.cp.Size:
		if !bytes.Equal(root, p.cp.Root) {
			return fmt.Errorf("cosign: another root at the cosigned size %d", size)
		}
		return nil
	}
	path, err := p.pb.ConsistencyProof(ctx, size, p.cp.Size)
	if err == nil {
		err = proof.VerifyConsistency(rfc6962.DefaultHasher, size, p.cp.Size, path, root, p.cp.Root)
	}
	if err != nil {
		return fmt.Errorf("cosign: size %d not consistent with the cosigned %d: %w", size, p.cp.Size, err)
	}
	return nil
}

// ProvenEntry is the entry at index at of the log in dir, proven included in cp, a checkpoint the witness
// cosigned: what a client or the range may conclude from the log only after the witness vouched for it.
func ProvenEntry(ctx context.Context, dir string, cp Checkpoint, at uint64) (entry.Entry, error) {
	if at >= cp.Size {
		return entry.Entry{}, fmt.Errorf("cosign: entry %d past the cosigned size %d", at, cp.Size)
	}
	p, err := OpenProven(ctx, dir, cp)
	if err != nil {
		return entry.Entry{}, fmt.Errorf("cosign: %s: %w", dir, err)
	}
	defer p.Close() //nolint:errcheck // read-only
	idx := at / layout.EntryBundleWidth
	b, err := p.Bundle(ctx, idx)
	if err != nil {
		return entry.Entry{}, fmt.Errorf("cosign: %w", err)
	}
	e, err := p.Prove(ctx, at, b[at-idx*layout.EntryBundleWidth])
	if err != nil {
		return entry.Entry{}, fmt.Errorf("cosign: %w", err)
	}
	return e, nil
}

// read reads a tile or bundle as Tessera's FileFetcher does, a partial one falling back to the full one.
func (p *Proven) read(part uint8, limit int, path func(uint8) string) ([]byte, error) {
	b, err := ReadFile(p.root, path(part), limit)
	if errors.Is(err, fs.ErrNotExist) && part > 0 {
		return ReadFile(p.root, path(0), limit)
	}
	return b, err
}

// ReadFile reads a regular file inside root (no link out of it), or at the path name without following
// a link when root is nil; O_NONBLOCK so a FIFO is refused rather than waited on, and never more than
// limit+1 bytes held.
func ReadFile(root *os.Root, name string, limit int) ([]byte, error) {
	var f *os.File
	var err error
	if root == nil {
		f, err = os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // a fixed name in the ledger's log
	} else {
		f, err = root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller names the entry
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
