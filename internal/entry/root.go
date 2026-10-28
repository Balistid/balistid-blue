package entry

import (
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Root accumulates a batch's root (ADR 0026, point 1): the RFC 6962 tree hash over D[i], the 32-byte
// rawrecord leaf of seq First+i. It keeps one hash per level, so a batch of any length costs no memory.
type Root struct{ r *compact.Range }

// NewRoot returns the root of an empty batch, ready for its first leaf.
func NewRoot() *Root {
	f := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	return &Root{r: f.NewEmptyRange(0)}
}

// Add appends the leaf of the next seq.
func (r *Root) Add(leaf [32]byte) error {
	if err := r.r.Append(rfc6962.DefaultHasher.HashLeaf(leaf[:]), nil); err != nil {
		return fmt.Errorf("entry: batch root: %w", err)
	}
	return nil
}

// Len is the number of leaves added.
func (r *Root) Len() uint64 { return r.r.End() }

// Sum returns the root over the leaves added; a batch holds at least one.
func (r *Root) Sum() ([32]byte, error) {
	if r.Len() == 0 {
		return [32]byte{}, errors.New("entry: batch root of no leaves")
	}
	h, err := r.r.GetRootHash(nil)
	if err != nil {
		return [32]byte{}, fmt.Errorf("entry: batch root: %w", err)
	}
	return [32]byte(h), nil
}
