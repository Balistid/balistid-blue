package watch

import (
	"context"
	"fmt"
	"math/bits"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/Balistid/balistid-blue/internal/entry"
)

// enc encodes test entries.
func enc(t testing.TB, bodies ...entry.Body) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(bodies))
	for i, b := range bodies {
		raw, err := entry.Entry{At: int64(i), Body: b}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
	}
	return out
}

// batches are n batch entries of ten records each, following each other from seq 1.
func batches(n int) []entry.Body {
	out := make([]entry.Body, n)
	for i := range out {
		out[i] = entry.Batch{First: uint64(10*i + 1), Last: uint64(10*i + 10), Root: [32]byte{1}}
	}
	return out
}

// mth is RFC 6962's Merkle tree hash by its definition, apart from the compact range under test.
func mth(leaves [][]byte) [32]byte {
	var out [32]byte
	switch len(leaves) {
	case 0:
		copy(out[:], rfc6962.DefaultHasher.EmptyRoot())
	case 1:
		copy(out[:], rfc6962.DefaultHasher.HashLeaf(leaves[0]))
	default:
		k := 1 << (bits.Len(uint(len(leaves)-1)) - 1)
		l, r := mth(leaves[:k]), mth(leaves[k:])
		copy(out[:], rfc6962.DefaultHasher.HashChildren(l[:], r[:]))
	}
	return out
}

func headOf(log [][]byte) Head { return Head{Size: uint64(len(log)), Root: mth(log)} }

// fetchFrom serves bundles of log as the relay would, each entry copied.
func fetchFrom(log [][]byte) Fetch {
	return func(_ context.Context, idx, w uint64) ([][]byte, error) {
		if idx*width+w > uint64(len(log)) {
			return nil, fmt.Errorf("bundle %d past the log", idx)
		}
		out := make([][]byte, w)
		for i := range out {
			out[i] = append([]byte(nil), log[idx*width+uint64(i)]...)
		}
		return out, nil
	}
}

// kept records the bundles Keep was given.
type kept map[uint64][][]byte

func (k kept) keep(idx uint64, entries [][]byte) error {
	k[idx] = append([][]byte(nil), entries...)
	return nil
}

func discard(uint64, [][]byte) error { return nil }

// verified is the log l verified up to its full length.
func verified(t testing.TB, log [][]byte) Log {
	t.Helper()
	l, _, err := Advance(context.Background(), Log{}, headOf(log), fetchFrom(log), discard)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
