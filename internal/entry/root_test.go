package entry

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// referenceRoot is RFC 6962's MTH written straight from section 2.1, independent of the merkle module.
func referenceRoot(d [][32]byte) [32]byte {
	if len(d) == 1 {
		return sha256.Sum256(append([]byte{0}, d[0][:]...))
	}
	k := 1
	for k*2 < len(d) {
		k *= 2
	}
	l, r := referenceRoot(d[:k]), referenceRoot(d[k:])
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

func leaves(n int) [][32]byte {
	d := make([][32]byte, n)
	for i := range d {
		for j := range d[i] {
			d[i][j] = byte(i)
		}
	}
	return d
}

func rootOf(t *testing.T, d [][32]byte) [32]byte {
	t.Helper()
	r := NewRoot()
	for _, l := range d {
		if err := r.Add(l); err != nil {
			t.Fatal(err)
		}
	}
	if r.Len() != uint64(len(d)) {
		t.Fatalf("Len = %d, want %d", r.Len(), len(d))
	}
	got, err := r.Sum()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRootMatchesRFC6962(t *testing.T) {
	for n := 1; n <= 300; n++ {
		d := leaves(n)
		if got, want := rootOf(t, d), referenceRoot(d); got != want {
			t.Fatalf("%d leaves: root %x, want %x", n, got, want)
		}
	}
}

// Computed outside Go (Python hashlib, RFC 6962 section 2.1) over leaves whose bytes all equal their index.
func TestRootVectors(t *testing.T) {
	for n, want := range map[int]string{
		1: "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9",
		2: "28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444",
		3: "ba8d94b7fbcecae7b81c4c80574fe24734a6917bf9c1ecd66ff3e0c34ead4620",
		7: "7318881c41fce3c1de3640df8e8c110c93f43f686b74204a9d1ad5b8c71c2047",
	} {
		if got := rootOf(t, leaves(n)); hex.EncodeToString(got[:]) != want {
			t.Errorf("%d leaves: root %x, want %s", n, got, want)
		}
	}
}

func TestRootOfNoLeavesFails(t *testing.T) {
	if got, err := NewRoot().Sum(); err == nil {
		t.Fatalf("empty batch root %x", got)
	}
}
