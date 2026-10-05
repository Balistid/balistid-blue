package rangejob

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestDiskRoundTrip(t *testing.T) {
	for _, program := range [][]byte{{0}, []byte("#!/bin/sh\nid\n"), bytes.Repeat([]byte{0xff}, MaxProgramBytes)} {
		disk, err := EncodeDisk(program)
		if err != nil || len(disk) != DiskBytes {
			t.Fatalf("EncodeDisk(%d bytes) = %d bytes, %v", len(program), len(disk), err)
		}
		got, sum, err := DecodeDisk(disk)
		if err != nil || !bytes.Equal(got, program) || sum != sha256.Sum256(program) {
			t.Fatalf("round trip of %d bytes: %d bytes, %v", len(program), len(got), err)
		}
	}
}

func TestEncodeDiskRefusesSizes(t *testing.T) {
	for _, n := range []int{0, MaxProgramBytes + 1} {
		if _, err := EncodeDisk(make([]byte, n)); err == nil {
			t.Errorf("EncodeDisk(%d bytes) succeeded", n)
		}
	}
}

func TestDecodeDiskRefuses(t *testing.T) {
	program := []byte("#!/bin/sh\nid\n")
	good, err := EncodeDisk(program)
	if err != nil {
		t.Fatal(err)
	}
	end := headerBytes + len(program)
	edit := map[string]func(d []byte) []byte{
		"short":            func(d []byte) []byte { return d[:DiskBytes-1] },
		"long":             func(d []byte) []byte { return append(d, 0) },
		"magic":            func(d []byte) []byte { d[0] ^= 1; return d },
		"version":          func(d []byte) []byte { d[offVersion+3] = 2; return d },
		"flags":            func(d []byte) []byte { d[offFlags+3] = 1; return d },
		"zero length":      func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], 0); return d },
		"length over cap":  func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], MaxProgramBytes+1); return d },
		"length huge":      func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], 1<<63); return d },
		"length one short": func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], uint64(len(program))-1); return d },
		"length one long":  func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], uint64(len(program))+1); return d },
		"hash":             func(d []byte) []byte { d[offSum] ^= 1; return d },
		"program":          func(d []byte) []byte { d[headerBytes] ^= 1; return d },
		"header padding":   func(d []byte) []byte { d[offPad] = 1; return d },
		"header end":       func(d []byte) []byte { d[headerBytes-1] = 1; return d },
		"tail":             func(d []byte) []byte { d[end] = 1; return d },
		"last byte":        func(d []byte) []byte { d[DiskBytes-1] = 1; return d },
	}
	for name, f := range edit {
		d := f(bytes.Clone(good))
		if got, _, err := DecodeDisk(d); err == nil {
			t.Errorf("%s: decoded %q", name, got)
		}
	}
}

func FuzzDecodeDisk(f *testing.F) {
	good, err := EncodeDisk([]byte("#!/bin/sh\nid\n"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint16(0), byte(1), uint64(13))
	f.Fuzz(func(t *testing.T, at uint16, b byte, length uint64) {
		d := bytes.Clone(good)
		d[int(at)%(headerBytes+64)] ^= b
		if at%7 == 0 {
			binary.BigEndian.PutUint64(d[offLength:], length)
		}
		program, sum, err := DecodeDisk(d)
		if err != nil {
			return
		}
		again, err := EncodeDisk(program)
		if err != nil || !bytes.Equal(again, d) || sum != sha256.Sum256(program) {
			t.Fatalf("decoded an image EncodeDisk would not produce (at %d, xor %d, length %d)", at, b, length)
		}
	})
}
