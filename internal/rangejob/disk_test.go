package rangejob

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestDiskRoundTrip(t *testing.T) {
	for i, program := range [][]byte{{0}, []byte("#!/bin/sh\nid\n"), bytes.Repeat([]byte{0xff}, MaxProgramBytes)} {
		timeout := []int{1, 5, MaxTimeoutS}[i]
		disk, err := EncodeDisk(program, timeout)
		if err != nil || len(disk) != DiskBytes {
			t.Fatalf("EncodeDisk(%d bytes) = %d bytes, %v", len(program), len(disk), err)
		}
		got, err := DecodeDisk(disk)
		if err != nil || !bytes.Equal(got.Program, program) || got.SHA256 != sha256.Sum256(program) || got.TimeoutS != timeout {
			t.Fatalf("round trip of %d bytes, %d s: %d bytes, %d s, %v", len(program), timeout, len(got.Program), got.TimeoutS, err)
		}
	}
}

func TestEncodeDiskRefusesSizes(t *testing.T) {
	for _, n := range []int{0, MaxProgramBytes + 1} {
		if _, err := EncodeDisk(make([]byte, n), 1); err == nil {
			t.Errorf("EncodeDisk(%d bytes) succeeded", n)
		}
	}
}

// The request parser caps timeout_s, but the disk is the last place the limit is written down
// before the guest enforces it, so it is checked again on both sides.
func TestEncodeDiskRefusesTimeouts(t *testing.T) {
	for _, s := range []int{-1, 0, MaxTimeoutS + 1, 1 << 30} {
		if _, err := EncodeDisk([]byte("x"), s); err == nil {
			t.Errorf("EncodeDisk with a %d s limit succeeded", s)
		}
	}
}

func TestDecodeDiskRefuses(t *testing.T) {
	program := []byte("#!/bin/sh\nid\n")
	good, err := EncodeDisk(program, 7)
	if err != nil {
		t.Fatal(err)
	}
	end := headerBytes + len(program)
	edit := map[string]func(d []byte) []byte{
		"short":            func(d []byte) []byte { return d[:DiskBytes-1] },
		"long":             func(d []byte) []byte { return append(d, 0) },
		"magic":            func(d []byte) []byte { d[0] ^= 1; return d },
		"version 1":        func(d []byte) []byte { d[offVersion+3] = 1; return d },
		"version 3":        func(d []byte) []byte { d[offVersion+3] = 3; return d },
		"flags":            func(d []byte) []byte { d[offFlags+3] = 1; return d },
		"zero length":      func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], 0); return d },
		"length over cap":  func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], MaxProgramBytes+1); return d },
		"length huge":      func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], 1<<63); return d },
		"length one short": func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], uint64(len(program))-1); return d },
		"length one long":  func(d []byte) []byte { binary.BigEndian.PutUint64(d[offLength:], uint64(len(program))+1); return d },
		"hash":             func(d []byte) []byte { d[offSum] ^= 1; return d },
		"zero timeout":     func(d []byte) []byte { binary.BigEndian.PutUint32(d[offTimeout:], 0); return d },
		"timeout over cap": func(d []byte) []byte { binary.BigEndian.PutUint32(d[offTimeout:], MaxTimeoutS+1); return d },
		"timeout huge":     func(d []byte) []byte { binary.BigEndian.PutUint32(d[offTimeout:], 1<<31); return d },
		"program":          func(d []byte) []byte { d[headerBytes] ^= 1; return d },
		"header padding":   func(d []byte) []byte { d[offPad] = 1; return d },
		"header end":       func(d []byte) []byte { d[headerBytes-1] = 1; return d },
		"tail":             func(d []byte) []byte { d[end] = 1; return d },
		"last byte":        func(d []byte) []byte { d[DiskBytes-1] = 1; return d },
	}
	for name, f := range edit {
		d := f(bytes.Clone(good))
		if got, err := DecodeDisk(d); err == nil {
			t.Errorf("%s: decoded %q", name, got.Program)
		}
	}
}

func FuzzDecodeDisk(f *testing.F) {
	good, err := EncodeDisk([]byte("#!/bin/sh\nid\n"), 7)
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
		got, err := DecodeDisk(d)
		if err != nil {
			return
		}
		again, err := EncodeDisk(got.Program, got.TimeoutS)
		if err != nil || !bytes.Equal(again, d) || got.SHA256 != sha256.Sum256(got.Program) {
			t.Fatalf("decoded an image EncodeDisk would not produce (at %d, xor %d, length %d)", at, b, length)
		}
	})
}
