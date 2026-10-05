package rangejob

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// The job disk carries an exec job's program into the VM (ADR 0011, point 3). It is a raw image of
// fixed size, attached read-only, and the guest reads it as data, never as a file system: a header
// block, then the program, then zeros. Its sha256 field lets the host check that the guest ran the
// program it was given.
const (
	DiskBytes   = 2 << 20
	headerBytes = 4096
	diskVersion = 1
)

var diskMagic = [8]byte{'B', 'L', 'S', 'T', 'D', 'J', 'O', 'B'}

// header: magic, version, flags, program length, program sha256; the rest of the block is zero.
const (
	offVersion = 8
	offFlags   = 12
	offLength  = 16
	offSum     = 24
	offPad     = offSum + sha256.Size
)

// EncodeDisk returns the job disk image for program.
func EncodeDisk(program []byte) ([]byte, error) {
	if len(program) == 0 || len(program) > MaxProgramBytes {
		return nil, errors.New("program must be 1 byte to the program cap")
	}
	disk := make([]byte, DiskBytes)
	copy(disk, diskMagic[:])
	binary.BigEndian.PutUint32(disk[offVersion:], diskVersion)
	binary.BigEndian.PutUint64(disk[offLength:], uint64(len(program)))
	sum := sha256.Sum256(program)
	copy(disk[offSum:], sum[:])
	copy(disk[headerBytes:], program)
	return disk, nil
}

// DecodeDisk returns the program on disk and its sha256 only if every byte of the image is where
// EncodeDisk puts it: exact size, magic, version, no flags, a length within the cap, a matching
// hash and zeros everywhere else.
func DecodeDisk(disk []byte) (program []byte, sum [sha256.Size]byte, err error) {
	if len(disk) != DiskBytes {
		return nil, sum, errors.New("job disk has the wrong size")
	}
	if !bytes.Equal(disk[:offVersion], diskMagic[:]) ||
		binary.BigEndian.Uint32(disk[offVersion:]) != diskVersion ||
		binary.BigEndian.Uint32(disk[offFlags:]) != 0 {
		return nil, sum, errors.New("job disk header is not version 1")
	}
	n := binary.BigEndian.Uint64(disk[offLength:])
	if n == 0 || n > MaxProgramBytes {
		return nil, sum, errors.New("job disk program length is out of range")
	}
	end := headerBytes + int(n)
	if !allZero(disk[offPad:headerBytes]) || !allZero(disk[end:]) {
		return nil, sum, errors.New("job disk has data outside the header and program")
	}
	program = disk[headerBytes:end]
	sum = sha256.Sum256(program)
	if !bytes.Equal(sum[:], disk[offSum:offPad]) {
		return nil, sum, errors.New("job disk program does not match its sha256")
	}
	return bytes.Clone(program), sum, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
