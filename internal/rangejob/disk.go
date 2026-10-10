package rangejob

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// The job disk carries an exec job's program and time limit into the VM (ADR 0011, point 3). It is
// a raw image of fixed size, attached read-only, and the guest reads it as data, never as a file
// system: a header block, then the program, then zeros. Its sha256 field lets the host check that
// the guest ran the program it was given. Host and guest are always built from one commit, so
// only the current version is read.
const (
	DiskBytes   = 2 << 20
	headerBytes = 4096
	diskVersion = 2
)

var diskMagic = [8]byte{'B', 'L', 'S', 'T', 'D', 'J', 'O', 'B'}

// header: magic, version, flags, program length, program sha256, time limit in seconds; the rest
// of the block is zero.
const (
	offVersion = 8
	offFlags   = 12
	offLength  = 16
	offSum     = 24
	offTimeout = offSum + sha256.Size
	offPad     = offTimeout + 4
)

// Disk is what a job disk carries: the program, its sha256 and the job's time limit (timeout_s).
type Disk struct {
	Program  []byte
	SHA256   [sha256.Size]byte
	TimeoutS int
}

// EncodeDisk returns the job disk image for program with a time limit of timeoutS seconds.
func EncodeDisk(program []byte, timeoutS int) ([]byte, error) {
	if len(program) == 0 || len(program) > MaxProgramBytes {
		return nil, errors.New("program must be 1 byte to the program cap")
	}
	if timeoutS < 1 || timeoutS > MaxTimeoutS {
		return nil, fmt.Errorf("timeout must be 1 to %d seconds", MaxTimeoutS)
	}
	disk := make([]byte, DiskBytes)
	copy(disk, diskMagic[:])
	binary.BigEndian.PutUint32(disk[offVersion:], diskVersion)
	binary.BigEndian.PutUint64(disk[offLength:], uint64(len(program)))
	sum := sha256.Sum256(program)
	copy(disk[offSum:], sum[:])
	binary.BigEndian.PutUint32(disk[offTimeout:], uint32(timeoutS))
	copy(disk[headerBytes:], program)
	return disk, nil
}

// DecodeDisk returns what the job disk carries only if every byte of the image is where EncodeDisk
// puts it: exact size, magic, version, no flags, a length and time limit within their caps, a
// matching hash and zeros everywhere else.
func DecodeDisk(disk []byte) (Disk, error) {
	if len(disk) != DiskBytes {
		return Disk{}, errors.New("job disk has the wrong size")
	}
	if !bytes.Equal(disk[:offVersion], diskMagic[:]) ||
		binary.BigEndian.Uint32(disk[offVersion:]) != diskVersion ||
		binary.BigEndian.Uint32(disk[offFlags:]) != 0 {
		return Disk{}, fmt.Errorf("job disk header is not version %d", diskVersion)
	}
	n := binary.BigEndian.Uint64(disk[offLength:])
	if n == 0 || n > MaxProgramBytes {
		return Disk{}, errors.New("job disk program length is out of range")
	}
	timeout := binary.BigEndian.Uint32(disk[offTimeout:])
	if timeout < 1 || timeout > MaxTimeoutS {
		return Disk{}, errors.New("job disk time limit is out of range")
	}
	end := headerBytes + int(n)
	if !allZero(disk[offPad:headerBytes]) || !allZero(disk[end:]) {
		return Disk{}, errors.New("job disk has data outside the header and program")
	}
	program := disk[headerBytes:end]
	sum := sha256.Sum256(program)
	if !bytes.Equal(sum[:], disk[offSum:offTimeout]) {
		return Disk{}, errors.New("job disk program does not match its sha256")
	}
	return Disk{Program: bytes.Clone(program), SHA256: sum, TimeoutS: int(timeout)}, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
