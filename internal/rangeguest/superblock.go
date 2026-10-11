package rangeguest

import (
	"encoding/binary"
	"errors"
)

// The ext4 superblock as e2fsprogs lays it out (lib/ext2fs/ext2_fs.h): it starts 1024 bytes into
// the device, with the magic at 0x38 and the compatible and incompatible feature sets at 0x5C and
// 0x60. A journal is compatible feature 0x4; incompatible feature 0x4 (RECOVER) stays set until a
// clean unmount clears it.
const (
	SuperblockEnd   = 2048
	superblockStart = 1024
	ext4Magic       = 0xEF53
	hasJournal      = 0x4
	needsRecovery   = 0x4
)

// Superblock reads the first SuperblockEnd bytes of a scratch disk, before anything mounts it,
// and reports whether it holds ext4 with a journal and whether that journal needs recovery: after
// a reset only a file system that was not cleanly unmounted proves the reset hit it (ADR 0018,
// point 3).
func Superblock(head []byte) (journal, recovery bool, err error) {
	if len(head) < SuperblockEnd {
		return false, false, errors.New("superblock cut short")
	}
	sb := head[superblockStart:SuperblockEnd]
	if binary.LittleEndian.Uint16(sb[0x38:]) != ext4Magic {
		return false, false, errors.New("no ext4 magic")
	}
	return binary.LittleEndian.Uint32(sb[0x5C:])&hasJournal != 0, binary.LittleEndian.Uint32(sb[0x60:])&needsRecovery != 0, nil
}
