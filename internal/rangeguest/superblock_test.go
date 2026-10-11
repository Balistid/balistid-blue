package rangeguest

import (
	"encoding/binary"
	"testing"
)

// superblock builds the first 2048 bytes of a device with the given magic and feature sets; the
// values match mkfs.ext4 1.47 on an 8 MiB image (magic 0xef53, compat 0x103c, incompat 0x22c2).
func superblock(magic uint16, compat, incompat uint32) []byte {
	head := make([]byte, SuperblockEnd)
	binary.LittleEndian.PutUint16(head[1024+0x38:], magic)
	binary.LittleEndian.PutUint32(head[1024+0x5C:], compat)
	binary.LittleEndian.PutUint32(head[1024+0x60:], incompat)
	return head
}

func TestSuperblock(t *testing.T) {
	cases := []struct {
		head              []byte
		journal, recovery bool
		ok                bool
	}{
		{superblock(0xEF53, 0x103c, 0x22c2), true, false, true},
		{superblock(0xEF53, 0x103c, 0x22c6), true, true, true},
		{superblock(0xEF53, 0x1038, 0x22c6), false, true, true},
		{superblock(0x53EF, 0x103c, 0x22c6), false, false, false},
		{superblock(0xEF53, 0x103c, 0x22c6)[:SuperblockEnd-1], false, false, false},
		{nil, false, false, false},
	}
	for i, c := range cases {
		j, r, err := Superblock(c.head)
		if j != c.journal || r != c.recovery || (err == nil) != c.ok {
			t.Errorf("case %d: journal %v, recovery %v, %v", i, j, r, err)
		}
	}
}

// Any head is read without panic, and only one with the ext4 magic at its place is ext4.
func FuzzSuperblock(f *testing.F) {
	f.Add(superblock(0xEF53, 0x103c, 0x22c6))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, head []byte) {
		if _, _, err := Superblock(head); err == nil && binary.LittleEndian.Uint16(head[1024+0x38:]) != 0xEF53 {
			t.Fatal("accepted a head without the ext4 magic")
		}
	})
}
