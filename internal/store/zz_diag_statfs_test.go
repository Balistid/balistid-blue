package store

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Diagnostic only (branch diag/statfs-lag, never merged): does f_bavail rise right after a truncate
// of a fallocated file on the CI filesystem, after its fsync, after syncfs? Printed as annotations.
func TestDiagStatfsAfterTruncate(t *testing.T) {
	dir := t.TempDir()
	bavail := func() int64 {
		var st syscall.Statfs_t
		if err := syscall.Statfs(dir, &st); err != nil {
			t.Fatal(err)
		}
		return int64(st.Bavail) * int64(st.Frsize) //nolint:gosec,unconvert // diagnostic
	}
	path := filepath.Join(dir, "reserve")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Fallocate(int(f.Fd()), 0, 0, 64<<20); err != nil {
		t.Fatal(err)
	}
	_ = f.Sync()
	var fs syscall.Statfs_t
	_ = syscall.Statfs(dir, &fs)
	out := fmt.Sprintf("fstype=%#x bsize=%d frsize=%d;", fs.Type, fs.Bsize, fs.Frsize)
	size := int64(64 << 20)
	for i := range 3 {
		b0 := bavail()
		size -= 64 << 10
		if err := os.Truncate(path, size); err != nil {
			t.Fatal(err)
		}
		b1 := bavail()
		_ = f.Sync()
		b2 := bavail()
		time.Sleep(50 * time.Millisecond)
		b3 := bavail()
		out += fmt.Sprintf(" step%d: truncate %+d fsync %+d sleep50ms %+d;", i, b1-b0, b2-b0, b3-b0)
	}
	b0 := bavail()
	size -= 64 << 10
	_ = os.Truncate(path, size)
	d, _ := os.Open(dir)
	_, _, e := syscall.Syscall(306, d.Fd(), 0, 0) // syncfs on amd64
	out += fmt.Sprintf(" syncfs(err %v) %+d;", e, bavail()-b0)
	_ = d.Close()
	_ = f.Close()
	fmt.Printf("::warning title=statfs-diag::%s\n", out)
	t.Fail() // so go test ./... prints the line
}
