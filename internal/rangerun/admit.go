package rangerun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Admission reserves of ADR 0011, point 6. A job starts only when the host keeps MemReserve after
// JobMemory, and DiskReserve after the job's caps on every filesystem it writes.
const (
	MemReserve  uint64 = 4 << 30 // maintainer, 6.10.2026
	JobMemory   uint64 = 5 << 29 // 2.5 GiB, acceptance metric runner_job_memory_gib
	DiskReserve uint64 = 5 << 30 // maintainer, 6.10.2026
	watchEvery         = time.Second
	maxMemInfo         = 64 << 10
)

// ErrNotAdmitted wraps a refusal because the host is short of its reserves, which only delays a
// job; any other Admit error means the host could not be read. The other two are the causes with
// which a context from Watch ends when the host, not the job, is the problem; the job is then
// INVALID. Compare with errors.Is.
var (
	ErrNotAdmitted   = errors.New("not admitted: the host is short of its reserves")
	ErrMemoryReserve = errors.New("memory available fell below the reserve")
	ErrMemoryUnknown = errors.New("memory available is unknown")
)

// DiskNeed is what a job may write under Path: the sum of the caps of the files it creates there.
type DiskNeed struct {
	Path  string
	Bytes uint64
}

// Admit lets a job start only if MemAvailable is at least MemReserve + JobMemory and every path in
// needs has DiskReserve plus the sum of all needs available to an unprivileged writer. Anything it
// cannot read refuses (R6). The caller admits before Next takes a job, so a refusal costs no
// quota; needs are therefore the worst case of any job Next can return.
func Admit(ctx context.Context, needs []DiskNeed) error {
	return admit(ctx, readMemInfo, statAvail, needs)
}

// admit is Admit with its readings injected. Every path must hold the whole sum, not only its own
// needs: btrfs subvolumes have their own st_dev and fsid but share free space, so grouping by
// device can admit twice what fits, while this only over-reserves across separate filesystems.
func admit(ctx context.Context, meminfo func() ([]byte, error), avail func(path string) (uint64, error), needs []DiskNeed) error {
	data, err := meminfo()
	if err != nil {
		return fmt.Errorf("memory admission: %w", err)
	}
	mem, err := memAvailable(data)
	if err != nil {
		return fmt.Errorf("memory admission: %w", err)
	}
	if want := MemReserve + JobMemory; mem < want {
		return fmt.Errorf("%w: memory %d bytes available, want %d", ErrNotAdmitted, mem, want)
	}
	if len(needs) == 0 {
		return errors.New("disk admission: no paths to check")
	}
	var total uint64
	for _, n := range needs {
		if n.Bytes > math.MaxUint64-DiskReserve-total {
			return errors.New("disk admission: needs out of range")
		}
		total += n.Bytes
	}
	for _, n := range needs {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("disk admission: %w", err)
		}
		free, err := avail(n.Path)
		if err != nil {
			return fmt.Errorf("disk admission: %w", err)
		}
		if want := DiskReserve + total; free < want {
			return fmt.Errorf("%w: %s has %d bytes available, want %d", ErrNotAdmitted, n.Path, free, want)
		}
	}
	return nil
}

// Watch returns a context that ends when MemAvailable, read every second and once at once, falls
// below MemReserve (cause ErrMemoryReserve) or cannot be read (cause ErrMemoryUnknown), and a stop
// function that ends the watch and returns after its goroutine has exited; calling it again is safe.
func Watch(ctx context.Context) (context.Context, func()) {
	return watch(ctx, watchEvery, readMemInfo)
}

func watch(ctx context.Context, every time.Duration, read func() ([]byte, error)) (context.Context, func()) {
	child, cancel := context.WithCancelCause(ctx)
	stopping, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		// Only this goroutine ends the child, after its last sample: a low or unreadable sample in flight when stop
		// comes still sets its cause, and the run it watched is INVALID.
		defer cancel(nil)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select { // stopped while select took the tick: no new read once stop is seen
			case <-stopping:
				return
			case <-child.Done():
				return
			default:
			}
			if cause := memoryCause(read); cause != nil {
				cancel(cause)
				return
			}
			select {
			case <-stopping:
				return
			case <-child.Done():
				return
			case <-tick.C:
			}
		}
	}()
	var once sync.Once
	return child, func() {
		once.Do(func() { close(stopping) })
		<-done
	}
}

func memoryCause(read func() ([]byte, error)) error {
	data, err := read()
	if err == nil {
		var avail uint64
		if avail, err = memAvailable(data); err == nil && avail < MemReserve {
			return fmt.Errorf("%w: %d bytes available, reserve %d", ErrMemoryReserve, avail, MemReserve)
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMemoryUnknown, err)
	}
	return nil
}

// memAvailable returns MemAvailable in bytes from /proc/meminfo content in the kernel's form only:
// one line "MemAvailable:", spaces, decimal digits, " kB". Anything else is an error (R6).
func memAvailable(data []byte) (uint64, error) {
	var value []byte
	found := false
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(line, []byte("MemAvailable:")); ok {
			if found {
				return 0, errors.New("meminfo: MemAvailable appears twice")
			}
			found, value = true, rest
		}
	}
	digits, ok := bytes.CutSuffix(bytes.TrimLeft(value, " "), []byte(" kB"))
	if !found || !ok || !bytes.HasPrefix(value, []byte(" ")) {
		return 0, errors.New("meminfo: no MemAvailable line of the kernel's form")
	}
	kib, err := strconv.ParseUint(string(digits), 10, 64) // refuses signs, spaces, "_" and "0x"
	if err != nil || kib > math.MaxUint64>>10 {
		return 0, errors.New("meminfo: MemAvailable is not a number of kB in range")
	}
	return kib << 10, nil
}

func readMemInfo() ([]byte, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("read meminfo: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxMemInfo+1))
	if err == nil && len(data) > maxMemInfo {
		err = fmt.Errorf("over %d bytes", maxMemInfo)
	}
	if err != nil {
		return nil, fmt.Errorf("read meminfo: %w", err)
	}
	return data, nil
}

// statAvail returns the bytes available to an unprivileged writer of the directory at path,
// following links as the job's own writes will; O_DIRECTORY keeps a FIFO from blocking.
func statAvail(path string) (uint64, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	defer syscall.Close(fd) //nolint:errcheck // read-only
	var fs syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &fs); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return availBytes(&fs)
}

// availBytes is f_bavail, the blocks left to unprivileged users (f_bfree includes root's reserve),
// in f_frsize units, which Linux fills with the block size when a filesystem has no fragments.
func availBytes(fs *syscall.Statfs_t) (uint64, error) {
	if fs.Frsize <= 0 || fs.Bavail > math.MaxUint64/uint64(fs.Frsize) {
		return 0, errors.New("statfs: available space out of range")
	}
	return fs.Bavail * uint64(fs.Frsize), nil
}
