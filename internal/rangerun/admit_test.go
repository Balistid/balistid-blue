package rangerun

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The lines around MemAvailable are as the kernel prints them: key padded to 16, value width 8.
func meminfo(kib uint64) []byte {
	return fmt.Appendf(nil, "MemTotal:       32584116 kB\nMemFree:          697104 kB\n"+
		"MemAvailable:   %8d kB\nBuffers:             360 kB\n", kib)
}

func TestMemAvailable(t *testing.T) {
	t.Parallel()
	good := []struct {
		name, in string
		want     uint64
	}{
		{"kernel", string(meminfo(7421384)), 7421384 << 10},
		{"wide", "MemAvailable:   123456789012 kB\n", 123456789012 << 10},
		{"zero", "MemAvailable:          0 kB\n", 0},
		{"no newline", "MemFree: 1 kB\nMemAvailable: 5 kB", 5 << 10},
		{"largest in kiB", fmt.Sprintf("MemAvailable: %d kB\n", uint64(math.MaxUint64>>10)), (math.MaxUint64 >> 10) << 10},
	}
	for _, c := range good {
		if got, err := memAvailable([]byte(c.in)); err != nil || got != c.want {
			t.Errorf("%s: memAvailable = %d, %v; want %d", c.name, got, err, c.want)
		}
	}
	bad := []struct{ name, in string }{
		{"empty", ""},
		{"missing", "MemTotal:       32584116 kB\nMemFree:          697104 kB\n"},
		{"twice", "MemAvailable:   5 kB\nMemAvailable:   6 kB\n"},
		{"negative", "MemAvailable: -5 kB\n"},
		{"plus", "MemAvailable: +5 kB\n"},
		{"hex", "MemAvailable: 0x10 kB\n"},
		{"MB", "MemAvailable: 5 MB\n"},
		{"no space before", "MemAvailable: 5kB\n"},
		{"no space after", "MemAvailable:5 kB\n"},
		{"two spaces", "MemAvailable: 5  kB\n"},
		{"tab", "MemAvailable:\t5 kB\n"},
		{"no unit", "MemAvailable: 5\n"},
		{"no value", "MemAvailable:    kB\n"},
		{"extra token", "MemAvailable: 5 kB x\n"},
		{"trailing space", "MemAvailable: 5 kB \n"},
		{"carriage return", "MemAvailable: 5 kB\r\n"},
		{"decimal point", "MemAvailable: 5.0 kB\n"},
		{"overflow uint64", "MemAvailable: 18446744073709551616 kB\n"},
		{"overflow bytes", fmt.Sprintf("MemAvailable: %d kB\n", uint64(math.MaxUint64>>10)+1)},
		{"unicode digit", "MemAvailable: ５ kB\n"},
		{"indented", "  MemAvailable: 5 kB\n"},
		{"other key prefix", "XMemAvailable: 5 kB\n"},
	}
	for _, c := range bad {
		if got, err := memAvailable([]byte(c.in)); err == nil {
			t.Errorf("%s: memAvailable(%q) = %d, want an error", c.name, c.in, got)
		}
	}
}

// What this host prints parses, which pins the format the tests above assume.
func TestReadMemInfoParsesOnThisHost(t *testing.T) {
	t.Parallel()
	data, err := readMemInfo()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := memAvailable(data); err != nil || v == 0 {
		t.Fatalf("memAvailable(/proc/meminfo) = %d, %v", v, err)
	}
}

func TestAdmit(t *testing.T) {
	t.Parallel()
	enough := (MemReserve + JobMemory) >> 10
	mem := func(kib uint64) func() ([]byte, error) { return func() ([]byte, error) { return meminfo(kib), nil } }
	// Two paths on one btrfs pool report the same free space under different st_dev; only the sum
	// of both needs decides.
	disk := func(free uint64) func(string) (uint64, error) {
		return func(string) (uint64, error) { return free, nil }
	}
	needs := []DiskNeed{{"runs", 3 << 30}, {"results", 1 << 30}}
	room := DiskReserve + 4<<30
	cases := []struct {
		name  string
		mem   func() ([]byte, error)
		avail func(string) (uint64, error)
		needs []DiskNeed
		ok    bool
	}{
		{"enough of both", mem(enough), disk(room), needs, true},
		{"memory one kiB short", mem(enough - 1), disk(room), needs, false},
		{"meminfo unreadable", func() ([]byte, error) { return nil, errors.New("gone") }, disk(room), needs, false},
		{"meminfo garbled", func() ([]byte, error) { return []byte("MemAvailable: ?\n"), nil }, disk(room), needs, false},
		{"room for each need alone, not for both", mem(enough), disk(room - 1), needs, false},
		{"one path short", mem(enough), func(p string) (uint64, error) {
			if p == "results" {
				return room - 1, nil
			}
			return room, nil
		}, needs, false},
		{"statfs error", mem(enough), func(string) (uint64, error) { return 0, errors.New("gone") }, needs, false},
		{"no paths", mem(enough), disk(room), nil, false},
		{"needs overflow", mem(enough), disk(math.MaxUint64), []DiskNeed{{"runs", math.MaxUint64 - DiskReserve + 1}}, false},
	}
	for _, c := range cases {
		if err := admit(t.Context(), c.mem, c.avail, c.needs); (err == nil) != c.ok {
			t.Errorf("%s: admit = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestAvailBytesIsWhatAnUnprivilegedWriterGets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		fs   syscall.Statfs_t
		want uint64
		ok   bool
	}{
		{"bavail, not bfree", syscall.Statfs_t{Bfree: 100, Bavail: 10, Frsize: 4096, Bsize: 4096}, 10 * 4096, true},
		{"frsize, not bsize", syscall.Statfs_t{Bavail: 10, Frsize: 1024, Bsize: 4096}, 10 * 1024, true},
		{"no frsize", syscall.Statfs_t{Bavail: 10, Bsize: 4096}, 0, false},
		{"overflow", syscall.Statfs_t{Bavail: math.MaxUint64 / 2, Frsize: 4}, 0, false},
	}
	for _, c := range cases {
		got, err := availBytes(&c.fs)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s: availBytes = %d, %v; want %d ok=%v", c.name, got, err, c.want, c.ok)
		}
	}
}

func TestStatAvail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if free, err := statAvail(dir); err != nil || free == 0 {
		t.Fatalf("statAvail(temp dir) = %d, %v", free, err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{fifo, filepath.Join(dir, "missing")} {
		if _, err := statAvail(p); err == nil {
			t.Errorf("statAvail(%s) succeeded", filepath.Base(p))
		}
	}
}

func waitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not end")
	}
}

func TestWatchEndsTheJob(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		read func() ([]byte, error)
		want error
	}{
		{"below reserve", func() ([]byte, error) { return meminfo(MemReserve>>10 - 1), nil }, ErrMemoryReserve},
		{"read error", func() ([]byte, error) { return nil, errors.New("gone") }, ErrMemoryUnknown},
		{"unparsable", func() ([]byte, error) { return []byte("MemAvailable: ?\n"), nil }, ErrMemoryUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// An hour between reads: only the immediate first read can end the watch.
			ctx, stop := watch(t.Context(), time.Hour, c.read)
			defer stop()
			waitDone(t, ctx)
			if cause := context.Cause(ctx); !errors.Is(cause, c.want) {
				t.Fatalf("cause = %v, want %v", cause, c.want)
			}
		})
	}
}

func TestWatchFiresWhenMemoryDropsLater(t *testing.T) {
	t.Parallel()
	var n int
	read := func() ([]byte, error) { // called only from the one watch goroutine
		n++
		if n < 5 {
			return meminfo(MemReserve >> 10), nil
		}
		return meminfo(MemReserve>>10 - 1), nil
	}
	ctx, stop := watch(t.Context(), time.Millisecond, read)
	waitDone(t, ctx)
	stop()
	if cause := context.Cause(ctx); !errors.Is(cause, ErrMemoryReserve) || n != 5 {
		t.Fatalf("after %d reads cause = %v, want %v after 5", n, cause, ErrMemoryReserve)
	}
}

func TestWatchStaysAliveWhileHealthy(t *testing.T) {
	t.Parallel()
	reads := make(chan struct{}, 1)
	read := func() ([]byte, error) {
		select {
		case reads <- struct{}{}:
		default:
		}
		return meminfo(MemReserve >> 10), nil
	}
	ctx, stop := watch(t.Context(), time.Millisecond, read)
	for range 3 {
		select {
		case <-reads:
		case <-time.After(5 * time.Second):
			t.Fatal("no read while memory was at the reserve")
		}
	}
	if ctx.Err() != nil {
		t.Fatalf("watch ended while memory was at the reserve: %v", context.Cause(ctx))
	}
	stop()
	if !errors.Is(ctx.Err(), context.Canceled) || !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatalf("after stop: %v, cause %v", ctx.Err(), context.Cause(ctx))
	}
}

func TestWatchStopWaitsForTheGoroutine(t *testing.T) {
	t.Parallel()
	entered, release := make(chan struct{}), make(chan struct{})
	n := 0
	read := func() ([]byte, error) { // called only from the one watch goroutine
		if n++; n == 2 {
			close(entered)
			<-release
		}
		return meminfo(MemReserve >> 9), nil
	}
	_, stop := watch(t.Context(), time.Millisecond, read)
	<-entered // the goroutine is inside its second read
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("stop returned while the goroutine was still reading")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return")
	}
	if n > 3 {
		t.Fatalf("%d reads, the watch went on after stop", n)
	}
	stop() // a second stop returns at once
}

func FuzzMemAvailable(f *testing.F) {
	f.Add(meminfo(7421384))
	f.Add([]byte("MemAvailable:   123456789012 kB\n"))
	f.Add([]byte("MemAvailable: 5 kB\nMemAvailable: 5 kB\n"))
	f.Add([]byte("MemAvailable: -5 kB\n"))
	f.Add([]byte("MemAvailable: 18014398509481983 kB"))
	f.Add([]byte("MemAvailable: 18014398509481984 kB"))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := memAvailable(data)
		if err != nil {
			return
		}
		if v%1024 != 0 {
			t.Fatalf("accepted %d bytes, not whole kiB", v)
		}
		if strings.Count(string(data), "\nMemAvailable:")+boolInt(strings.HasPrefix(string(data), "MemAvailable:")) != 1 {
			t.Fatalf("accepted %q without exactly one MemAvailable line", data)
		}
		again, err := memAvailable(meminfo(v >> 10))
		if err != nil || again != v {
			t.Fatalf("%d did not round-trip: %d, %v", v, again, err)
		}
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
