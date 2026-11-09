package collector

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// CPUUnits are the floor-0 services whose CPU cpu_cores and cpu_cores_typical count (ADR 0025, 0046, 0073):
// auditd's cgroup holds Laurel, its plugin. A unit not installed reads as absent.
var CPUUnits = []string{
	"auditd.service", "balistid-collector.service", "balistid-auditstat.service", "balistid-ledger.service",
	"balistid-relay.service", "balistid-net.service", "balistid-announce.service",
	"balistid-announce-suspend.service", "balistid-pi.service", "balistid-pi-failed.service",
}

const (
	// cpuEvery is how often the units' cgroups are read: of an invocation that ends, at most this much of its
	// CPU goes unread.
	cpuEvery = time.Second
	// statLimit bounds a read of cpu.stat, a few hundred bytes from the kernel.
	statLimit = 4 << 10
)

// cgroupUsage is one read of a unit's cgroup: its directory's inode, which a new invocation changes, and
// usage_usec.
type cgroupUsage struct{ ino, usec uint64 }

// unitCPU is what the writer knows of one unit's CPU since the collector started.
type unitCPU struct {
	cur      cgroupUsage // the last good read of the running invocation, while present
	goodAt   time.Time   // when it was read
	present  bool
	err      string // why the last read failed, other than an absent cgroup; "" after a good one
	gone     uint64 // invocations that ended since the collector started
	goneUsec uint64 // their usage_usec at their last read
	unreadMS uint64 // their time from that read to the read that found them ended, which bounds what went unread
}

// cpuState is the writer's reading of the floor-0 units' CPU, stored with each stats record (#201).
type cpuState struct {
	cpu   map[string]*unitCPU
	cpuAt time.Time // the last read
}

// readCPU reads every unit's cgroup once per cpuEvery. An invocation ends when its cgroup is gone, has another
// inode or a lower usage; its last read then adds to gone_usec. A read that fails otherwise keeps the last
// good one and says why, in the record and once in the journal.
func (w *Writer) readCPU(now time.Time) {
	if w.CgroupRoot == "" || now.Sub(w.cpuAt) < cpuEvery {
		return
	}
	w.cpuAt = now
	for _, name := range CPUUnits {
		u := w.cpu[name]
		got, err := readCgroup(filepath.Join(w.CgroupRoot, name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			u.end(now)
		case err != nil:
			if u.err != err.Error() { // once per failure, not every second
				w.Log.Warn("unit CPU not read", "unit", name, "err", err)
			}
			u.err = err.Error()
		default:
			if u.present && (got.ino != u.cur.ino || got.usec < u.cur.usec) {
				u.end(now)
			}
			u.cur, u.goodAt, u.present, u.err = got, now, true, ""
		}
	}
}

func (u *unitCPU) end(now time.Time) {
	if u.present {
		u.gone++
		u.goneUsec += u.cur.usec
		u.unreadMS += uint64(max(now.Sub(u.goodAt).Milliseconds(), 0))
	}
	u.present, u.err = false, ""
}

// cpuFields is the reading a started, stats or stopping record carries: CLOCK_MONOTONIC (mono_ns, which a suspend
// stops) and CLOCK_BOOTTIME (boot_ns, which it does not), the CPUs and each unit's counters. The collector's own
// cgroup absent means the root is wrong, so every unit's absence would be a zero nobody measured (R6).
func (w *Writer) cpuFields() map[string]any {
	units := make(map[string]any, len(CPUUnits))
	for _, name := range CPUUnits {
		u := w.cpu[name]
		f := map[string]any{"gone": u.gone, "gone_usec": u.goneUsec, "gone_unread_ms": u.unreadMS}
		if u.present {
			f["ino"], f["usec"] = u.cur.ino, u.cur.usec
		} else {
			f["absent"] = true
		}
		if u.err != "" {
			f["err"] = u.err
		}
		units[name] = f
	}
	out := map[string]any{"ncpu": runtime.NumCPU(), "units": units}
	for name, clock := range map[string]func() (uint64, error){"mono": w.Monotonic, "boot": w.Boottime} {
		if ns, err := clock(); err == nil {
			out[name+"_ns"] = ns
		} else {
			out[name+"_err"] = err.Error()
		}
	}
	if own := w.cpu["balistid-collector.service"]; !own.present && own.err == "" {
		out["err"] = "the collector's own cgroup is absent: wrong root or slice"
	}
	return out
}

// Monotonic is CLOCK_MONOTONIC in ns, which a suspend stops: its difference between two records of one boot is the
// time the host was awake between them, across collector restarts.
func Monotonic() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("collector: CLOCK_MONOTONIC: %w", err)
	}
	return uint64(ts.Nano()), nil //nolint:gosec // never negative
}

// readCgroup reads the cgroup at dir through one directory fd, so the inode and the counter are of the same
// cgroup even when systemd replaces it between the two.
func readCgroup(dir string) (cgroupUsage, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return cgroupUsage{}, fmt.Errorf("cgroup: %w", err)
	}
	defer unix.Close(fd) //nolint:errcheck // a read-only directory fd
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return cgroupUsage{}, fmt.Errorf("cgroup: %w", err)
	}
	sfd, err := unix.Openat(fd, "cpu.stat", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return cgroupUsage{}, fmt.Errorf("cpu.stat: %w", err)
	}
	f := os.NewFile(uintptr(sfd), "cpu.stat")
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, statLimit))
	if err != nil {
		return cgroupUsage{}, fmt.Errorf("cpu.stat: %w", err)
	}
	usec, err := UsageUsec(string(b))
	return cgroupUsage{ino: st.Ino, usec: usec}, err
}

// UsageUsec is usage_usec of a cgroup's cpu.stat.
func UsageUsec(stat string) (uint64, error) {
	for line := range strings.SplitSeq(stat, "\n") {
		if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil { // not quoted: the record carrying the reason stays under MaxHealthBytes
				return 0, errors.New("cpu.stat: usage_usec is not a number")
			}
			return n, nil
		}
	}
	return 0, errors.New("cpu.stat: no usage_usec")
}
