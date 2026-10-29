// Package store keeps the raw shards of one collector within a cap (ADR 0005, point 4; ADR 0013): it
// rotates shards, drops new records at the cap without evicting stored ones, counts the drops in loss
// records in the same gap-free seq (paid for past the cap out of a reserve allocated up front), and
// records every seal in a fsynced index, the only thing Open trusts. It retires the oldest shard once
// the witness's and its own clock both put it past the retention age (ADR 0029).
package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const (
	// LossProvider and HealthProvider name the store's own records.
	LossProvider, HealthProvider = "balistid-loss", "balistid-health"
	// SensorProvider is the only provider Append accepts: Laurel's lines (ADR 0004). Another sensor
	// needs its own ADR (R9).
	SensorProvider = "laurel"
	// LossChunk is the reserve given back to the filesystem at a time for records past the cap.
	LossChunk = 64 << 10
	// FlushEvery is how often the collector calls Flush (ADR 0013, point 1).
	FlushEvery = 250 * time.Millisecond

	day         = int64(86400e9)
	reserveName = "reserve"
	indexName   = "seals"
	indexHeader = "balistid-seals 2\n"
)

var shardName = regexp.MustCompile(`^[0-9]{20}\.db$`)

// admitSlack is what SQLite needs beyond a record's two copies (main file and WAL): b-tree pages
// split by the insert. A record is admitted only if, besides that, a whole WAL (shard.WALMaxBytes,
// what one checkpoint can add to the main file) still fits under the cap, so the cap is never passed.
const admitSlack = 64 << 10

// ownSlack is a page and its WAL frame: what an own record adds besides its data.
const ownSlack = 4096 + 24

// Health records are small and their queue bounded, so a collector bug cannot fill memory or the
// reserve with them.
const (
	// MaxHealthBytes is the largest health record NoteHealth takes.
	MaxHealthBytes  = 4 << 10
	maxHealthQueued = 64
)

// Limits are the byte sizes of acceptance metrics raw_cap_gib, shard_max_gib and headroom_gib.
type Limits struct{ Cap, ShardMax, Headroom int64 }

// Seal is one line of the index: a sealed shard, its seq range and hash. The collector hands every one
// to the ledger, again after a restart (ADR 0013, point 3). Its times, Unix seconds, decide retirement
// together, never one alone (ADR 0029).
type Seal struct {
	Name        string
	First, Last uint64
	SHA256      [32]byte
	Sealed      int64 // the store's clock at the seal
	Cosigned    int64 // the witness's time when a cosigned checkpoint was first known to cover it; 0 until then
}

func (l Seal) line() string {
	s := fmt.Sprintf("%s %d %d %s %d", l.Name, l.First, l.Last, hex.EncodeToString(l.SHA256[:]), l.Sealed)
	if l.Cosigned != 0 {
		s += " " + strconv.FormatInt(l.Cosigned, 10)
	}
	return s + "\n"
}

// Store appends records with gap-free seq to the current shard of dir. Not safe for concurrent use:
// the collector is its only caller, on one goroutine.
type Store struct {
	dir         string
	lim         Limits
	seals       []Seal
	next        uint64
	sealedBytes int64
	cur         *shard.Writer
	curName     string
	curFirst    uint64
	curDay      int64
	dropped     uint64
	firstDrop   int64
	lastDrop    int64
	health      [][]byte // health records waiting for Flush
	torn        bool     // the index ends in a torn line
	unknown     string
	sealLost    bool   // a seal failed: what the shard held since its last commit may be gone
	committed   uint64 // the last seq on disk to stay: sealed, recovered or committed
	now         func() time.Time
	avail       func() (int64, error) // what the filesystem lets the collector allocate (a test seam)
	given       int64                 // what the reserve gave back: Headroom less its size, kept for own records
	crashAt     func(string)          // a test seam: crash tests kill the process at these named points
	retiring    *retiring             // a retired shard whose unlink failed: Expire finishes it first
}

// Open uses dir, owned by the collector. It trusts a shard only through its index line, recovers any
// other (shard.Recover), derives the next seq from the data, and fails on anything it cannot account
// for: a malformed index, a foreign file, a gap in seq, a shard that cannot be recovered or no space
// to do it. A missing or unallocated reserve opens the store UNKNOWN.
func Open(ctx context.Context, dir string, lim Limits) (*Store, error) {
	return openWith(ctx, dir, lim, func(string) {})
}

func openWith(ctx context.Context, dir string, lim Limits, crashAt func(string)) (*Store, error) {
	if lim.Headroom < shard.WALMaxBytes+LossChunk || lim.ShardMax < LossChunk+admitSlack || lim.Cap < lim.ShardMax+shard.WALMaxBytes {
		return nil, fmt.Errorf("store: limits %+v cannot hold a shard and a loss record", lim)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// Only the collector may write here (ADR 0007): the code checks it rather than trust the install.
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != os.Getuid() || st.Mode&0o022 != 0 {
		return nil, fmt.Errorf("store: %s is not a directory of this user that only it can write", dir)
	}
	s := &Store{dir: dir, lim: lim, next: 1, now: time.Now, crashAt: crashAt, avail: func() (int64, error) { return freeBytes(dir) }}
	var err error
	if s.seals, s.torn, err = readSeals(ctx, dir); err != nil {
		return nil, err
	}
	pending, err := s.scan()
	if err != nil {
		return nil, err
	}
	if len(s.seals) > 0 {
		s.next = s.seals[len(s.seals)-1].Last + 1
	}
	// Recovery indexes the pending shards, and the shard holding its health record is the next to seal:
	// refused before any write when the index could not take them all (a deliberate upper bound), or
	// each retried Open would seal another shard and fail again.
	if n := indexBytes(s.seals) + int64(len(pending)+1)*maxLineBytes; len(pending) > 0 && n > indexCap {
		return nil, fmt.Errorf("store: index: recovering %d shards could take %d bytes, past the %d its reader takes", len(pending), n, indexCap)
	}
	indexed := len(s.seals)
	if err := s.recover(ctx, pending); err != nil {
		return nil, err
	}
	s.committed = s.next - 1 // every seq below next is in a sealed shard
	if err := s.reserve(); err != nil {
		s.unknown = err.Error()
	}
	if len(pending) > 0 || s.torn { // a torn index line's shard is among the pending
		// The recovery health records are stored before the index makes the recovery final, so a
		// second crash cannot erase the trace of the first.
		if s.unknown != "" { // the next Open recovers again, and then stores the health records
			s.seals = s.seals[:indexed]
			return s, nil
		}
		err := s.flush(ctx)
		if err == nil {
			err = s.commit()
		}
		if err == nil {
			err = s.room(indexBytes(s.seals), func() error { return s.writeIndex(s.seals) })
		}
		if err != nil && s.cur != nil { // the health records' shard is sealed; the next Open recovers it
			_, serr := s.cur.Seal(ctx)
			err = errors.Join(err, serr)
		}
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ErrUnindexed marks a store directory holding shards its index does not list (a torn or lost index
// line, or a shard still open): its seals are not the whole store.
var ErrUnindexed = errors.New("store: shards missing from the index")

// UnindexedError is the ErrUnindexed of ReadSeals with what it found, by kind, each list sorted: a
// reader that knows a newer collector run is writing (the range guest) accepts some and refuses the
// rest (ADR 0022, point 3).
type UnindexedError struct {
	Pending  []string // shards the index does not list
	Sidecars []string // -wal, -shm or -journal files of those shards
	Beside   []string // sidecars of indexed shards, which a sealed shard never has
	Torn     bool     // the index ends in a line without its newline
}

func (e *UnindexedError) Error() string {
	return fmt.Sprintf("%v: %v (torn last line: %v)", ErrUnindexed, slices.Sorted(slices.Values(slices.Concat(e.Pending, e.Sidecars, e.Beside))), e.Torn)
}

// Is makes errors.Is(err, ErrUnindexed) true.
func (e *UnindexedError) Is(target error) bool { return target == ErrUnindexed }

// maxIndexBytes bounds the index read into memory: about 128 bytes a seal, so over 100000 shards,
// years of daily shards at the cap. A larger index is refused, not read.
const maxIndexBytes = 16 << 20

// indexCap is what the writers let the index grow to: what its reader takes (a test lowers it).
var indexCap int64 = maxIndexBytes

// maxLineBytes is the longest index line: the widest name and seq numbers.
var maxLineBytes = int64(len(Seal{Name: fmt.Sprintf("%020d.db", 0), First: math.MaxUint64, Last: math.MaxUint64,
	Sealed: math.MaxInt64, Cosigned: math.MaxInt64}.line()))

// indexCheckEvery is how many index lines are parsed between checks of ctx.
const indexCheckEvery = 4096

// ReadSeals returns the seal index of dir, oldest first, without opening the store: it writes nothing and
// checks no owner, so a reader such as the range guest finds the sealed shards for shard.Read after the
// collector stopped; a dir that group or others can write is refused, as Open refuses it. It holds the entries of dir to the rules Open does (classify): an entry that
// does not belong in the store, or an indexed shard that is not there, is an error. A shard file the
// index does not list, or any shard sidecar, makes it fail with an *UnindexedError, along with the seals it
// did list: Open recovers such a shard or refuses the directory; a reader would silently miss it either way.
// A dir that is missing, not a directory or a symlink is an error, not an empty store.
func ReadSeals(ctx context.Context, dir string) ([]Seal, error) {
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("store: %s is not a directory", dir)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("store: %s can be written by others than its owner", dir)
	}
	seals, torn, err := readSeals(ctx, dir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	c, err := classify(entries, seals)
	if err != nil {
		return nil, err
	}
	// A sealed shard has no sidecar: a -wal, -shm or -journal file, never listed, holds data no seal covers.
	if torn || len(c.pending)+len(c.sidecars)+len(c.beside) > 0 {
		return seals, &UnindexedError{Pending: c.pending, Sidecars: c.sidecars, Beside: c.beside, Torn: torn}
	}
	return seals, nil // a retired shard's file is not evidence the index keeps: it is left out
}

// layout is a store directory sorted by what Open must do with each entry.
type layout struct {
	pending  []string // shards the index does not list, in seq order: Open recovers them
	sidecars []string // sidecars of shards the index does not list
	beside   []string // sidecars of indexed shards, which a sealed shard never has
	retired  []string // a shard below the index's first line, and its sidecars: Open finishes its retirement
}

// classify checks every entry of a store directory against its index: the index and reserve are regular
// files, every other entry is a shard or a shard's sidecar, and lost+found, which a filesystem root has,
// is the one directory allowed. Anything else is refused, as is an indexed shard that is not there. Open
// and ReadSeals share it, so a reader accepts no entry that the collector refuses as foreign.
func classify(list []os.DirEntry, seals []Seal) (layout, error) {
	indexed := make(map[string]bool, len(seals))
	for _, l := range seals {
		indexed[l.Name] = true
	}
	var c layout
	present := map[string]bool{}
	for _, e := range list {
		name, base := e.Name(), sidecarOf(e.Name())
		switch {
		case name == "lost+found" && e.IsDir():
		case !e.Type().IsRegular():
			return layout{}, fmt.Errorf("store: %s is not a regular file", name)
		case !ownerOnly(e):
			return layout{}, fmt.Errorf("store: %s can be written by its group or read by others", name)
		case name == indexName || name == indexName+".tmp" || name == reserveName || name == reserveName+".tmp":
		case !shardName.MatchString(base):
			return layout{}, fmt.Errorf("store: %s does not belong in the store", name)
		case indexed[base] && base != name:
			c.beside = append(c.beside, name)
		case indexed[base]:
			present[name] = true
		case len(seals) > 0 && base < seals[0].Name: // zero-padded names sort as their seqs
			c.retired = append(c.retired, name)
		case base == name:
			c.pending = append(c.pending, name)
		default:
			c.sidecars = append(c.sidecars, name)
		}
	}
	var missing []string
	for _, l := range seals {
		if !present[l.Name] {
			missing = append(missing, l.Name)
		}
	}
	if len(missing) > 0 {
		return layout{}, fmt.Errorf("store: indexed shards missing: %v", missing)
	}
	return c, nil // the caller's ReadDir sorts by name, and names are zero-padded seq
}

// ownerOnly is true for a file whose mode only the owner can write and only the group may read (a sealed
// shard, for balistid-normalize, ADR 0007). It checks the mode, not the owner: hygiene, not a T1 control.
func ownerOnly(e os.DirEntry) bool {
	info, err := e.Info()
	return err == nil && info.Mode().Perm()&0o027 == 0
}

// readSeals parses the index of dir. A last line without its newline is a torn append: it is left out
// and reported, so Open recovers its shard and rewrites the index (ADR 0013, point 6).
func readSeals(ctx context.Context, dir string) ([]Seal, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("store: index: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, indexName), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the index, a fixed name in the store directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: index: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("store: index: not a regular file (%w)", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIndexBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("store: index: %w", err)
	}
	if len(data) > maxIndexBytes {
		return nil, false, fmt.Errorf("store: index over %d bytes", maxIndexBytes)
	}
	if !bytes.HasPrefix(data, []byte(indexHeader)) {
		return nil, false, errors.New("store: index: not a balistid-seals 2 file")
	}
	lines := strings.Split(string(data[len(indexHeader):]), "\n")
	var seals []Seal
	for i, line := range lines[:len(lines)-1] {
		if i%indexCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, false, fmt.Errorf("store: index: %w", err)
			}
		}
		l, err := parseSeal(line)
		if err != nil {
			return nil, false, fmt.Errorf("store: index line %d: %w", i+2, err)
		}
		// Seqs run on from the first line, which retirement moves (ADR 0029, point 4).
		if want := nextAfter(seals); len(seals) > 0 && l.First != want {
			return nil, false, fmt.Errorf("store: index line %d: seq %d, want %d", i+2, l.First, want)
		}
		// Cosign times cover a prefix and never fall: MarkCosigned writes them so.
		if prev := newestCosigned(seals); l.Cosigned != 0 && (l.Cosigned < prev || len(seals) > 0 && seals[len(seals)-1].Cosigned == 0) {
			return nil, false, fmt.Errorf("store: index line %d: cosign time %d after %d", i+2, l.Cosigned, prev)
		}
		seals = append(seals, l)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("store: index: %w", err)
	}
	return seals, lines[len(lines)-1] != "", nil
}

func parseSeal(line string) (Seal, error) {
	f := strings.Split(line, " ")
	if len(f) != 5 && len(f) != 6 {
		return Seal{}, errors.New("not 'name first last sha256 sealed [cosigned]'")
	}
	first, err1 := strconv.ParseUint(f[1], 10, 63)
	last, err2 := strconv.ParseUint(f[2], 10, 63)
	sum, err3 := hex.DecodeString(f[3])
	sealed, err4 := strconv.ParseInt(f[4], 10, 64)
	if err4 == nil && sealed < 0 {
		err4 = errors.New("a seal time before 1970")
	}
	var cosigned int64
	var err5 error
	if len(f) == 6 {
		if cosigned, err5 = strconv.ParseInt(f[5], 10, 64); err5 == nil && cosigned <= 0 {
			err5 = errors.New("a cosign time is after 1970; none is written as none")
		}
	}
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil || len(sum) != 32 || first == 0 || last < first ||
		bytes.Equal(sum, make([]byte, 32)) { // seqs start at 1; no shard hashes to zero
		return Seal{}, fmt.Errorf("malformed seal %q (%w)", line, err)
	}
	// One spelling per line: the name from its first seq, lower-case hex, no sign or leading zero.
	l := Seal{Name: f[0], First: first, Last: last, SHA256: [32]byte(sum), Sealed: sealed, Cosigned: cosigned}
	if f[0] != fmt.Sprintf("%020d.db", first) || l.line() != line+"\n" {
		return Seal{}, fmt.Errorf("malformed seal %q", line)
	}
	return l, nil
}

// nextAfter is the first seq after seals.
func nextAfter(seals []Seal) uint64 {
	if len(seals) == 0 {
		return 1
	}
	return seals[len(seals)-1].Last + 1
}

// newestCosigned is the latest cosign time in seals, or 0: times cover a prefix and never fall.
func newestCosigned(seals []Seal) int64 {
	for i := len(seals) - 1; i >= 0; i-- {
		if seals[i].Cosigned != 0 {
			return seals[i].Cosigned
		}
	}
	return 0
}

// scan checks every entry of dir (classify): indexed shards exist without sidecars, and other shards are
// returned for recovery in seq order with at most one sidecar suffix each.
func (s *Store) scan() ([]string, error) {
	list, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	c, err := classify(list, s.seals)
	if err != nil {
		return nil, err
	}
	if len(c.beside) > 0 {
		return nil, fmt.Errorf("store: %s beside a sealed shard", c.beside[0])
	}
	// Expire retires one shard at a time and finishes a failed one first, so a crash, or a failed removal
	// before Close, leaves one below the first line; more is neither.
	bases := map[string]bool{}
	for _, name := range c.retired {
		bases[sidecarOf(name)] = true
	}
	if len(bases) > 1 {
		return nil, fmt.Errorf("store: %d shards below the index's first line: %v", len(bases), slices.Sorted(maps.Keys(bases)))
	}
	for _, name := range c.retired { // the index left it before the crash that kept its file
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
	}
	if len(c.retired) > 0 {
		if err := syncDir(s.dir); err != nil {
			return nil, err
		}
	}
	pending := c.pending
	for _, name := range c.sidecars { // a WAL without its shard may hold committed records
		if !slices.Contains(pending, sidecarOf(name)) {
			return nil, fmt.Errorf("store: %s without its shard", name)
		}
	}
	for _, l := range s.seals {
		n, err := allocated(filepath.Join(s.dir, l.Name))
		if err != nil {
			return nil, err
		}
		s.sealedBytes += n
	}
	return pending, nil // ReadDir sorts by name, and names are zero-padded seq
}

// sidecarOf is the shard a SQLite sidecar belongs to, or name itself: one suffix only.
func sidecarOf(name string) string {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if base, ok := strings.CutSuffix(name, suffix); ok {
			return base
		}
	}
	return name
}

// recover seals the shards a crash left (ADR 0013, point 5) and queues a health record for each; Open
// then rewrites the index. A shard that cannot be recovered stops Open: no seq is issued past an
// unknown range.
func (s *Store) recover(ctx context.Context, pending []string) error {
	var shards int
	var first, last uint64
	for _, name := range pending {
		if n, _ := strconv.ParseUint(strings.TrimSuffix(name, ".db"), 10, 63); n != s.next {
			return fmt.Errorf("store: unsealed shard %s does not start at seq %d", name, s.next)
		}
		path := filepath.Join(s.dir, name)
		r, err := shard.Recover(ctx, path)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if r.Empty {
			if err := s.remove(path); err != nil {
				return err
			}
			continue
		}
		if r.First != s.next {
			return fmt.Errorf("store: recovered shard %s holds seq %d..%d, want %d first", name, r.First, r.Last, s.next)
		}
		s.seals = append(s.seals, Seal{Name: name, First: r.First, Last: r.Last, SHA256: r.SHA256, Sealed: max(s.now().Unix(), 0)})
		s.next = r.Last + 1
		n, err := allocated(path)
		if err != nil {
			return err
		}
		s.sealedBytes += n
		if shards++; shards == 1 {
			first = r.First
		}
		last = r.Last
	}
	if shards == 0 {
		return nil
	}
	// One record for the whole recovery, however many crashes left shards: the queue stays bounded.
	note, err := json.Marshal(struct {
		SchemaVersion int    `json:"schema_version"`
		Event         string `json:"event"`
		Shards        int    `json:"shards"`
		First         uint64 `json:"first"`
		Last          uint64 `json:"last"`
	}{1, "recovered", shards, first, last})
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	s.health = append(s.health, note)
	return nil
}

func (s *Store) remove(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) { //nolint:gosec // a shard name parseSeal or scan checked, in the collector's own directory
			return fmt.Errorf("store: %w", err)
		}
	}
	return syncDir(s.dir)
}

// writeIndex replaces the index with seals: a temporary file, fsynced, renamed only once it is whole,
// then the directory fsynced.
func (s *Store) writeIndex(seals []Seal) error {
	var b strings.Builder
	b.WriteString(indexHeader)
	for _, l := range seals {
		b.WriteString(l.line())
	}
	if int64(b.Len()) > indexCap {
		return fmt.Errorf("store: index: %d bytes would pass the %d its reader takes", b.Len(), indexCap)
	}
	tmp := filepath.Join(s.dir, indexName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the collector's own directory
	if err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	_, err = f.WriteString(b.String())
	if err := errors.Join(err, f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	if err := errors.Join(os.Rename(tmp, filepath.Join(s.dir, indexName)), syncDir(s.dir)); err != nil { //nolint:gosec // fixed names in the collector's own directory
		return fmt.Errorf("store: index: %w", err)
	}
	return nil
}

// appendIndex adds one line and fsyncs it: from then on the seal counts (ADR 0013, point 2). When the
// filesystem is full it frees a chunk of the reserve (point 8) and writes the index whole instead, so a
// short append never stays in it.
func (s *Store) appendIndex(l Seal) error {
	if n := indexBytes(s.seals) + int64(len(l.line())); n > indexCap {
		return fmt.Errorf("store: index: %d bytes would pass the %d its reader takes", n, indexCap)
	}
	err := s.appendLine(l)
	if errors.Is(err, syscall.ENOSPC) {
		all := append(slices.Clone(s.seals), l)
		err = s.room(indexBytes(all), func() error { return s.writeIndex(all) })
	}
	return err
}

func (s *Store) appendLine(l Seal) error {
	path := filepath.Join(s.dir, indexName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) { //nolint:gosec // a fixed name in the collector's own directory
		return s.writeIndex(append(slices.Clone(s.seals), l))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the collector's own directory
	if err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	if st, serr := f.Stat(); serr != nil || !st.Mode().IsRegular() {
		return errors.Join(fmt.Errorf("store: index: not a regular file (%w)", serr), f.Close())
	}
	_, err = f.WriteString(l.line())
	if err := errors.Join(err, f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	return nil
}

// room runs write, and once more if the filesystem was full, after freeing enough of the reserve for
// need bytes (one chunk at least). A chunk that gives the filesystem no space stops it, as in putOwn.
func (s *Store) room(need int64, write func() error) error {
	err := write()
	if !errors.Is(err, syscall.ENOSPC) {
		return err
	}
	for freed := int64(0); freed < max(need, 1); freed += LossChunk {
		before, ferr := s.fsRoom()
		if ferr != nil {
			return errors.Join(err, s.fail(ferr))
		}
		if ferr := s.free(); ferr != nil {
			return errors.Join(err, ferr)
		}
		after, ferr := s.fsRoom()
		if ferr == nil && after <= before {
			ferr = errors.New("freeing the reserve gave the filesystem no space")
		}
		if ferr != nil {
			return errors.Join(err, s.fail(ferr))
		}
	}
	return write()
}

// indexBytes is the size of an index holding seals, which a whole rewrite needs free.
func indexBytes(seals []Seal) int64 {
	n := int64(len(indexHeader))
	for _, l := range seals {
		n += int64(len(l.line()))
	}
	return n
}

// free gives one chunk of the reserve back to the filesystem; a reserve too small for that is UNKNOWN.
func (s *Store) free() error {
	path := filepath.Join(s.dir, reserveName)
	st, err := os.Lstat(path) //nolint:gosec // the reserve, a fixed name in the collector's own directory
	if err != nil {
		return s.fail(err)
	}
	if st.Size() < LossChunk {
		return s.fail(errors.New("the reserve for loss, health and index records is used up"))
	}
	if err := os.Truncate(path, st.Size()-LossChunk); err != nil {
		return s.fail(err)
	}
	s.given += LossChunk
	return nil
}

// Health is "" while the store can keep and count records, otherwise why not (UNKNOWN, ADR 0005).
func (s *Store) Health() string { return s.unknown }

// NoteHealth queues a health record (JSON with a schema_version, at most MaxHealthBytes) for the next
// Flush; the collector calls it when the state it reports changes (ADR 0013, point 1). It refuses a
// larger record or a full queue, which only a collector that stopped flushing can cause.
func (s *Store) NoteHealth(data []byte) error {
	if len(data) > MaxHealthBytes || len(s.health) >= maxHealthQueued {
		return fmt.Errorf("store: health record of %d bytes with %d queued refused", len(data), len(s.health))
	}
	var v struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &v); err != nil || v.SchemaVersion < 1 {
		return fmt.Errorf("store: a health record must be JSON with a schema_version (%w)", err)
	}
	s.health = append(s.health, slices.Clone(data))
	return nil
}

// Seals returns the index, oldest first. The seals Append, Flush and Close return are only the new
// ones; the collector can always catch up from here, after the last seal the ledger reports.
func (s *Store) Seals() []Seal { return append([]Seal(nil), s.seals...) }

// ErrNotIndexed marks a seal the index does not hold as named: the store never sealed that shard.
var ErrNotIndexed = errors.New("store: no such seal in the index")

// ClockSkew is how far the witness's clock may be off the store's: a replayed checkpoint can date a shard
// at most this much before its seal, and a witness time further ahead of the store's clock is not taken.
const ClockSkew = time.Hour

// ErrUndated marks a checkpoint that left the seal it names without a cosign time: predating that seal or
// one before it by more than ClockSkew, as a witness clock that lags the store's does, or met by an UNKNOWN
// store. Seals before it may have been dated; a later checkpoint dates the rest.
var ErrUndated = errors.New("store: the named seal stays without a cosign time")

// ErrStale marks a checkpoint older than a cosign time already stored: a replayed or delayed note. It dates
// nothing, and its time is no witness's latest.
var ErrStale = errors.New("store: cosign time older than a stored one")

// MarkCosigned dates seals by a checkpoint the witness cosigned at at, which covers the seal of first..last
// with hash sum and so every shard before it (ADR 0029, point 3). Each of them still without a cosign time
// gets at, in seq order, up to the first that at predates by more than ClockSkew: that one and the rest
// wait for a later checkpoint, as a replayed old one would. A time older than a stored one dates nothing
// (ErrStale), so times never fall, and a stored time never changes. When the named seal stays undated it
// returns ErrUndated, after dating what it could. A store that is UNKNOWN is left as it is, and an index that
// cannot be rewritten stays as it was: the next call tries again, and neither spends the reserve.
func (s *Store) MarkCosigned(first, last uint64, sum [32]byte, at time.Time) error {
	if s.unknown != "" {
		return fmt.Errorf("%w: the store is UNKNOWN", ErrUndated)
	}
	i := slices.IndexFunc(s.seals, func(l Seal) bool { return l.First == first && l.Last == last && l.SHA256 == sum })
	if i < 0 {
		return fmt.Errorf("%w: %d-%d", ErrNotIndexed, first, last)
	}
	t, skew := at.Unix(), int64(ClockSkew/time.Second)
	if t <= 0 {
		return fmt.Errorf("store: cosign time %d", t)
	}
	if newest := newestCosigned(s.seals); t < newest {
		return fmt.Errorf("%w: %d before %d", ErrStale, t, newest)
	}
	seals, dated := slices.Clone(s.seals), 0
	for j := range seals[:i+1] {
		if seals[j].Cosigned != 0 {
			continue
		}
		if t < seals[j].Sealed-skew {
			break
		}
		seals[j].Cosigned, dated = t, dated+1
	}
	var undated error
	if seals[i].Cosigned == 0 {
		undated = fmt.Errorf("%w: %d predates a seal by more than %v", ErrUndated, t, ClockSkew)
	}
	if dated == 0 {
		return undated
	}
	if err := s.writeIndex(seals); err != nil {
		return err
	}
	s.seals = seals
	s.crashAt("cosigned")
	return undated
}

// Expire retires the oldest shard once both clocks put it minAge past its seal (ADR 0029, point 4): the
// witness's latest time past the shard's cosign time, and the store's clock past its seal time. It never
// retires the last sealed shard, nor any while latest is older than a stored cosign time. The index loses
// the shard before its file goes, so a crash in between leaves a file below the first line, which Open
// removes; an unlink that fails is retried on the next call before another shard leaves the index, so
// there is never more than one. It returns the shard it retired, if any, with the unlink's error; the
// space freed first refills the reserve. Like MarkCosigned it leaves an UNKNOWN store alone.
func (s *Store) Expire(latest time.Time, minAge time.Duration) (*Seal, error) {
	if minAge <= 0 {
		return nil, fmt.Errorf("store: retention age %v", minAge)
	}
	if s.unknown != "" {
		return nil, nil
	}
	if s.retiring != nil {
		return nil, s.unlinkRetired()
	}
	if len(s.seals) < 2 {
		return nil, nil
	}
	o, secs := s.seals[0], int64((minAge+time.Second-1)/time.Second)
	old := func(from, to int64) bool { return to >= from && to-from >= secs } // both at least 0: no overflow
	if o.Cosigned == 0 || latest.Unix() < newestCosigned(s.seals) || !old(o.Cosigned, latest.Unix()) || !old(o.Sealed, s.now().Unix()) {
		return nil, nil
	}
	n, err := allocated(filepath.Join(s.dir, o.Name))
	if err != nil {
		return nil, err
	}
	if err := s.writeIndex(s.seals[1:]); err != nil {
		return nil, err
	}
	s.seals, s.retiring = slices.Clone(s.seals[1:]), &retiring{name: o.Name, bytes: n}
	s.crashAt("retired")
	return &o, s.unlinkRetired()
}

// retiring is a shard the index no longer holds whose file is not yet gone.
type retiring struct {
	name  string
	bytes int64
}

// unlinkRetired removes the retiring shard's file and gives its space back, first to the reserve.
func (s *Store) unlinkRetired() error {
	if err := s.remove(filepath.Join(s.dir, s.retiring.name)); err != nil {
		return err
	}
	s.crashAt("unlinked")
	s.sealedBytes -= s.retiring.bytes
	s.retiring = nil
	return s.refill()
}

// refill gives the reserve back what it gave the store's own records, once retiring freed space; a
// filesystem still short leaves it as it is until the next retirement.
func (s *Store) refill() error {
	if s.given <= 0 {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(s.dir, reserveName), os.O_WRONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the reserve, a fixed name in the collector's own directory
	if err != nil {
		return fmt.Errorf("store: reserve: %w", err)
	}
	err = errors.Join(syscall.Fallocate(int(f.Fd()), 0, 0, s.lim.Headroom), f.Sync(), f.Close())
	if errors.Is(err, syscall.ENOSPC) { // a filesystem may have extended it in part: count what it holds
		st, serr := os.Lstat(filepath.Join(s.dir, reserveName)) //nolint:gosec // the reserve, a fixed name in the collector's own directory
		if serr != nil {
			return fmt.Errorf("store: reserve: %w", serr)
		}
		s.given = s.lim.Headroom - st.Size()
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: reserve: %w", err)
	}
	s.given = 0
	return nil
}

// Leaves returns up to max committed records after seq after, in seq order, fewer once their stored data
// reaches budget bytes (reading a leaf walks past its record's data), with the seal of each shard whose
// last record is among them, which the ledger logs after that record (ADR 0027, points 1 and 4).
func (s *Store) Leaves(ctx context.Context, after uint64, max int, budget int64) ([]shard.Leaf, []Seal, error) {
	if s.unknown != "" { // a seal whose index line failed holds seqs no index names: the reopen recovers it
		return nil, nil, errors.New("store: " + s.unknown)
	}
	if budget <= 0 { // a zero budget would read nothing forever, unseen
		return nil, nil, fmt.Errorf("store: leaves budget %d", budget)
	}
	if max <= 0 || after >= s.committed {
		return nil, nil, nil
	}
	end := min(s.committed, after+uint64(max))
	var out []shard.Leaf
	var seals []Seal
	for used := int64(0); after < end && used < budget; {
		i := sort.Search(len(s.seals), func(i int) bool { return s.seals[i].Last > after })
		var got []shard.Leaf
		var err error
		switch {
		case i < len(s.seals) && s.seals[i].First <= after+1:
			l := s.seals[i]
			got, err = shard.Leaves(ctx, filepath.Join(s.dir, l.Name), SensorProvider, after, min(end, l.Last), budget-used)
			if err == nil && got[len(got)-1].Seq == l.Last {
				seals = append(seals, l)
			}
		case s.cur != nil && s.curFirst <= after+1:
			got, err = s.cur.Leaves(ctx, SensorProvider, after, end, budget-used)
		default:
			err = fmt.Errorf("seq %d is in no shard", after+1)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("store: leaves: %w", err)
		}
		out, after = append(out, got...), got[len(got)-1].Seq
		for _, l := range got {
			used += l.Size
		}
	}
	return out, seals, nil
}

// Committed is the last seq the store has made durable: through it, a crash loses no record. It
// rises only when a commit or a seal returns (a seal Append makes on the way included), never for
// the record Append stores, and Open sets it to what it found on disk (crash_loss_ms, ADR 0022).
func (s *Store) Committed() uint64 { return s.committed }

// Append stores a sensor's record under the next seq, whatever r.Seq holds, or drops it at the cap and
// counts it for a loss record, which Flush or the next stored record writes. A record that
// rawrecord.Check refuses, or from a provider other than the sensor's, fails with ErrRefused and the
// store stays usable; any other error means the store failed. It returns whether r was stored and any shard it sealed on the way, already in
// the index. A stored record is durable once the next Flush, Close or seal returns; a crash before
// that loses it, as it does a record still on its way to Append.
func (s *Store) Append(ctx context.Context, r rawrecord.Record) (bool, []Seal, error) {
	if s.unknown != "" {
		return false, nil, errors.New("store: " + s.unknown)
	}
	if err := checkRecord(r); err != nil {
		return false, nil, err
	}
	received := r.Received
	size := int64(r.EncodedLen()) // its length does not depend on Seq
	used, err := s.used()
	if err != nil {
		return false, nil, s.fail(err)
	}
	free, err := s.fsRoom()
	if err != nil {
		return false, nil, s.fail(err)
	}
	// A full filesystem drops like the cap: another writer can fill it first (T10). What the reserve gave
	// back is kept for the store's own records, so a sensor record never spends it, and the own records
	// written before it (Flush's queue) must fit too.
	if need := shard.WALMaxBytes + 2*size + admitSlack; used+need > s.lim.Cap || need+s.queuedBytes() > free-max(s.given, 0) { // dropped before any rotation
		if s.dropped == 0 {
			s.firstDrop = received
		}
		s.dropped++
		s.lastDrop = received
		s.crashAt("dropped")
		return false, nil, nil
	}
	sealed, err := s.rotate(ctx, size)
	if err != nil {
		return false, sealed, err
	}
	if err := s.flush(ctx); err != nil { // drops are recorded before the records after them
		return false, sealed, err
	}
	r.Seq = s.next // a seal or loss record on the way took seq numbers
	if err := s.put(ctx, r); err != nil {
		return false, sealed, err
	}
	return true, sealed, nil
}

// ErrRefused marks a record Append did not take because of the record itself; the store is unharmed.
var ErrRefused = errors.New("store: record refused")

// checkRecord admits only the sensor's records that rawrecord.Check accepts; the store's own providers
// are written by the store alone (ADR 0013). Anything else is refused before the shard would fail on it.
func checkRecord(r rawrecord.Record) error {
	if r.Provider != SensorProvider {
		return fmt.Errorf("%w: provider %q is not the sensor's", ErrRefused, r.Provider)
	}
	if err := r.Check(); err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return nil
}

// rotate seals the current shard when size more bytes would pass ShardMax or the store's clock is on
// another UTC day than the shard (one shard per day, ADR 0005; the store's clock, not the records'
// receive times, so its own records and the sensor's agree).
func (s *Store) rotate(ctx context.Context, size int64) ([]Seal, error) {
	if s.cur == nil {
		return nil, nil
	}
	curBytes, err := s.curBytes()
	if err != nil {
		return nil, s.fail(err)
	}
	if curBytes+size <= s.lim.ShardMax && s.now().UnixNano()/day == s.curDay {
		return nil, nil
	}
	l, err := s.sealCurrent(ctx)
	if err != nil {
		return nil, err
	}
	return []Seal{l}, nil
}

// Flush writes the waiting health records and a loss record for the drops not yet counted. When they
// would pass ShardMax or a new day began, it seals the current shard, with the waiting records written
// into it first (ADR 0013, point 1). The collector calls it every FlushEvery, so a crash loses at most
// one interval of drop counts, and hands on what it sealed.
func (s *Store) Flush(ctx context.Context) ([]Seal, error) {
	if s.unknown != "" { // the records taken before are still made durable
		return nil, errors.Join(errors.New("store: "+s.unknown), s.commit())
	}
	if len(s.health) == 0 && s.dropped == 0 {
		return nil, s.commit()
	}
	size := int64(512) // a loss record with its encoding
	for _, h := range s.health {
		size += int64(len(h)) + 512
	}
	sealed, err := s.rotate(ctx, size)
	if err != nil {
		return sealed, err
	}
	if err := s.flush(ctx); err != nil {
		return sealed, err
	}
	return sealed, s.commit()
}

// commit makes the current shard's records durable.
func (s *Store) commit() error {
	if s.cur == nil {
		return nil
	}
	if err := s.cur.Commit(); err != nil {
		return s.fail(err)
	}
	s.committed = s.next - 1
	return nil
}

// flush writes what Flush holds into the current shard, at the store's clock.
func (s *Store) flush(ctx context.Context) error {
	if s.unknown != "" {
		return errors.New("store: " + s.unknown)
	}
	now := s.now().UnixNano()
	for len(s.health) > 0 {
		if err := s.putOwn(ctx, HealthProvider, s.health[0], now); err != nil {
			return err
		}
		s.health = s.health[1:]
	}
	if s.dropped == 0 {
		return nil
	}
	data, err := json.Marshal(struct {
		SchemaVersion int    `json:"schema_version"`
		Dropped       uint64 `json:"dropped"`
		FirstReceived int64  `json:"first_received"`
		LastReceived  int64  `json:"last_received"`
	}{1, s.dropped, s.firstDrop, s.lastDrop})
	if err != nil {
		return s.fail(err)
	}
	if err := s.putOwn(ctx, LossProvider, data, now); err != nil {
		return err
	}
	s.dropped = 0
	return nil
}

// putOwn stores one of the store's own records. Past the cap or on a full filesystem it is paid for out
// of the reserve: past the cap, what the reserve has already given back must cover the overrun; on a
// full filesystem, the free space must hold the record. Until both hold another chunk is freed; a
// used-up reserve, or a chunk that gives the filesystem nothing back, makes the store UNKNOWN.
func (s *Store) putOwn(ctx context.Context, provider string, data []byte, received int64) error {
	used, err := s.used()
	if err != nil {
		return s.fail(err)
	}
	// The record's two copies, a split page and a checkpoint it may trigger.
	need := shard.WALMaxBytes + 2*int64(len(data)) + 2*ownSlack
	freedFor, before := false, int64(0) // whether the last chunk was freed for the filesystem, and its room then
	for {
		free, err := s.fsRoom()
		if err != nil {
			return s.fail(err)
		}
		if freedFor && free <= before {
			return s.fail(errors.New("freeing the reserve gave the filesystem no space"))
		}
		if over := used + need - s.lim.Cap; (over <= 0 || over <= s.given) && need <= free {
			break
		}
		freedFor, before = need > free, free
		if err := s.free(); err != nil {
			return err
		}
	}
	return s.put(ctx, rawrecord.New(s.next, provider, 0, received, data))
}

// queuedBytes is what the own records waiting for Flush can allocate: a loss record and the health records.
func (s *Store) queuedBytes() int64 {
	n := int64(0)
	if s.dropped > 0 {
		n = 2 * (512 + ownSlack)
	}
	for _, h := range s.health {
		n += 2 * (int64(len(h)) + ownSlack)
	}
	return n
}

// fsRoom is what the filesystem can still take besides the records not yet committed: free space is a
// second cap, which another writer on the same filesystem can reach before the store's own (T10).
func (s *Store) fsRoom() (int64, error) {
	free, err := s.avail()
	if err != nil {
		return 0, err
	}
	if s.cur != nil {
		free -= s.cur.Pending()
	}
	return free, nil
}

// freeBytes is the space the filesystem of dir leaves to unprivileged users (statfs f_bavail, in
// f_frsize units); quotas are not seen.
func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	err := syscall.Statfs(dir, &st)
	for errors.Is(err, syscall.EINTR) {
		err = syscall.Statfs(dir, &st)
	}
	if err != nil {
		return 0, fmt.Errorf("statfs: %w", err)
	}
	// The Statfs_t field types differ between architectures, so the conversions stay.
	unit := int64(st.Frsize) //nolint:unconvert // int32 on 386 and arm
	if unit <= 0 {
		unit = int64(st.Bsize) //nolint:unconvert // as above
	}
	if unit <= 0 {
		return 0, fmt.Errorf("statfs: block size %d", unit)
	}
	return int64(min(uint64(st.Bavail), uint64(math.MaxInt64)/uint64(unit))) * unit, nil //nolint:gosec,unconvert // bounded by MaxInt64 / unit; types differ by architecture
}

func (s *Store) put(ctx context.Context, r rawrecord.Record) error {
	if s.cur == nil {
		if s.next > math.MaxInt64 {
			return s.fail(errors.New("seq exhausted"))
		}
		name := fmt.Sprintf("%020d.db", s.next)
		cur, err := shard.Create(ctx, filepath.Join(s.dir, name))
		if err != nil {
			return s.fail(err)
		}
		s.crashAt("created")
		s.cur, s.curName, s.curFirst, s.curDay = cur, name, s.next, s.now().UnixNano()/day
	}
	if err := s.cur.Append(ctx, r); err != nil {
		return s.fail(err)
	}
	s.next++
	s.crashAt("appended")
	return nil
}

// sealCurrent writes what Flush holds into the shard, then seals it (ADR 0013, point 1).
func (s *Store) sealCurrent(ctx context.Context) (Seal, error) {
	if err := s.flush(ctx); err != nil {
		return Seal{}, err
	}
	return s.seal(ctx)
}

// seal seals the current shard and adds its index line; only then does the seal count.
func (s *Store) seal(ctx context.Context) (Seal, error) {
	sum, err := s.cur.Seal(ctx)
	s.cur = nil
	if err != nil {
		s.sealLost = true
		return Seal{}, s.fail(fmt.Errorf("seal %s: %w", s.curName, err))
	}
	s.committed = s.next - 1 // a sealed shard outlives a lost index line (Open recovers it)
	s.crashAt("sealed")
	l := Seal{Name: s.curName, First: s.curFirst, Last: s.next - 1, SHA256: sum, Sealed: max(s.now().Unix(), 0)}
	if err := s.appendIndex(l); err != nil {
		return Seal{}, s.fail(err)
	}
	s.seals = append(s.seals, l)
	n, err := allocated(filepath.Join(s.dir, s.curName))
	if err != nil {
		return Seal{}, s.fail(err)
	}
	s.sealedBytes += n
	return l, nil
}

// Close flushes and seals the current shard; it seals even when the store is UNKNOWN or the flush
// fails, since the records already in the shard are evidence.
func (s *Store) Close(ctx context.Context) ([]Seal, error) {
	var flushErr error
	switch {
	case s.unknown == "":
		flushErr = s.flush(ctx)
	case s.dropped > 0 || len(s.health) > 0 || s.sealLost: // what is waiting, or a failed seal took, is lost: say so
		flushErr = errors.New("store: " + s.unknown)
	}
	if s.cur == nil {
		return nil, flushErr
	}
	l, err := s.seal(ctx)
	if err != nil {
		return nil, errors.Join(flushErr, err)
	}
	return []Seal{l}, flushErr
}

// fail makes the store UNKNOWN: a store that cannot keep or count a record says so instead of guessing.
func (s *Store) fail(err error) error {
	if s.unknown == "" {
		s.unknown = err.Error()
	}
	return fmt.Errorf("store: %w", err)
}

// reserve checks the reserve file, or makes it: allocated (not sparse) under a temporary name, then
// renamed, so a failed allocation never leaves a short file in its place.
func (s *Store) reserve() error {
	path := filepath.Join(s.dir, reserveName)
	if _, err := os.Lstat(path); err == nil {
		var st syscall.Stat_t
		if err := syscall.Lstat(path, &st); err != nil {
			return fmt.Errorf("reserve: %w", err)
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size < LossChunk || st.Blocks*512 < st.Size {
			return fmt.Errorf("reserve: %d bytes, %d allocated: not a reserve for one more record", st.Size, st.Blocks*512)
		}
		s.given = s.lim.Headroom - st.Size // a restart forgets nothing the reserve gave
		return nil
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the collector's own directory
	if err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	if err := errors.Join(syscall.Fallocate(int(f.Fd()), 0, 0, s.lim.Headroom), f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	if err := errors.Join(os.Rename(tmp, path), syncDir(s.dir)); err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	return nil
}

// used is the space the shards hold: sealed ones, the current one and its WAL, by allocated blocks.
func (s *Store) used() (int64, error) {
	n, err := s.curBytes()
	return s.sealedBytes + n, err
}

func (s *Store) curBytes() (int64, error) {
	if s.cur == nil {
		return 0, nil
	}
	n := s.cur.Pending() // records not yet committed need not be on disk yet
	for _, p := range []string{s.curName, s.curName + "-wal"} {
		b, err := allocated(filepath.Join(s.dir, p))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		n += b
	}
	return n, nil
}

func allocated(path string) (int64, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, fmt.Errorf("store: %s: %w", filepath.Base(path), err)
	}
	return st.Blocks * 512, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the collector's own directory
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}
