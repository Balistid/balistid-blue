// Package store keeps the raw shards of one collector within a cap (ADR 0005, point 4; ADR 0013): it
// rotates shards, drops new records at the cap without evicting stored ones, counts the drops in loss
// records in the same gap-free seq (paid for past the cap out of a reserve allocated up front), and
// records every seal in a fsynced index, the only thing Open trusts.
package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	// LossChunk is the reserve given back to the filesystem at a time for records past the cap.
	LossChunk = 64 << 10
	// FlushEvery is how often the collector calls Flush (ADR 0013, point 1).
	FlushEvery = 250 * time.Millisecond

	day         = int64(86400e9)
	reserveName = "reserve"
	indexName   = "seals"
	indexHeader = "balistid-seals 1\n"
)

var shardName = regexp.MustCompile(`^[0-9]{20}\.db$`)

// crashAt is a test seam: crash tests kill the process at these named points.
var crashAt = func(string) {}

// Limits are the byte sizes of acceptance metrics raw_cap_gib, shard_max_gib and headroom_gib.
type Limits struct{ Cap, ShardMax, Headroom int64 }

// Seal is one line of the index: a sealed shard, its seq range and hash. The collector hands every one
// to the ledger, again after a restart (ADR 0013, point 3).
type Seal struct {
	Name        string
	First, Last uint64
	SHA256      [32]byte
}

func (l Seal) line() string {
	return fmt.Sprintf("%s %d %d %s\n", l.Name, l.First, l.Last, hex.EncodeToString(l.SHA256[:]))
}

// Store appends records with gap-free seq to the current shard of dir. Not safe for concurrent use:
// the collector is its only caller, on one goroutine.
type Store struct {
	dir         string
	lim         Limits
	seals       []Seal
	next        uint64
	sealedBytes int64
	credit      int64 // bytes past the cap paid out of the reserve
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
	now         func() time.Time
}

// Open uses dir, owned by the collector. It trusts a shard only through its index line, recovers any
// other (shard.Recover), derives the next seq from the data, and fails on anything it cannot account
// for: a malformed index, a foreign file, a gap in seq, a shard that cannot be recovered or no space
// to do it. A missing or unallocated reserve opens the store UNKNOWN.
func Open(ctx context.Context, dir string, lim Limits) (*Store, error) {
	if lim.Headroom < LossChunk || lim.ShardMax < LossChunk || lim.Cap < lim.ShardMax {
		return nil, fmt.Errorf("store: limits %+v cannot hold a shard and a loss record", lim)
	}
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() { //nolint:gosec // the collector names its own directory
		return nil, fmt.Errorf("store: %s is not a directory (%w)", dir, err)
	}
	s := &Store{dir: dir, lim: lim, next: 1, now: time.Now}
	if err := s.readIndex(); err != nil {
		return nil, err
	}
	pending, err := s.scan()
	if err != nil {
		return nil, err
	}
	if len(s.seals) > 0 {
		s.next = s.seals[len(s.seals)-1].Last + 1
	}
	if len(pending) > 0 || s.torn { // a torn index line's shard is among the pending
		if err := s.recover(ctx, pending); err != nil {
			return nil, err
		}
	}
	if err := s.reserve(); err != nil {
		s.unknown = err.Error()
	}
	return s, nil
}

// readIndex loads the index. A last line without its newline is a torn append: it is left out, so its
// shard is recovered and the index rewritten (ADR 0013, point 6).
func (s *Store) readIndex() error {
	data, err := os.ReadFile(filepath.Join(s.dir, indexName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	if !bytes.HasPrefix(data, []byte(indexHeader)) {
		return errors.New("store: index: not a balistid-seals 1 file")
	}
	lines := strings.Split(string(data[len(indexHeader):]), "\n")
	s.torn = lines[len(lines)-1] != ""
	for i, line := range lines[:len(lines)-1] {
		l, err := parseSeal(line)
		if err != nil {
			return fmt.Errorf("store: index line %d: %w", i+2, err)
		}
		if want := s.nextAfter(); l.First != want {
			return fmt.Errorf("store: index line %d: seq %d, want %d", i+2, l.First, want)
		}
		s.seals = append(s.seals, l)
	}
	return nil
}

func parseSeal(line string) (Seal, error) {
	f := strings.Split(line, " ")
	if len(f) != 4 {
		return Seal{}, errors.New("not 'name first last sha256'")
	}
	first, err1 := strconv.ParseUint(f[1], 10, 63)
	last, err2 := strconv.ParseUint(f[2], 10, 63)
	sum, err3 := hex.DecodeString(f[3])
	if err := errors.Join(err1, err2, err3); err != nil || len(sum) != 32 || last < first ||
		f[0] != fmt.Sprintf("%020d.db", first) || f[3] != strings.ToLower(f[3]) {
		return Seal{}, fmt.Errorf("malformed seal %q (%w)", line, err)
	}
	return Seal{Name: f[0], First: first, Last: last, SHA256: [32]byte(sum)}, nil
}

func (s *Store) nextAfter() uint64 {
	if len(s.seals) == 0 {
		return 1
	}
	return s.seals[len(s.seals)-1].Last + 1
}

// scan checks every file in dir: indexed shards must exist without sidecars; other shards are returned
// for recovery, in seq order; anything else is refused.
func (s *Store) scan() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	indexed := map[string]bool{}
	for _, l := range s.seals {
		indexed[l.Name] = true
	}
	var pending, sidecars []string
	for _, e := range entries {
		name := e.Name()
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), "-shm"), "-journal")
		switch {
		case name == indexName || name == indexName+".tmp" || name == reserveName || name == reserveName+".tmp":
		case !shardName.MatchString(base) || !e.Type().IsRegular():
			return nil, fmt.Errorf("store: %s does not belong in the store", name)
		case indexed[base] && base != name:
			return nil, fmt.Errorf("store: %s beside a sealed shard", name)
		case indexed[base]:
		case base == name:
			pending = append(pending, name)
		default:
			sidecars = append(sidecars, name)
		}
	}
	for _, name := range sidecars { // a WAL without its shard may hold committed records
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "-wal"), "-shm"), "-journal")
		if !slices.Contains(pending, base) {
			return nil, fmt.Errorf("store: %s without its shard", name)
		}
	}
	for _, l := range s.seals { // a missing indexed shard fails here
		n, err := allocated(filepath.Join(s.dir, l.Name))
		if err != nil {
			return nil, err
		}
		s.sealedBytes += n
	}
	return pending, nil // ReadDir sorts by name, and names are zero-padded seq
}

// recover seals and indexes the shards a crash left (ADR 0013, point 5) and rewrites the index without
// a torn line. A shard that cannot be recovered stops Open: no seq is issued past an unknown range.
func (s *Store) recover(ctx context.Context, pending []string) error {
	for _, name := range pending {
		if first, _ := strconv.ParseUint(strings.TrimSuffix(name, ".db"), 10, 63); first != s.next {
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
		s.seals = append(s.seals, Seal{Name: name, First: r.First, Last: r.Last, SHA256: r.SHA256})
		s.next = r.Last + 1
		n, err := allocated(path)
		if err != nil {
			return err
		}
		s.sealedBytes += n
		note, err := json.Marshal(struct {
			SchemaVersion int    `json:"schema_version"`
			Event         string `json:"event"`
			Shard         string `json:"shard"`
			First         uint64 `json:"first"`
			Last          uint64 `json:"last"`
		}{1, "recovered", name, r.First, r.Last})
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		s.health = append(s.health, note)
	}
	return s.writeIndex()
}

func (s *Store) remove(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("store: %w", err)
		}
	}
	return syncDir(s.dir)
}

// writeIndex replaces the index with s.seals: a temporary file, fsynced, renamed, the directory fsynced.
func (s *Store) writeIndex() error {
	var b strings.Builder
	b.WriteString(indexHeader)
	for _, l := range s.seals {
		b.WriteString(l.line())
	}
	tmp := filepath.Join(s.dir, indexName+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the collector's own directory
	if err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	_, err = f.WriteString(b.String())
	if err := errors.Join(err, f.Sync(), f.Close(), os.Rename(tmp, filepath.Join(s.dir, indexName)), syncDir(s.dir)); err != nil { //nolint:gosec // fixed names in the collector's own directory
		return fmt.Errorf("store: index: %w", err)
	}
	return nil
}

// appendIndex adds one line and fsyncs it: from then on the seal counts (ADR 0013, point 2).
func (s *Store) appendIndex(l Seal) error {
	path := filepath.Join(s.dir, indexName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) { //nolint:gosec // a fixed name in the collector's own directory
		if err := s.writeIndex(); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the collector's own directory
	if err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	line := l.line()
	_, err = f.WriteString(line[:len(line)/2])
	crashAt("mid-index")
	_, err2 := f.WriteString(line[len(line)/2:])
	if err := errors.Join(err, err2, f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("store: index: %w", err)
	}
	return nil
}

// Health is "" while the store can keep and count records, otherwise why not (UNKNOWN, ADR 0005).
func (s *Store) Health() string { return s.unknown }

// Seals returns the index, oldest first, for the collector to hand to the ledger after a restart.
func (s *Store) Seals() []Seal { return append([]Seal(nil), s.seals...) }

// Append stores data with the next seq, or drops it at the cap and counts it for a loss record, which
// Flush or the next stored record writes. It returns whether the data was stored and any shard it
// sealed on the way, already in the index.
func (s *Store) Append(ctx context.Context, provider string, providerSeq uint64, received int64, data []byte) (bool, []Seal, error) {
	if s.unknown != "" {
		return false, nil, errors.New("store: " + s.unknown)
	}
	size := int64(len(rawrecord.New(0, provider, providerSeq, received, data).Encode()))
	sealed, err := s.rotate(ctx, received, size)
	if err != nil {
		return false, sealed, err
	}
	used, err := s.used()
	if err != nil {
		return false, sealed, s.fail(err)
	}
	if used+size > s.lim.Cap {
		if s.dropped == 0 {
			s.firstDrop = received
		}
		s.dropped++
		s.lastDrop = received
		crashAt("dropped")
		return false, sealed, nil
	}
	if err := s.Flush(ctx); err != nil { // drops are recorded before the records after them
		return false, sealed, err
	}
	if err := s.put(ctx, rawrecord.New(s.next, provider, providerSeq, received, data), received); err != nil {
		return false, sealed, err
	}
	return true, sealed, nil
}

// rotate seals the current shard when a record of size would pass ShardMax or starts a new UTC day.
func (s *Store) rotate(ctx context.Context, received, size int64) ([]Seal, error) {
	if s.cur == nil {
		return nil, nil
	}
	curBytes, err := s.curBytes()
	if err != nil {
		return nil, s.fail(err)
	}
	if curBytes+size <= s.lim.ShardMax && received/day == s.curDay {
		return nil, nil
	}
	l, err := s.sealCurrent(ctx)
	if err != nil {
		return nil, err
	}
	return []Seal{l}, nil
}

// Flush writes the waiting health records and a loss record for the drops not yet counted. The
// collector calls it every FlushEvery, so a crash loses at most one interval of drop counts.
func (s *Store) Flush(ctx context.Context) error {
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

// putOwn stores one of the store's own records; past the cap it first gives LossChunk of the reserve
// back to the filesystem, and a reserve too small for that is UNKNOWN.
func (s *Store) putOwn(ctx context.Context, provider string, data []byte, received int64) error {
	used, err := s.used()
	if err != nil {
		return s.fail(err)
	}
	if used+LossChunk > s.lim.Cap+s.credit {
		path := filepath.Join(s.dir, reserveName)
		st, err := os.Lstat(path) //nolint:gosec // the reserve, a fixed name in the collector's own directory
		if err != nil {
			return s.fail(err)
		}
		if st.Size() < LossChunk {
			return s.fail(errors.New("the reserve for loss and health records is used up"))
		}
		if err := os.Truncate(path, st.Size()-LossChunk); err != nil {
			return s.fail(err)
		}
		s.credit += LossChunk
	}
	return s.put(ctx, rawrecord.New(s.next, provider, 0, received, data), received)
}

func (s *Store) put(ctx context.Context, r rawrecord.Record, received int64) error {
	if s.cur == nil {
		if s.next > math.MaxInt64 {
			return s.fail(errors.New("seq exhausted"))
		}
		name := fmt.Sprintf("%020d.db", s.next)
		cur, err := shard.Create(ctx, filepath.Join(s.dir, name))
		if err != nil {
			return s.fail(err)
		}
		crashAt("created")
		s.cur, s.curName, s.curFirst, s.curDay = cur, name, s.next, received/day
	}
	if err := s.cur.Append(ctx, r); err != nil {
		return s.fail(err)
	}
	s.next++
	crashAt("appended")
	return nil
}

// sealCurrent writes what Flush holds into the shard, then seals it (ADR 0013, point 1).
func (s *Store) sealCurrent(ctx context.Context) (Seal, error) {
	if err := s.Flush(ctx); err != nil {
		return Seal{}, err
	}
	return s.seal(ctx)
}

// seal seals the current shard and adds its index line; only then does the seal count.
func (s *Store) seal(ctx context.Context) (Seal, error) {
	sum, err := s.cur.Seal(ctx)
	s.cur = nil
	if err != nil {
		return Seal{}, s.fail(fmt.Errorf("seal %s: %w", s.curName, err))
	}
	crashAt("sealed")
	l := Seal{Name: s.curName, First: s.curFirst, Last: s.next - 1, SHA256: sum}
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
	if s.unknown == "" {
		flushErr = s.Flush(ctx)
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
	var n int64
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
