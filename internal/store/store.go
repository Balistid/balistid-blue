// Package store keeps the raw shards of one collector within a cap (ADR 0005, point 4): it rotates
// shards, drops new records at the cap without evicting stored ones, and records the drops as loss
// records in the same gap-free seq, paid for past the cap out of a reserve file allocated up front.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const (
	// LossProvider names the store's own loss records.
	LossProvider = "balistid-loss"
	// LossChunk is the reserve given back to the filesystem at a time for loss records past the cap.
	LossChunk = 64 << 10
	// LossDelay bounds the drops a crash can lose uncounted (acceptance crash_loss_ms).
	LossDelay   = time.Second
	day         = int64(86400e9)
	reserveName = "reserve"
)

// Limits are the byte sizes of acceptance metrics raw_cap_gib, shard_max_gib and headroom_gib.
type Limits struct{ Cap, ShardMax, Headroom int64 }

// Sealed is a shard the store sealed; its hash goes to the ledger, without which it is never read.
type Sealed struct {
	Path   string
	SHA256 [32]byte
}

// Store appends records with gap-free seq to the current shard of dir. Not safe for concurrent use.
// A record larger than ShardMax gets a shard of its own; rawrecord.MaxBytes keeps that small.
type Store struct {
	dir         string
	lim         Limits
	next        uint64
	sealedBytes int64
	credit      int64 // bytes past the cap paid out of the reserve
	cur         *shard.Writer
	curPath     string
	curDay      int64
	dropped     uint64
	firstDrop   int64
	lastDrop    int64
	dropSince   time.Time
	unknown     string
	now         func() time.Time
}

// Open uses dir, owned by the collector, with next as the first seq to store. It refuses limits that
// cannot hold a loss record, a shard left unsealed (a sidecar file, or a .db not out of WAL mode) and
// returns a store that is UNKNOWN when the reserve is missing or not allocated.
func Open(ctx context.Context, dir string, next uint64, lim Limits) (*Store, error) {
	if lim.Headroom < LossChunk || lim.ShardMax < LossChunk || lim.Cap < lim.ShardMax {
		return nil, fmt.Errorf("store: limits %+v cannot hold a shard and a loss record", lim)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s := &Store{dir: dir, lim: lim, next: next, now: time.Now}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") || strings.HasSuffix(name, "-journal") {
			return nil, fmt.Errorf("store: %s is left from an unsealed shard", name)
		}
		if strings.HasSuffix(name, ".db") {
			if err := shard.Final(filepath.Join(dir, name)); err != nil {
				return nil, fmt.Errorf("store: %w", err)
			}
			n, err := allocated(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			s.sealedBytes += n
		}
	}
	if err := s.reserve(); err != nil {
		s.unknown = err.Error()
	}
	return s, nil
}

// Health is "" while the store can keep and count records, otherwise why not (UNKNOWN, ADR 0005).
func (s *Store) Health() string { return s.unknown }

// Append stores data with the next seq, or drops it at the cap and counts it for a loss record, which
// is written before the next stored record and at most LossDelay after the first uncounted drop. It
// returns whether the data was stored and the shards it sealed on the way.
func (s *Store) Append(ctx context.Context, provider string, providerSeq uint64, received int64, data []byte) (bool, []Sealed, error) {
	if s.unknown != "" {
		return false, nil, errors.New("store: " + s.unknown)
	}
	size := int64(len(rawrecord.New(0, provider, providerSeq, received, data).Encode()))
	var sealed []Sealed
	if s.cur != nil {
		curBytes, err := s.curBytes()
		if err != nil {
			return false, nil, s.fail(err)
		}
		if curBytes+size > s.lim.ShardMax || received/day != s.curDay {
			done, err := s.sealCurrent(ctx)
			if err != nil {
				return false, nil, err
			}
			sealed = append(sealed, done)
		}
	}
	used, err := s.used()
	if err != nil {
		return false, sealed, s.fail(err)
	}
	if used+size > s.lim.Cap {
		if s.dropped == 0 {
			s.firstDrop, s.dropSince = received, s.now()
		}
		s.dropped++
		s.lastDrop = received
		if s.now().Sub(s.dropSince) >= LossDelay {
			return false, sealed, s.writeLoss(ctx, received)
		}
		return false, sealed, nil
	}
	if s.dropped > 0 {
		if err := s.writeLoss(ctx, received); err != nil {
			return false, sealed, err
		}
	}
	if err := s.appendRecord(ctx, rawrecord.New(s.next, provider, providerSeq, received, data), received); err != nil {
		return false, sealed, err
	}
	return true, sealed, nil
}

// Close counts the drops not yet recorded and seals the current shard, even when the count fails.
func (s *Store) Close(ctx context.Context, received int64) ([]Sealed, error) {
	var lossErr error
	if s.dropped > 0 && s.unknown == "" {
		lossErr = s.writeLoss(ctx, received)
	}
	if s.cur == nil {
		return nil, lossErr
	}
	done, err := s.sealCurrent(ctx)
	if err != nil {
		return nil, errors.Join(lossErr, err)
	}
	return []Sealed{done}, lossErr
}

func (s *Store) appendRecord(ctx context.Context, r rawrecord.Record, received int64) error {
	if s.cur == nil {
		s.curPath = filepath.Join(s.dir, fmt.Sprintf("%020d.db", s.next))
		cur, err := shard.Create(ctx, s.curPath)
		if err != nil {
			return s.fail(err)
		}
		s.cur, s.curDay = cur, received/day
	}
	if err := s.cur.Append(ctx, r); err != nil {
		return s.fail(err)
	}
	s.next++
	return nil
}

// writeLoss appends one loss record for the drops since the last; past the cap it first gives
// LossChunk of the reserve back to the filesystem, and a reserve too small for that is UNKNOWN.
func (s *Store) writeLoss(ctx context.Context, received int64) error {
	used, err := s.used()
	if err != nil {
		return s.fail(err)
	}
	if used+LossChunk > s.lim.Cap+s.credit {
		path := filepath.Join(s.dir, reserveName)
		st, err := os.Stat(path)
		if err != nil {
			return s.fail(err)
		}
		if st.Size() < LossChunk {
			return s.fail(errors.New("the reserve for loss records is used up"))
		}
		if err := os.Truncate(path, st.Size()-LossChunk); err != nil {
			return s.fail(err)
		}
		s.credit += LossChunk
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
	if err := s.appendRecord(ctx, rawrecord.New(s.next, LossProvider, 0, received, data), received); err != nil {
		return err
	}
	s.dropped = 0
	return nil
}

func (s *Store) sealCurrent(ctx context.Context) (Sealed, error) {
	sum, err := s.cur.Seal(ctx)
	s.cur = nil
	if err != nil {
		return Sealed{}, s.fail(fmt.Errorf("seal %s: %w", filepath.Base(s.curPath), err))
	}
	n, err := allocated(s.curPath)
	if err != nil {
		return Sealed{}, s.fail(err)
	}
	s.sealedBytes += n
	return Sealed{Path: s.curPath, SHA256: sum}, nil
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
			return fmt.Errorf("reserve: %d bytes, %d allocated: not a reserve for one more loss record", st.Size, st.Blocks*512)
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
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("reserve: %w", err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
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
	for _, p := range []string{s.curPath, s.curPath + "-wal"} {
		b, err := allocated(p)
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
