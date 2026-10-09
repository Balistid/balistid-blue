// Package store keeps the raw shards of one collector within a cap (ADR 0005, point 4): it rotates
// shards, drops new records at the cap without evicting stored ones, and writes loss records into a
// separate shard whose space comes out of a reserve file allocated in advance.
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

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const (
	// LossProvider names the store's own loss records.
	LossProvider = "balistid-loss"
	// LossChunk is the reserve given up before each loss record: a WAL frame and the record fit in it.
	LossChunk = 64 << 10
	// LossInterval is the shortest gap, in received nanoseconds, between two loss records of one run of drops.
	LossInterval = int64(60e9)
	day          = int64(86400e9)
	reserveName  = "reserve"
)

// Limits are the byte sizes of acceptance metrics raw_cap_gib, shard_max_gib and headroom_gib.
type Limits struct{ Cap, ShardMax, Headroom int64 }

// Sealed is a shard the store sealed; its hash goes to the ledger, without which it is never read.
type Sealed struct {
	Path   string
	SHA256 [32]byte
}

// Store appends records with gap-free seq to the current shard of dir. Not safe for concurrent use.
type Store struct {
	dir                 string
	lim                 Limits
	next, lossNext      uint64
	sealedBytes         int64
	cur, loss           *shard.Writer
	curPath, lossPath   string
	curDay              int64
	dropped             uint64
	firstDrop, lastLoss int64
	unknown             string
}

// Open uses dir, owned by the collector, with next as the first seq to store. It allocates the reserve
// on first use and refuses a dir in which a shard was left unsealed (-wal, -shm or -journal beside it).
func Open(dir string, next uint64, lim Limits) (*Store, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s := &Store{dir: dir, lim: lim, next: next, lossNext: 1, firstDrop: -1, lastLoss: -1}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") || strings.HasSuffix(name, "-journal") {
			return nil, fmt.Errorf("store: %s is left from an unsealed shard", name)
		}
		if strings.HasSuffix(name, ".db") {
			n, err := allocated(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			s.sealedBytes += n
		}
	}
	if err := s.reserve(); err != nil {
		return nil, err
	}
	return s, nil
}

// Health is "" while the store can record losses, otherwise why it cannot (UNKNOWN, ADR 0005).
// Records under the cap are still stored; only the loss records fail.
func (s *Store) Health() string { return s.unknown }

// Append stores data with the next seq, or drops it at the cap and counts it for a loss record. It
// returns whether the data was stored and the shards it sealed on the way.
func (s *Store) Append(ctx context.Context, provider string, providerSeq uint64, received int64, data []byte) (bool, []Sealed, error) {
	r := rawrecord.New(s.next, provider, providerSeq, received, data)
	size := int64(len(r.Encode()))
	var sealed []Sealed
	if s.cur != nil {
		curBytes, err := s.curBytes()
		if err != nil {
			return false, nil, err
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
		return false, sealed, err
	}
	if used+size > s.lim.Cap {
		return false, sealed, s.drop(ctx, received)
	}
	if err := s.flushLoss(ctx, received); err != nil {
		return false, sealed, err
	}
	if s.cur == nil {
		s.curPath = filepath.Join(s.dir, fmt.Sprintf("%020d.db", s.next))
		if s.cur, err = shard.Create(ctx, s.curPath); err != nil {
			return false, sealed, fmt.Errorf("store: %w", err)
		}
		s.curDay = received / day
	}
	if err := s.cur.Append(ctx, r); err != nil {
		return false, sealed, fmt.Errorf("store: %w", err)
	}
	s.next++
	return true, sealed, nil
}

// Close writes a loss record for drops not yet recorded and seals both open shards.
func (s *Store) Close(ctx context.Context, received int64) ([]Sealed, error) {
	var sealed []Sealed
	if s.dropped > 0 {
		if err := s.writeLoss(ctx, received); err != nil {
			return nil, err
		}
	}
	for _, w := range []struct {
		writer **shard.Writer
		path   string
	}{{&s.cur, s.curPath}, {&s.loss, s.lossPath}} {
		if *w.writer == nil {
			continue
		}
		sum, err := (*w.writer).Seal(ctx)
		*w.writer = nil
		if err != nil {
			return sealed, fmt.Errorf("store: seal %s: %w", filepath.Base(w.path), err)
		}
		sealed = append(sealed, Sealed{Path: w.path, SHA256: sum})
	}
	return sealed, nil
}

func (s *Store) sealCurrent(ctx context.Context) (Sealed, error) {
	sum, err := s.cur.Seal(ctx)
	s.cur = nil
	if err != nil {
		return Sealed{}, fmt.Errorf("store: seal %s: %w", filepath.Base(s.curPath), err)
	}
	n, err := allocated(s.curPath)
	if err != nil {
		return Sealed{}, err
	}
	s.sealedBytes += n
	return Sealed{Path: s.curPath, SHA256: sum}, nil
}

// drop counts a record dropped at the cap and writes a loss record for the first drop of a run and
// then at most once per LossInterval.
func (s *Store) drop(ctx context.Context, received int64) error {
	if s.dropped == 0 {
		s.firstDrop = received
	}
	s.dropped++
	if s.lastLoss < 0 || received-s.lastLoss >= LossInterval {
		return s.writeLoss(ctx, received)
	}
	return nil
}

// flushLoss records the drops of a run that ended before its next loss record was due.
func (s *Store) flushLoss(ctx context.Context, received int64) error {
	if s.dropped == 0 {
		return nil
	}
	return s.writeLoss(ctx, received)
}

// writeLoss gives LossChunk of the reserve back to the filesystem and spends it on one loss record
// in the loss shard, which has its own gap-free seq; before_seq is the seq the next stored record
// gets. A reserve too small for that leaves the store UNKNOWN.
func (s *Store) writeLoss(ctx context.Context, received int64) error {
	path := filepath.Join(s.dir, reserveName)
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("store: reserve: %w", err)
	}
	if st.Size() < LossChunk {
		s.unknown = "the reserve for loss records is used up"
		return errors.New("store: " + s.unknown)
	}
	if err := os.Truncate(path, st.Size()-LossChunk); err != nil {
		return fmt.Errorf("store: reserve: %w", err)
	}
	if s.loss == nil {
		s.lossPath = filepath.Join(s.dir, fmt.Sprintf("loss-%020d.db", s.next))
		if s.loss, err = shard.Create(ctx, s.lossPath); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	data, err := json.Marshal(struct {
		Dropped       uint64 `json:"dropped"`
		BeforeSeq     uint64 `json:"before_seq"`
		FirstReceived int64  `json:"first_received"`
		LastReceived  int64  `json:"last_received"`
	}{s.dropped, s.next, s.firstDrop, received})
	if err != nil {
		return fmt.Errorf("store: loss record: %w", err)
	}
	if err := s.loss.Append(ctx, rawrecord.New(s.lossNext, LossProvider, 0, received, data)); err != nil {
		return fmt.Errorf("store: loss record: %w", err)
	}
	s.lossNext++
	s.dropped, s.firstDrop, s.lastLoss = 0, -1, received
	return nil
}

// reserve allocates the reserve file to Headroom bytes on first use (not sparse: fallocate).
func (s *Store) reserve() error {
	path := filepath.Join(s.dir, reserveName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // the collector's own directory
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: reserve: %w", err)
	}
	if err := errors.Join(syscall.Fallocate(int(f.Fd()), 0, 0, s.lim.Headroom), f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("store: reserve: %w", err)
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
