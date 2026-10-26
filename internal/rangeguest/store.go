package rangeguest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

// ErrBarrierMissing is a read whose barrier never reached a sealed shard in time: what it read is not
// known to be whole (ADR 0022, point 3).
var ErrBarrierMissing = errors.New("barrier missing")

// Collector is what a store read needs of the running collector; the guest's is systemd and the
// journal, tests replace it.
type Collector interface {
	// Follow sends the seq of each "committed through" line the collector journals from now on, until
	// ctx ends, then closes the channel. It starts no process per line: one that did would add an
	// audited exec, and so a commit, of its own every time.
	Follow(ctx context.Context) (<-chan uint64, error)
	// Stop stops the collector's service, not its socket, and returns once it exited: its Close
	// sealed the open shard, and systemd starts it again when Laurel reconnects.
	Stop(ctx context.Context) error
}

// StoreRead is one read of the collector's store at Dir.
type StoreRead struct {
	Dir       string
	Collector Collector
	// Mark execs /usr/bin/true with token as its one argument: the barrier.
	Mark  func(ctx context.Context, token string) error
	Clock Clock
	// Settle is how long the commit line must stay unchanged before the stop; Poll how often it is read.
	Settle, Poll time.Duration
}

// Read calls before with every record the store holds before a fresh barrier, in seq order, and after,
// if not nil, with every record sealed after it: the collector writes health records of a tick after
// its Laurel lines, and the rest of the stopped run at its stop, so what happened before the barrier
// can be stored behind it. It reads only sealed shards (store.ReadSeals, shard.Read; never
// store.Open): it execs the barrier, waits at most wait until the commit line moved and then stayed
// for Settle, and stops the collector once. A barrier not in the shards sealed then is
// ErrBarrierMissing: a second stop would lose what Laurel had sent and not been read (T25). Only
// shards a newer collector run is writing may be beside the seals: unindexed shards above the last
// seal, their sidecars and a torn last index line; a sidecar beside a seal is an error.
func (sr StoreRead) Read(ctx context.Context, wait time.Duration, before, after func(rawrecord.Record) error) error {
	if sr.Settle <= 0 || sr.Poll <= 0 {
		return errors.New("store read: settle and poll must be positive")
	}
	if after == nil {
		after = func(rawrecord.Record) error { return nil }
	}
	token, err := barrierToken()
	if err != nil {
		return err
	}
	followCtx, stopFollow := context.WithCancel(ctx)
	defer stopFollow()
	commits, err := sr.Collector.Follow(followCtx)
	if err != nil {
		return fmt.Errorf("commit line: %w", err)
	}
	defer func() {
		stopFollow()
		for range commits { //nolint:revive // waits until the follower ended (ENGINEERING.md 7, Goroutines)
		}
	}()
	deadline := sr.Clock.Now().Add(wait)
	if err := sr.Mark(ctx, token); err != nil {
		return fmt.Errorf("barrier: %w", err)
	}
	if err := sr.settle(ctx, commits, deadline); err != nil {
		return err
	}
	if err := sr.Collector.Stop(ctx); err != nil {
		return fmt.Errorf("stop collector: %w", err)
	}
	found, err := sr.sealed(ctx, token, before, after)
	if err == nil && !found {
		return ErrBarrierMissing
	}
	return err
}

// settle returns once a commit line came after the barrier's exec and none followed for Settle, or
// at deadline; a barrier not sealed by the stop is missing.
func (sr StoreRead) settle(ctx context.Context, commits <-chan uint64, deadline time.Time) error {
	moved, since := false, sr.Clock.Now()
	for {
		for drained := false; !drained; {
			select {
			case _, ok := <-commits:
				if !ok {
					return errors.New("commit line: the journal follower ended")
				}
				moved, since = true, sr.Clock.Now()
			default:
				drained = true
			}
		}
		now := sr.Clock.Now()
		if moved && now.Sub(since) >= sr.Settle || !now.Before(deadline) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("commit line: %w", err)
		}
		sr.Clock.Sleep(sr.Poll)
	}
}

// sealed reads every seal, records before the barrier through before and the rest through after. It
// reports whether the barrier was found; then everything below its seq is sealed and read.
func (sr StoreRead) sealed(ctx context.Context, token string, before, after func(rawrecord.Record) error) (bool, error) {
	seals, err := store.ReadSeals(ctx, sr.Dir)
	var u *store.UnindexedError
	if err != nil && !errors.As(err, &u) {
		return false, fmt.Errorf("read store: %w", err)
	}
	if u != nil && len(u.Beside) > 0 {
		return false, fmt.Errorf("read store: sidecars beside sealed shards: %v", u.Beside)
	}
	found, next := false, uint64(1)
	for _, l := range seals {
		if l.First != next {
			return false, fmt.Errorf("read store: seal %s starts at %d, want %d", l.Name, l.First, next)
		}
		err := shard.Read(ctx, filepath.Join(sr.Dir, l.Name), l.SHA256, func(r rawrecord.Record) error {
			switch {
			case found:
				return after(r)
			case r.Provider == store.SensorProvider && IsBarrier(r.Data, token):
				found = true
				return nil
			}
			return before(r)
		})
		if err != nil {
			return false, fmt.Errorf("read store: %s: %w", l.Name, err)
		}
		next = l.Last + 1
	}
	if !found {
		return false, nil
	}
	return true, newerRunOnly(u, next-1)
}

// newerRunOnly accepts what ReadSeals did not index only as a newer run's: shards that start above
// last, the end of the last seal, which holds or follows the barrier, and their sidecars. A torn last
// index line follows every whole one, so it is above last too.
func newerRunOnly(u *store.UnindexedError, last uint64) error {
	if u == nil {
		return nil
	}
	for _, name := range u.Pending {
		first, err := strconv.ParseUint(strings.TrimSuffix(name, ".db"), 10, 64)
		if err != nil || first <= last {
			return fmt.Errorf("read store: unindexed shard %s is not above the barrier's seal (%d)", name, last)
		}
	}
	for _, name := range u.Sidecars {
		base := name[:strings.LastIndexByte(name, '-')]
		if !slices.Contains(u.Pending, base) {
			return fmt.Errorf("read store: sidecar %s of no unindexed shard", name)
		}
	}
	return nil
}

func barrierToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("barrier token: %w", err)
	}
	return "balistid-barrier-" + hex.EncodeToString(b[:]), nil
}

// LastCommitted returns the seq of the last "committed through" line in the collector's journal
// output (one slog JSON object per line), 0 when it has none.
func LastCommitted(journal string) uint64 {
	var seq uint64
	for _, line := range strings.Split(journal, "\n") {
		var rec map[string]json.RawMessage
		var msg string
		var n uint64
		if json.Unmarshal([]byte(line), &rec) == nil && json.Unmarshal(rec["msg"], &msg) == nil && msg == "committed through" &&
			json.Unmarshal(rec["seq"], &n) == nil {
			seq = n
		}
	}
	return seq
}
