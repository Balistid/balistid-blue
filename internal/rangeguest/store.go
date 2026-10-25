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
	// Committed is the seq of the collector's last "committed through" journal line, 0 for none.
	Committed(ctx context.Context) (uint64, error)
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

// Read calls fn with every record the store holds before a fresh barrier, in seq order, reading
// only sealed shards (store.ReadSeals, shard.Read; never store.Open). It execs the barrier, waits at
// most wait until the commit line rose and then stayed for Settle, and stops the collector. A
// barrier not found in the shards sealed so far is tried again with a new one until wait has passed,
// then the read is ErrBarrierMissing. Only shards a newer collector run is writing may be beside the
// seals: unindexed shards above the seal holding the barrier, their sidecars and a torn last index
// line; a sidecar beside a seal is an error.
func (sr StoreRead) Read(ctx context.Context, wait time.Duration, fn func(rawrecord.Record) error) error {
	deadline := sr.Clock.Now().Add(wait)
	next := uint64(1)
	for {
		token, err := barrierToken()
		if err != nil {
			return err
		}
		before, err := sr.Collector.Committed(ctx)
		if err != nil {
			return fmt.Errorf("commit line: %w", err)
		}
		if err := sr.Mark(ctx, token); err != nil {
			return fmt.Errorf("barrier: %w", err)
		}
		if err := sr.settle(ctx, before, deadline); err != nil {
			return err
		}
		if err := sr.Collector.Stop(ctx); err != nil {
			return fmt.Errorf("stop collector: %w", err)
		}
		found, err := sr.sealed(ctx, token, &next, fn)
		if err != nil || found {
			return err
		}
		if !sr.Clock.Now().Before(deadline) {
			return ErrBarrierMissing
		}
	}
}

// settle returns once the commit line rose above before and then stayed for Settle, or at deadline:
// a barrier that is not sealed by then is looked for again.
func (sr StoreRead) settle(ctx context.Context, before uint64, deadline time.Time) error {
	last, since := before, sr.Clock.Now()
	for {
		n, err := sr.Collector.Committed(ctx)
		if err != nil {
			return fmt.Errorf("commit line: %w", err)
		}
		now := sr.Clock.Now()
		if n != last {
			last, since = n, now
		}
		if last > before && now.Sub(since) >= sr.Settle || !now.Before(deadline) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("commit line: %w", err)
		}
		sr.Clock.Sleep(sr.Poll)
	}
}

// sealed reads the seals from *next on up to the barrier's record and moves *next past them. It
// reports whether the barrier was found; then everything below its seq is sealed and read.
func (sr StoreRead) sealed(ctx context.Context, token string, next *uint64, fn func(rawrecord.Record) error) (bool, error) {
	seals, err := store.ReadSeals(ctx, sr.Dir)
	var u *store.UnindexedError
	if err != nil && !errors.As(err, &u) {
		return false, fmt.Errorf("read store: %w", err)
	}
	if u != nil && len(u.Beside) > 0 {
		return false, fmt.Errorf("read store: sidecars beside sealed shards: %v", u.Beside)
	}
	for _, l := range seals {
		if l.Last < *next {
			continue
		}
		if l.First != *next {
			return false, fmt.Errorf("read store: seal %s starts at %d, want %d", l.Name, l.First, *next)
		}
		found := false
		err := shard.Read(ctx, filepath.Join(sr.Dir, l.Name), l.SHA256, func(r rawrecord.Record) error {
			switch {
			case found:
				return nil
			case r.Provider == store.SensorProvider && IsBarrier(r.Data, token):
				found = true
				return nil
			}
			return fn(r)
		})
		if err != nil {
			return false, fmt.Errorf("read store: %s: %w", l.Name, err)
		}
		*next = l.Last + 1
		if found {
			return true, newerRunOnly(u, l.Last)
		}
	}
	return false, nil
}

// newerRunOnly accepts what ReadSeals did not index only as a newer run's: shards that start above
// last, the end of the seal holding the barrier, and their sidecars. A torn last index line follows
// every whole one, so it is above last too.
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
