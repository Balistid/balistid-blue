package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const noon = int64(1791460800000000000)

var small = Limits{Cap: 1 << 20, ShardMax: 256 << 10, Headroom: 4 * LossChunk}

// clock is a store clock the test moves by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func open(t *testing.T, dir string, next uint64) (*Store, *clock) {
	t.Helper()
	s, err := Open(t.Context(), dir, next, small)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Unix(0, noon)}
	s.now = c.now
	return s, c
}

// fill appends n records of size bytes, one ms apart from start, and returns how many were stored and
// every shard sealed on the way.
func fill(t *testing.T, s *Store, n, size int, start int64) (int, []Sealed) {
	t.Helper()
	stored, all := 0, []Sealed(nil)
	for i := range n {
		ok, sealed, err := s.Append(t.Context(), "laurel", 1, start+int64(i)*1e6, make([]byte, size))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			stored++
		}
		all = append(all, sealed...)
	}
	return stored, all
}

func closeStore(t *testing.T, s *Store) []Sealed {
	t.Helper()
	sealed, err := s.Close(t.Context(), noon+day/2)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// readAll reads every sealed shard and checks that seq is gap-free across them from first.
func readAll(t *testing.T, sealed []Sealed, first uint64) []rawrecord.Record {
	t.Helper()
	var got []rawrecord.Record
	for _, s := range sealed {
		if err := shard.Read(t.Context(), s.Path, s.SHA256, func(r rawrecord.Record) error {
			got = append(got, r)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i, r := range got {
		if r.Seq != first+uint64(i) {
			t.Fatalf("record %d has seq %d, want %d", i, r.Seq, first+uint64(i))
		}
	}
	return got
}

// losses sums the drops the loss records count and returns the seq of the last loss record.
func losses(t *testing.T, rs []rawrecord.Record) (dropped uint64, lastSeq uint64) {
	t.Helper()
	for _, r := range rs {
		if r.Provider != LossProvider {
			continue
		}
		var l struct {
			SchemaVersion int    `json:"schema_version"`
			Dropped       uint64 `json:"dropped"`
		}
		if err := json.Unmarshal(r.Data, &l); err != nil || l.SchemaVersion != 1 {
			t.Fatalf("loss record %q: %v", r.Data, err)
		}
		dropped += l.Dropped
		lastSeq = r.Seq
	}
	return dropped, lastSeq
}

func reserveSize(t *testing.T, dir string) int64 {
	t.Helper()
	st, err := os.Stat(filepath.Join(dir, reserveName))
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

func TestReserveIsAllocated(t *testing.T) {
	dir := t.TempDir()
	if s, _ := open(t, dir, 1); s.Health() != "" {
		t.Fatal(s.Health())
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dir, reserveName), &st); err != nil || st.Blocks*512 < small.Headroom {
		t.Fatalf("reserve holds %d bytes of disk, want %d: %v", st.Blocks*512, small.Headroom, err)
	}
}

func TestASparseOrShortReserveIsUnknown(t *testing.T) {
	for name, size := range map[string]int64{"sparse": small.Headroom, "short": LossChunk - 1} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, reserveName), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(filepath.Join(dir, reserveName), size); err != nil {
			t.Fatal(err)
		}
		if s, _ := open(t, dir, 1); s.Health() == "" {
			t.Errorf("%s reserve accepted", name)
		}
	}
}

func TestShardsSealAtShardMaxAndDayAndStayUnderTheCap(t *testing.T) {
	s, _ := open(t, t.TempDir(), 1)
	stored, sealed := fill(t, s, 40, 16<<10, noon)
	more, sealedDay := fill(t, s, 1, 10, noon+day)
	all := append(append(sealed, sealedDay...), closeStore(t, s)...)
	if len(sealed) == 0 || len(sealedDay) != 1 {
		t.Fatalf("sealed %d at ShardMax and %d at the day change, want some and 1", len(sealed), len(sealedDay))
	}
	var total int64
	for _, x := range all {
		n, err := allocated(x.Path)
		if err != nil {
			t.Fatal(err)
		}
		total += n
		if n > small.ShardMax+LossChunk {
			t.Errorf("%s holds %d bytes, ShardMax %d", x.Path, n, small.ShardMax)
		}
	}
	if total > small.Cap {
		t.Errorf("shards hold %d bytes, cap %d", total, small.Cap)
	}
	if got := readAll(t, all, 1); len(got) != stored+more {
		t.Fatalf("read %d records, stored %d", len(got), stored+more)
	}
}

// At the cap new records are dropped, stored ones stay, and every drop is counted in a loss record in
// the same gap-free seq.
func TestTheCapDropsNewRecordsAndCountsEveryDrop(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir, 1)
	stored, sealed := fill(t, s, 200, 16<<10, noon)
	got := readAll(t, append(sealed, closeStore(t, s)...), 1)
	dropped, _ := losses(t, got)
	if stored == 200 || int(dropped) != 200-stored { //nolint:gosec // test count
		t.Fatalf("stored %d of 200, loss records count %d drops", stored, dropped)
	}
	if spent := small.Headroom - reserveSize(t, dir); spent > LossChunk {
		t.Errorf("one loss record past the cap used %d bytes of reserve", spent)
	}
}

func TestALossRecordFollowsWithinLossDelayWithoutAnotherWrite(t *testing.T) {
	s, c := open(t, t.TempDir(), 1)
	fill(t, s, 100, 16<<10, noon)
	if s.dropped == 0 {
		t.Fatal("nothing dropped")
	}
	c.t = c.t.Add(LossDelay)
	if _, _, err := s.Append(t.Context(), "laurel", 1, noon, make([]byte, 16<<10)); err != nil {
		t.Fatal(err)
	}
	if s.dropped != 0 {
		t.Fatalf("%d drops still uncounted %s after the first", s.dropped, LossDelay)
	}
}

// A record that fits after a run of drops is stored right after the loss record that counts them.
func TestARunOfDropsIsRecordedBeforeTheNextStoredRecord(t *testing.T) {
	s, _ := open(t, t.TempDir(), 1)
	_, sealed := fill(t, s, 70, 16<<10, noon)
	ok, more, err := s.Append(t.Context(), "laurel", 1, noon+1e8, []byte("x"))
	if err != nil || !ok {
		t.Fatalf("a small record under the cap: stored %v, %v", ok, err)
	}
	got := readAll(t, append(append(sealed, more...), closeStore(t, s)...), 1)
	_, lossSeq := losses(t, got)
	if last := got[len(got)-1]; string(last.Data) != "x" || last.Seq != lossSeq+1 {
		t.Fatalf("small record seq %d, last loss record seq %d", last.Seq, lossSeq)
	}
}

// A restart at the cap keeps counting drops and spends at most one more chunk of the reserve.
func TestARestartAtTheCapKeepsCountingDrops(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir, 1)
	_, sealed := fill(t, s, 200, 16<<10, noon)
	sealed = append(sealed, closeStore(t, s)...)
	before := reserveSize(t, dir)
	next := uint64(len(readAll(t, sealed, 1))) + 1
	s2, _ := open(t, dir, next)
	stored2, sealed2 := fill(t, s2, 50, 16<<10, noon+1e12)
	got := readAll(t, append(sealed2, closeStore(t, s2)...), next)
	// Sealing drops the WAL, so a few records may fit again; every other one is counted.
	if dropped, _ := losses(t, got); dropped == 0 || uint64(stored2)+dropped != 50 || s2.Health() != "" { //nolint:gosec // test count
		t.Fatalf("after restart: stored %d, counted %d drops of 50, health %q", stored2, dropped, s2.Health())
	}
	if spent := before - reserveSize(t, dir); spent > LossChunk {
		t.Errorf("the restart spent %d bytes of reserve", spent)
	}
}

// With the reserve used up the store is UNKNOWN, Close still seals, and the dir opens again.
func TestAUsedUpReserveIsUnknownAndCloseStillSeals(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(t.Context(), dir, 1, Limits{Cap: 256 << 10, ShardMax: 256 << 10, Headroom: LossChunk})
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Unix(0, noon)}
	s.now = c.now
	for i := 0; s.Health() == "" && i < 1000; i++ {
		c.t = c.t.Add(LossDelay)
		_, _, _ = s.Append(t.Context(), "laurel", 1, noon, make([]byte, 16<<10))
	}
	if s.Health() == "" {
		t.Fatal("the reserve ran out and the store did not say so")
	}
	if sealed, _ := s.Close(t.Context(), noon); len(sealed) != 1 {
		t.Fatalf("Close sealed %d shards after the reserve ran out", len(sealed))
	}
	if _, err := Open(t.Context(), dir, 100, small); err != nil {
		t.Fatalf("the dir does not open again: %v", err)
	}
}

func TestAFailedSealIsUnknown(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir, 1)
	fill(t, s, 3, 100, noon)
	moved := filepath.Join(dir, "moved")
	if err := os.Rename(s.curPath, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, s.curPath); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Close(t.Context(), noon); err == nil || s.Health() == "" {
		t.Fatalf("a failed seal: err %v, health %q", err, s.Health())
	}
}

func TestOpenRefusesAnUnsealedShardAndBadLimits(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir, 1)
	fill(t, s, 3, 100, noon) // the current shard stays open: its sidecars are in dir
	if _, err := Open(t.Context(), dir, 4, small); err == nil {
		t.Error("Open accepted a directory with an open shard")
	}
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "00000000000000000001.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), empty, 1, small); err == nil {
		t.Error("Open accepted an empty .db")
	}
	if _, err := Open(t.Context(), t.TempDir(), 1, Limits{Cap: 1 << 20, ShardMax: 256 << 10, Headroom: 1}); err == nil {
		t.Error("Open accepted a headroom smaller than one loss record")
	}
}

// A loss record Close cannot pay for leaves the store UNKNOWN, and the shard is still sealed.
func TestCloseSealsWhenItsLossRecordFails(t *testing.T) {
	dir := t.TempDir()
	s, _ := open(t, dir, 1)
	fill(t, s, 100, 16<<10, noon) // drops start; the clock stands, so no loss record yet
	if err := os.Truncate(filepath.Join(dir, reserveName), 0); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Close(t.Context(), noon)
	if err == nil || s.Health() == "" || len(sealed) != 1 {
		t.Fatalf("Close: err %v, health %q, sealed %d", err, s.Health(), len(sealed))
	}
}
