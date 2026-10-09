package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const noon = int64(1791460800000000000)

var small = Limits{Cap: 1 << 20, ShardMax: 256 << 10, Headroom: 4 * LossChunk}

func open(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, 1, small)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fill appends n records of size bytes, one ms apart from start, and returns how many were stored and
// every shard sealed on the way.
func fill(t *testing.T, s *Store, n, size int, start int64) (int, []Sealed) {
	t.Helper()
	stored, all := 0, []Sealed(nil)
	for i := 0; i < n; i++ {
		ok, sealed, err := s.Append(t.Context(), "laurel", uint64(i), start+int64(i)*1e6, make([]byte, size))
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

func readAll(t *testing.T, sealed []Sealed) []rawrecord.Record {
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
	return got
}

func TestReserveIsAllocated(t *testing.T) {
	dir := t.TempDir()
	open(t, dir)
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dir, reserveName), &st); err != nil || st.Blocks*512 < small.Headroom {
		t.Fatalf("reserve holds %d bytes of disk, want %d: %v", st.Blocks*512, small.Headroom, err)
	}
}

func TestShardsSealAtShardMaxAndDayAndStayUnderTheCap(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	stored, sealed := fill(t, s, 40, 16<<10, noon)
	more, sealedDay := fill(t, s, 1, 10, noon+day)
	closed, err := s.Close(t.Context(), noon+day)
	if err != nil {
		t.Fatal(err)
	}
	all := append(append(sealed, sealedDay...), closed...)
	if len(sealed) == 0 || len(sealedDay) != 1 {
		t.Fatalf("sealed %d at ShardMax and %d at the day change, want some and 1", len(sealed), len(sealedDay))
	}
	var total int64
	for _, x := range all {
		n, err := allocated(x.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(filepath.Base(x.Path), "loss-") {
			total += n
			if n > small.ShardMax+64<<10 {
				t.Errorf("%s holds %d bytes, ShardMax %d", x.Path, n, small.ShardMax)
			}
		}
	}
	if total > small.Cap {
		t.Errorf("shards hold %d bytes, cap %d", total, small.Cap)
	}
	got := readAll(t, all)
	if len(got) != stored+more+lossCount(got) {
		t.Fatalf("read %d records, stored %d plus losses", len(got), stored+more)
	}
}

func lossCount(rs []rawrecord.Record) int {
	n := 0
	for _, r := range rs {
		if r.Provider == LossProvider {
			n++
		}
	}
	return n
}

// At the cap new records are dropped, the stored ones stay, and the drops are counted in loss records
// whose seq continues the same gap-free sequence.
func TestTheCapDropsNewRecordsAndRecordsTheLoss(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	stored, sealed := fill(t, s, 200, 16<<10, noon)
	if stored == 200 {
		t.Fatal("nothing was dropped at the cap")
	}
	closed, err := s.Close(t.Context(), noon+1e9)
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, append(sealed, closed...))
	var dropped uint64
	seqs := map[uint64]bool{}
	for _, r := range got {
		if r.Provider != LossProvider {
			seqs[r.Seq] = true
		}
		if r.Provider == LossProvider {
			var l struct{ Dropped uint64 }
			if err := json.Unmarshal(r.Data, &l); err != nil {
				t.Fatal(err)
			}
			dropped += l.Dropped
		}
	}
	if int(dropped) != 200-stored {
		t.Fatalf("loss records count %d drops, %d were dropped", dropped, 200-stored)
	}
	for seq := uint64(1); seq <= uint64(stored); seq++ { //nolint:gosec // test counter
		if !seqs[seq] {
			t.Fatalf("stored seq %d missing among %d records", seq, stored)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == reserveName {
			info, _ := e.Info()
			if info.Size() != small.Headroom-int64(lossCount(got))*LossChunk {
				t.Errorf("reserve is %d bytes after %d loss records", info.Size(), lossCount(got))
			}
		}
	}
}

func TestAUsedUpReserveIsUnknown(t *testing.T) {
	s, err := Open(t.TempDir(), 1, Limits{Cap: 64 << 10, ShardMax: 256 << 10, Headroom: LossChunk})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; s.Health() == "" && i < 1000; i++ {
		if _, _, err := s.Append(t.Context(), "laurel", 1, noon+int64(i)*LossInterval, make([]byte, 16<<10)); err != nil && s.Health() == "" {
			t.Fatal(err)
		}
	}
	if s.Health() == "" {
		t.Fatal("the reserve ran out and the store did not say so")
	}
	if _, _, err := s.Append(t.Context(), "laurel", 1, noon+1e15, make([]byte, 16<<10)); err == nil {
		t.Fatal("a drop with the reserve used up was not an error")
	}
}

func TestOpenRefusesAnUnsealedShard(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir)
	fill(t, s, 3, 100, noon) // the current shard stays open: its -wal is in dir
	if _, err := Open(dir, 4, small); err == nil {
		t.Fatal("Open accepted a directory with an unsealed shard")
	}
}

// A record that fits after a run of drops is stored after the loss record that counts them.
func TestARunOfDropsIsRecordedBeforeTheNextStoredRecord(t *testing.T) {
	s := open(t, t.TempDir())
	_, sealed := fill(t, s, 70, 16<<10, noon)
	ok, more, err := s.Append(t.Context(), "laurel", 1, noon+1e8, []byte("x"))
	if err != nil || !ok {
		t.Fatalf("a small record under the cap: stored %v, %v", ok, err)
	}
	closed, err := s.Close(t.Context(), noon+2e8)
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, append(append(sealed, more...), closed...))
	var beforeSeq, small uint64
	for _, r := range got {
		if r.Provider == LossProvider {
			var l struct {
				BeforeSeq uint64 `json:"before_seq"`
			}
			if err := json.Unmarshal(r.Data, &l); err != nil {
				t.Fatal(err)
			}
			beforeSeq = max(beforeSeq, l.BeforeSeq)
		}
		if string(r.Data) == "x" {
			small = r.Seq
		}
	}
	if beforeSeq == 0 || small != beforeSeq {
		t.Fatalf("small record seq %d, loss records say the next stored seq is %d", small, beforeSeq)
	}
}
