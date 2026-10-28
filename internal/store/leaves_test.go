package store

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

// threeDays stores records over three days, so two shards are sealed and one is current, with a health
// record and a cap loss record among them, and flushes.
func threeDays(t *testing.T, dir string) *Store {
	t.Helper()
	s := open(t, dir, small)
	for d := range 3 {
		onDay(s, d)
		for i := range 4 {
			add(t, s, noon+int64(d)*day, fmt.Sprintf("day %d record %d", d, i))
		}
		if err := s.NoteHealth([]byte(`{"schema_version":1,"kind":"stats"}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	s.dropped, s.firstDrop, s.lastDrop = 2, noon, noon
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return s
}

func leavesOf(t *testing.T, s *Store, after uint64, max int) ([]shard.Leaf, []Seal) {
	t.Helper()
	got, seals, err := s.Leaves(t.Context(), after, max, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	return got, seals
}

func TestLeavesAreTheStoredRecordsAcrossShards(t *testing.T) {
	dir := t.TempDir()
	s := threeDays(t, dir)
	got, seals := leavesOf(t, s, 0, 1000)
	if uint64(len(got)) != s.Committed() || len(seals) != 2 || fmt.Sprint(seals) != fmt.Sprint(s.Seals()) {
		t.Fatalf("%d leaves of %d committed, seals %v of %v", len(got), s.Committed(), seals, s.Seals())
	}
	closeStore(t, s)
	records := readAll(t, dir)
	if len(records) != len(got) {
		t.Fatalf("%d records, %d leaves", len(records), len(got))
	}
	own := 0
	for i, r := range records {
		l := got[i]
		if l.Seq != r.Seq || l.Hash != r.Leaf() || l.Provider != r.Provider || l.Truncated {
			t.Fatalf("leaf %+v for record %d %s", l, r.Seq, r.Provider)
		}
		if sensor := r.Provider == SensorProvider; sensor != (l.Data == nil) || (!sensor && !bytes.Equal(l.Data, r.Data)) {
			t.Fatalf("record %d of %s: data %q", r.Seq, r.Provider, l.Data)
		}
		if r.Provider != SensorProvider {
			own++
		}
	}
	if own != 4 { // three health records and the loss record
		t.Fatalf("%d own records", own)
	}
}

// Pages of any size give the same leaves, each seal once and in the page holding its last record.
func TestLeavesPageThroughTheStore(t *testing.T) {
	s := threeDays(t, t.TempDir())
	all, _ := leavesOf(t, s, 0, 1000)
	for _, size := range []int{1, 2, 3, 7} {
		var got []shard.Leaf
		var seals []Seal
		for after := uint64(0); after < s.Committed(); {
			page, sealed := leavesOf(t, s, after, size)
			if len(page) == 0 || len(page) > size {
				t.Fatalf("page of %d after %d: %d leaves", size, after, len(page))
			}
			for _, l := range sealed {
				if l.Last < page[0].Seq || l.Last > page[len(page)-1].Seq {
					t.Fatalf("seal %v outside its page %d-%d", l, page[0].Seq, page[len(page)-1].Seq)
				}
			}
			got, seals, after = append(got, page...), append(seals, sealed...), page[len(page)-1].Seq
		}
		if fmt.Sprint(got) != fmt.Sprint(all) || fmt.Sprint(seals) != fmt.Sprint(s.Seals()) {
			t.Fatalf("pages of %d: %d leaves, seals %v", size, len(got), seals)
		}
	}
}

func TestLeavesStopAtCommitted(t *testing.T) {
	s := open(t, t.TempDir(), small)
	add(t, s, noon, "one")
	if got, seals := leavesOf(t, s, 0, 10); got != nil || seals != nil {
		t.Fatalf("before any commit: %v %v", got, seals)
	}
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	add(t, s, noon, "two")
	if got, _ := leavesOf(t, s, 0, 10); len(got) != 1 || got[0].Seq != 1 {
		t.Fatalf("leaves %v, want seq 1 only", got)
	}
	if got, _ := leavesOf(t, s, 1, 10); got != nil {
		t.Fatalf("after the last committed seq: %v", got)
	}
}

// An open transaction holds the one connection: Leaves reads through it, at once, and only committed seqs.
func TestLeavesReadThroughAnOpenTransaction(t *testing.T) {
	s := open(t, t.TempDir(), small)
	add(t, s, noon, "one")
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	add(t, s, noon, "two")
	if s.cur.Pending() == 0 {
		t.Fatal("no transaction open")
	}
	done := make(chan []shard.Leaf, 1)
	go func() {
		got, _, err := s.Leaves(t.Context(), 0, 10, 1<<40)
		if err != nil {
			t.Error(err)
		}
		done <- got
	}()
	select {
	case got := <-done:
		if len(got) != 1 || got[0].Seq != 1 {
			t.Fatalf("leaves %+v, want committed seq 1 only", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Leaves waited for the open transaction")
	}
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatalf("the transaction did not survive the read: %v", err)
	}
	if got, _ := leavesOf(t, s, 1, 10); len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("after the commit: %+v", got)
	}
}

func TestLeavesOfAFailedStoreFail(t *testing.T) {
	s := threeDays(t, t.TempDir())
	s.unknown = "seal index: no space"
	if got, _, err := s.Leaves(t.Context(), 0, 10, 1<<40); err == nil {
		t.Fatalf("UNKNOWN store gave %d leaves", len(got))
	}
}

func TestLeavesRefuseASeqInNoShard(t *testing.T) {
	s := threeDays(t, t.TempDir())
	s.seals = s.seals[1:] // the first shard's index line, as if lost
	if got, _, err := s.Leaves(t.Context(), 0, 10, 1<<40); err == nil {
		t.Fatalf("seq 1 without its shard gave %d leaves", len(got))
	}
}

func TestLeavesFlagATruncatedRecord(t *testing.T) {
	s := open(t, t.TempDir(), Limits{Cap: 64 << 20, ShardMax: 32 << 20, Headroom: shard.WALMaxBytes + LossChunk})
	big := make([]byte, rawrecord.MaxBytes+1)
	if stored, _, err := s.Append(t.Context(), rawrecord.New(0, SensorProvider, 1, noon, big)); err != nil || !stored {
		t.Fatalf("append: %v %v", stored, err)
	}
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ := leavesOf(t, s, 0, 10); len(got) != 1 || !got[0].Truncated || got[0].Data != nil {
		t.Fatalf("leaves %+v, want one truncated sensor record without its data", got)
	}
}

// BenchmarkLeaves reads one collector tick of committed records (FlushEvery at sustained_rate, 500) as
// the ledger stream does, for small records and for the largest, whose leaf column follows 2 MiB of data.
// Example: TMPDIR=/var/tmp go test -run '^$' -bench Leaves ./internal/store/
func BenchmarkLeaves(b *testing.B) {
	for _, c := range []struct{ size, n int }{{1 << 10, 500}, {rawrecord.MaxBytes, 9}} {
		b.Run(fmt.Sprintf("%dKiBx%d", c.size>>10, c.n), func(b *testing.B) {
			s, err := Open(b.Context(), b.TempDir(), Limits{Cap: 64 << 30, ShardMax: 2 << 30, Headroom: shard.WALMaxBytes + LossChunk})
			if err != nil {
				b.Fatal(err)
			}
			onDay(s, 0)
			data := make([]byte, c.size)
			_, _ = rand.Read(data)
			for i := range c.n {
				if stored, _, err := s.Append(b.Context(), rawrecord.New(0, SensorProvider, uint64(i)+1, 0, data)); err != nil || !stored {
					b.Fatalf("append: %v %v", stored, err)
				}
			}
			if _, err := s.Flush(b.Context()); err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				if got, _, err := s.Leaves(b.Context(), 0, c.n, 1<<40); err != nil || len(got) != c.n {
					b.Fatalf("leaves: %d, %v", len(got), err)
				}
			}
		})
	}
}

// Reading a leaf walks past its record's data, so a read stops once that data reaches the budget, after at
// least one record, and names a seal only if it reached the seal's last record.
func TestLeavesStopAtTheByteBudget(t *testing.T) {
	s := threeDays(t, t.TempDir())
	all, allSeals := leavesOf(t, s, 0, 1000)
	var sizes int64
	for _, l := range all[:2] {
		sizes += l.Size
	}
	got, seals, err := s.Leaves(t.Context(), 0, 1000, sizes)
	if err != nil || len(got) != 2 || len(seals) != 0 {
		t.Fatalf("budget of two records: %d leaves, seals %v, %v", len(got), seals, err)
	}
	if got, _, err := s.Leaves(t.Context(), 0, 1000, 1); err != nil || len(got) != 1 {
		t.Fatalf("a budget below one record: %d leaves, %v", len(got), err)
	}
	var upToSeal int64
	for _, l := range all {
		if upToSeal += l.Size; l.Seq == allSeals[0].Last {
			break
		}
	}
	if _, seals, err := s.Leaves(t.Context(), 0, 1000, upToSeal); err != nil || len(seals) != 1 {
		t.Fatalf("a budget through the first shard: seals %v, %v", seals, err)
	}
}

func TestLeavesRefuseANoBudget(t *testing.T) {
	s := threeDays(t, t.TempDir())
	for _, budget := range []int64{0, -1} {
		if got, _, err := s.Leaves(t.Context(), 0, 10, budget); err == nil {
			t.Fatalf("budget %d: %d leaves, no error", budget, len(got))
		}
	}
}
