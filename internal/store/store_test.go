package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

const noon = int64(1791460800000000000)

var small = Limits{Cap: shard.WALMaxBytes + 1<<20, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 4*LossChunk}

func open(t *testing.T, dir string, lim Limits) *Store {
	t.Helper()
	s, err := Open(t.Context(), dir, lim)
	if err != nil {
		t.Fatal(err)
	}
	onDay(s, 0)
	return s
}

func add(t *testing.T, s *Store, received int64, data string) bool {
	t.Helper()
	stored, _, err := s.Append(t.Context(), rawrecord.New(0, "laurel", 7, received, []byte(data)))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// atTheCap fills the store's sealed space up to its cap, as a long cap episode leaves it, so the
// store's own records must be paid for out of the reserve.
func atTheCap(s *Store) {
	s.sealedBytes = s.lim.Cap
}

// onDay sets the store's clock to noon of day d after the test's start; shards rotate by it.
func onDay(s *Store, d int) {
	s.now = func() time.Time { return time.Unix(0, noon+int64(d)*day) }
}

func closeStore(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// readAll reads every indexed shard of dir through a fresh Open and checks seq runs gap-free from 1.
func readAll(t *testing.T, dir string) []rawrecord.Record {
	t.Helper()
	s := open(t, dir, small)
	closeStore(t, s) // writes what Open left waiting, such as a recovery health record
	var got []rawrecord.Record
	for _, l := range s.Seals() {
		if err := shard.Read(t.Context(), filepath.Join(dir, l.Name), l.SHA256, func(r rawrecord.Record) error {
			if r.Seq != uint64(len(got))+1 {
				return fmt.Errorf("seq %d after %d records", r.Seq, len(got))
			}
			got = append(got, r)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return got
}

func copyDir(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(from, e.Name())) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), data, 0o600); err != nil { //nolint:gosec // test temp dir
			t.Fatal(err)
		}
	}
	return to
}

func TestOpenRefusesLimitsThatCannotHoldARecord(t *testing.T) {
	for _, lim := range []Limits{{Cap: 1 << 30, ShardMax: 1 << 20, Headroom: 1}, {Cap: 1 << 10, ShardMax: 1 << 20, Headroom: shard.WALMaxBytes + LossChunk},
		{Cap: shard.WALMaxBytes + 1<<20, ShardMax: 100 << 10, Headroom: shard.WALMaxBytes + LossChunk}, // a shard that could never admit a record
		{Cap: shard.WALMaxBytes + 1<<20, ShardMax: 128 << 10, Headroom: 16 * LossChunk}} {              // a reserve that cannot cover a checkpoint
		if _, err := Open(t.Context(), t.TempDir(), lim); err == nil {
			t.Fatalf("Open accepted %+v", lim)
		}
	}
}

func TestOpenAllocatesTheReserve(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	if s.Health() != "" {
		t.Fatal(s.Health())
	}
	if n, err := allocated(filepath.Join(dir, reserveName)); err != nil || n < small.Headroom {
		t.Fatalf("reserve holds %d bytes, %v", n, err)
	}
	if err := os.WriteFile(filepath.Join(dir, reserveName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if s := open(t, dir, small); s.Health() == "" {
		t.Fatal("an empty reserve is not UNKNOWN")
	}
}

func TestShardsSealAtShardMaxAndDayIntoTheIndex(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	var sealed []Seal
	for i := range 40 {
		_, got, err := s.Append(t.Context(), rawrecord.New(0, "laurel", uint64(i), noon+int64(i), make([]byte, 8<<10)))
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, got...)
	}
	if len(sealed) == 0 {
		t.Fatal("no shard sealed at ShardMax")
	}
	onDay(s, 1)
	_, got, err := s.Append(t.Context(), rawrecord.New(0, "laurel", 99, noon+day, []byte("next day")))
	if err != nil || len(got) != 1 {
		t.Fatalf("a new UTC day sealed %d shards, %v", len(got), err)
	}
	closeStore(t, s)
	records := readAll(t, dir)
	if len(records) != 41 || string(records[40].Data) != "next day" {
		t.Fatalf("read %d records back", len(records))
	}
	index, err := os.ReadFile(filepath.Join(dir, indexName)) //nolint:gosec // test temp dir
	if err != nil || !strings.HasPrefix(string(index), indexHeader) {
		t.Fatalf("index: %v", err)
	}
}

func TestReopenContinuesTheSeq(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	add(t, s, noon, "a")
	add(t, s, noon, "b")
	closeStore(t, s)
	s = open(t, dir, small)
	add(t, s, noon, "c")
	closeStore(t, s)
	if got := readAll(t, dir); len(got) != 3 || got[2].Seq != 3 {
		t.Fatalf("records %v", got)
	}
}

func TestTheCapDropsAndFlushCountsTheDropsWithoutAnotherAppend(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	drops := 0
	for i := range 400 {
		if !add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)) {
			drops++
		}
	}
	if drops == 0 {
		t.Fatal("nothing dropped at the cap")
	}
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	closeStore(t, s)
	counted := 0
	for _, r := range readAll(t, dir) {
		if r.Provider == LossProvider {
			var loss struct{ Dropped int }
			if err := json.Unmarshal(r.Data, &loss); err != nil {
				t.Fatal(err)
			}
			counted += loss.Dropped
		}
	}
	if counted != drops {
		t.Fatalf("loss records count %d drops, want %d", counted, drops)
	}
}

func TestAUsedUpReserveIsUnknownAndCloseStillSeals(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Limits{Cap: shard.WALMaxBytes + 256<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + LossChunk})
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	} // one drop waits for its loss record
	for i := 0; i < 200 && s.Health() == ""; i++ { // a full filesystem takes the reserve chunk by chunk
		_ = s.room(0, func() error { return syscall.ENOSPC })
	}
	if s.Health() == "" {
		t.Fatal("a used-up reserve is not UNKNOWN")
	}
	if _, _, err := s.Append(t.Context(), rawrecord.New(0, "laurel", 1, noon, []byte("late"))); err == nil {
		t.Fatal("an UNKNOWN store took a record")
	}
	if _, err := s.Close(t.Context()); err == nil || !strings.Contains(err.Error(), "used up") {
		t.Fatalf("Close of an UNKNOWN store = %v; want its reason, since waiting drops are lost", err)
	}
	if len(readAll(t, dir)) == 0 {
		t.Fatal("the stored records were not sealed")
	}
}

// crashed is dir as a crash leaves it while s is still open: files copied, nothing closed.
func crashed(t *testing.T, s *Store) string {
	t.Helper()
	return copyDir(t, s.dir)
}

// flushedThenCrashed is crashed right after a Flush, which made the stored records durable.
func flushedThenCrashed(t *testing.T, s *Store) string {
	t.Helper()
	if _, err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return crashed(t, s)
}

func TestOpenRecoversAShardACrashLeftOpen(t *testing.T) {
	s := open(t, t.TempDir(), small)
	for i := range 5 {
		add(t, s, noon, fmt.Sprint(i))
	}
	dir := flushedThenCrashed(t, s)
	r := open(t, dir, small)
	if len(r.Seals()) != 1 || r.Seals()[0].Last != 5 {
		t.Fatalf("seals %+v", r.Seals())
	}
	add(t, r, noon, "after")
	closeStore(t, r)
	got := readAll(t, dir)
	if len(got) != 7 || got[5].Provider != HealthProvider || string(got[6].Data) != "after" {
		t.Fatalf("want 5 records, a recovery health record, then the next: %+v", got)
	}
}

func TestOpenRecoversAShardSealedBeforeItsIndexLine(t *testing.T) {
	s := open(t, t.TempDir(), small)
	add(t, s, noon, "a")
	if _, err := s.cur.Seal(t.Context()); err != nil {
		t.Fatal(err)
	}
	dir := flushedThenCrashed(t, s)
	if got := readAll(t, dir); len(got) != 2 || string(got[0].Data) != "a" {
		t.Fatalf("records %+v", got)
	}
}

func TestOpenRecoversATornIndexLineAndRewritesTheIndex(t *testing.T) {
	src := t.TempDir()
	s := open(t, src, small)
	add(t, s, noon, "a")
	onDay(s, 1)
	add(t, s, noon+day, "b") // seals the first shard
	closeStore(t, s)
	index := filepath.Join(src, indexName)
	data, err := os.ReadFile(index) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, data[:len(data)-10], 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	if got := readAll(t, src); len(got) != 3 {
		t.Fatalf("records %+v", got)
	}
	if got := readAll(t, src); len(got) != 3 { // the index Open rewrote parses again
		t.Fatalf("records %+v", got)
	}
	data, err = os.ReadFile(index) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	// A torn line whose shard was never sealed.
	if err := os.WriteFile(index, append(data, "000000"...), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	s = open(t, src, small)
	onDay(s, 2)
	add(t, s, noon+2*day, "c")
	closeStore(t, s)
	if got := readAll(t, src); len(got) != 4 {
		t.Fatalf("records %+v", got)
	}
}

func TestOpenRemovesAShardWithoutRecords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000001.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := open(t, dir, small)
	if len(s.Seals()) != 0 {
		t.Fatal(s.Seals())
	}
	if _, err := os.Stat(filepath.Join(dir, "00000000000000000001.db")); !os.IsNotExist(err) {
		t.Fatalf("the empty shard is still there: %v", err)
	}
}

func TestOpenFailsOnWhatItCannotAccountFor(t *testing.T) {
	src := t.TempDir()
	s := open(t, src, small)
	add(t, s, noon, "a")
	onDay(s, 1)
	add(t, s, noon+day, "b")
	onDay(s, 2)
	add(t, s, noon+2*day, "c")
	closeStore(t, s)
	sealed, err := os.ReadFile(filepath.Join(src, indexName)) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(sealed), "\n")
	cases := map[string]func(dir string) error{
		"index header": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, indexName), []byte("balistid-seals 2\n"+strings.Join(lines[1:], "")), 0o600) //nolint:gosec // test temp dir
		},
		"index line": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, indexName), []byte(lines[0]+"x y z\n"+strings.Join(lines[2:], "")), 0o600) //nolint:gosec // test temp dir
		},
		"index seq gap": func(dir string) error {
			return errors.Join(os.Remove(filepath.Join(dir, "00000000000000000002.db")),
				os.WriteFile(filepath.Join(dir, indexName), []byte(lines[0]+lines[1]+lines[3]), 0o600)) //nolint:gosec // test temp dir
		},
		"index name not its first seq": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, indexName), []byte(strings.Replace(string(sealed), "00000000000000000001.db 1", "00000000000000000001.db 2", 1)), 0o600) //nolint:gosec // test temp dir
		},
		"index hash in upper case": func(dir string) error {
			f := strings.Fields(lines[1])
			return os.WriteFile(filepath.Join(dir, indexName), []byte(lines[0]+strings.Join(f[:3], " ")+" "+strings.ToUpper(f[3])+"\n"+strings.Join(lines[2:], "")), 0o600) //nolint:gosec // test temp dir
		},
		"index name other than its first seq": func(dir string) error {
			name := "00000000000000000005.db"
			return errors.Join(os.Rename(filepath.Join(dir, "00000000000000000001.db"), filepath.Join(dir, name)),
				os.WriteFile(filepath.Join(dir, indexName), []byte(strings.Replace(string(sealed), "00000000000000000001.db", name, 1)), 0o600)) //nolint:gosec // test temp dir
		},
		"index name pattern": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, indexName), []byte(strings.Replace(string(sealed), "00000000000000000001.db", "0000000000000000001.db", 1)), 0o600) //nolint:gosec // test temp dir
		},
		"foreign file": func(dir string) error { return os.WriteFile(filepath.Join(dir, "notes.txt"), nil, 0o600) },
		"orphan WAL": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "00000000000000000009.db-wal"), []byte("frames"), 0o600)
		},
		"WAL beside a sealed shard": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "00000000000000000001.db-wal"), nil, 0o600)
		},
		"indexed shard missing": func(dir string) error { return os.Remove(filepath.Join(dir, "00000000000000000001.db")) },
		"shard out of seq": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "00000000000000000009.db"), []byte("x"), 0o600)
		},
		"name over int64": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "99999999999999999999.db"), nil, 0o600)
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			dir := copyDir(t, src)
			if err := damage(dir); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(t.Context(), dir, small); err == nil {
				t.Fatal("Open accepted it")
			}
		})
	}
}

func TestFlushIsTheOnlyWriterOfWaitingDropsWhileTheCollectorIsIdle(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Limits{Cap: shard.WALMaxBytes + 128<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 4*LossChunk})
	i := 0
	for ; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	if s.dropped != 1 {
		t.Fatalf("dropped %d", s.dropped)
	}
	onDay(s, 3) // the loss record carries the store's time
	if _, err := s.Flush(t.Context()); err != nil || s.dropped != 0 {
		t.Fatalf("Flush: %v, %d drops still waiting", err, s.dropped)
	}
	closeStore(t, s)
	got := readAll(t, dir)
	if last := got[len(got)-1]; last.Provider != LossProvider || last.Received != noon+3*day {
		t.Fatalf("last record %+v", last)
	}
}

func TestPendingDropsGoIntoTheShardBeforeItIsSealed(t *testing.T) {
	s := open(t, t.TempDir(), Limits{Cap: shard.WALMaxBytes + 256<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 4*LossChunk})
	add(t, s, noon, "a")
	if add(t, s, noon+1, strings.Repeat("x", 100<<10)) {
		t.Fatal("a record whose two copies pass the cap was stored")
	}
	onDay(s, 1)
	_, sealed, err := s.Append(t.Context(), rawrecord.New(0, "laurel", 1, noon+day, []byte("next day, small")))
	if err != nil || len(sealed) != 1 {
		t.Fatalf("Append sealed %d shards, %v", len(sealed), err)
	}
	var last rawrecord.Record
	if err := shard.Read(t.Context(), filepath.Join(s.dir, sealed[0].Name), sealed[0].SHA256, func(r rawrecord.Record) error {
		last = r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if last.Provider != LossProvider {
		t.Fatalf("the sealed shard ends with %s, not the loss record of its drops", last.Provider)
	}
}

func TestRecordsPastTheCapSpendTheReserveByTheChunk(t *testing.T) {
	dir := t.TempDir()
	lim := Limits{Cap: shard.WALMaxBytes + 128<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 64*LossChunk}
	s := open(t, dir, lim)
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	atTheCap(s)
	for i := range 20 {
		add(t, s, noon+int64(i), strings.Repeat("x", 4<<10))
		if _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}
	st, err := os.Stat(filepath.Join(dir, reserveName))
	if err != nil {
		t.Fatal(err)
	}
	used, err := s.used()
	if err != nil {
		t.Fatal(err)
	}
	// The reserve gives back what the loss records allocate past the cap, a chunk at a time, no more.
	if spent, past := lim.Headroom-st.Size(), used-lim.Cap; spent < past || spent > past+shard.WALMaxBytes+2*LossChunk {
		t.Fatalf("reserve spent %d bytes for %d allocated past the cap", spent, past)
	}
}

func TestAReopenAtTheCapDoesNotPayForTheReserveTwice(t *testing.T) {
	dir := t.TempDir()
	lim := Limits{Cap: shard.WALMaxBytes + 128<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 16*LossChunk}
	s := open(t, dir, lim)
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	atTheCap(s)
	reserve := func() int64 {
		st, err := os.Stat(filepath.Join(dir, reserveName))
		if err != nil {
			t.Fatal(err)
		}
		return st.Size()
	}
	for range 3 {
		closeStore(t, s)
		before := reserve()
		s = open(t, dir, lim)
		atTheCap(s)
		for i := range 5 { // five small loss records fit in what the reserve already gave back
			add(t, s, noon+int64(i), strings.Repeat("x", 4<<10))
			if _, err := s.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if after := reserve(); before-after > LossChunk {
			t.Fatalf("a reopen spent %d bytes of the reserve on five loss records", before-after)
		}
	}
	closeStore(t, s)
}

func TestLossRecordsAtTheCapKeepToTheirShardWhateverTheClockSays(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Limits{Cap: shard.WALMaxBytes + 128<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 16*LossChunk})
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	s.now = func() time.Time { return time.Unix(0, noon+5*day) }
	for i := range 30 {
		add(t, s, noon+int64(i), strings.Repeat("x", 4<<10))
		if _, err := s.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	closeStore(t, s)
	if n := len(readAll(t, dir)); n == 0 {
		t.Fatal("nothing stored")
	}
	shards, err := filepath.Glob(filepath.Join(dir, "*.db"))
	if err != nil || len(shards) > 3 {
		t.Fatalf("%d shards for one day of records and its loss records, %v", len(shards), err)
	}
}

func TestStoredRecordsStayUnderTheCapThroughCheckpoints(t *testing.T) {
	// A checkpoint can add a whole WAL to the main file at once; the cap must hold through every one.
	dir := t.TempDir()
	lim := Limits{Cap: shard.WALMaxBytes + 4<<20, ShardMax: 4 << 20, Headroom: shard.WALMaxBytes + 4*LossChunk}
	s := open(t, dir, lim)
	drops := 0
	for i := range 3000 {
		if !add(t, s, noon+int64(i), strings.Repeat("x", 2000+i*37%3000)) {
			drops++
		}
		used, err := s.used()
		if err != nil || used > lim.Cap {
			t.Fatalf("after record %d the shards allocate %d bytes under a cap of %d, %v", i, used, lim.Cap, err)
		}
	}
	if drops == 0 {
		t.Fatal("the cap was never reached")
	}
	closeStore(t, s)
}

func TestARecoveryRecordSurvivesASecondCrash(t *testing.T) {
	s := open(t, t.TempDir(), small)
	add(t, s, noon, "a")
	first := flushedThenCrashed(t, s)
	r := open(t, first, small) // recovers, stores the health record, rewrites the index
	second := crashed(t, r)    // and crashes before its first Flush
	got := readAll(t, second)
	found := false
	for _, rec := range got {
		found = found || rec.Provider == HealthProvider && strings.Contains(string(rec.Data), `"recovered"`)
	}
	if !found {
		t.Fatalf("the trace of the first crash is gone: %+v", got)
	}
}

// A health record waiting when a record arrives is stored first and takes the next seq; the record
// takes the one after it.
func TestAWaitingHealthRecordGoesFirst(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	add(t, s, noon, "a")
	if err := s.NoteHealth([]byte(`{"schema_version":1,"sensor":"UNKNOWN"}`)); err != nil {
		t.Fatal(err)
	}
	add(t, s, noon, "b")
	closeStore(t, s)
	got := readAll(t, dir)
	if len(got) != 3 || got[1].Provider != HealthProvider || string(got[2].Data) != "b" {
		t.Fatalf("records %+v", got)
	}
}

// Records taken before the store became UNKNOWN, or before Close got a cancelled context, are still
// committed, so a crash after that does not lose them.
func TestTakenRecordsAreCommittedWhenTheStoreFails(t *testing.T) {
	for name, fail := range map[string]func(t *testing.T, s *Store){
		"unknown": func(t *testing.T, s *Store) {
			t.Helper()
			s.unknown = "the reserve is used up"
			if _, err := s.Flush(t.Context()); err == nil {
				t.Fatal("Flush of an UNKNOWN store succeeded")
			}
		},
		"close with a cancelled context": func(t *testing.T, s *Store) {
			t.Helper()
			cancelled, cancel := context.WithCancel(t.Context())
			cancel()
			_, _ = s.Close(cancelled)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := open(t, t.TempDir(), small)
			add(t, s, noon, "a")
			add(t, s, noon, "b")
			fail(t, s)
			got, n := readAll(t, crashed(t, s)), 0
			for _, r := range got {
				if r.Provider == "laurel" {
					n++
				}
			}
			if n != 2 {
				t.Fatalf("%d of 2 taken records after the crash: %+v", n, got)
			}
		})
	}
}

func TestNoteHealthIsStoredByFlush(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	add(t, s, noon, "a")
	if err := s.NoteHealth([]byte(`{"schema_version":1,"sensor":"UNKNOWN"}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{make([]byte, maxHealthBytes+1), []byte("not json"), []byte(`{"sensor":"OK"}`)} {
		if err := s.NoteHealth(bad); err == nil {
			t.Fatalf("health record %.20q was queued", bad)
		}
	}
	closeStore(t, s)
	if got := readAll(t, dir); len(got) != 2 || got[1].Provider != HealthProvider {
		t.Fatalf("records %+v", got)
	}
}

func TestOpenRefusesNamesAndTypesThatDoNotBelong(t *testing.T) {
	cases := map[string]func(dir string) error{
		"two sidecar suffixes": func(dir string) error {
			return errors.Join(os.WriteFile(filepath.Join(dir, "00000000000000000001.db"), nil, 0o600),
				os.WriteFile(filepath.Join(dir, "00000000000000000001.db-shm-wal"), nil, 0o600))
		},
		"index as a symlink": func(dir string) error {
			return os.Symlink(filepath.Join(dir, reserveName), filepath.Join(dir, indexName))
		},
		"index temp as a directory": func(dir string) error { return os.Mkdir(filepath.Join(dir, indexName+".tmp"), 0o700) },
		"shard as a directory":      func(dir string) error { return os.Mkdir(filepath.Join(dir, "00000000000000000001.db"), 0o700) },
	}
	for name, add := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := add(dir); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(t.Context(), dir, small); err == nil {
				t.Fatal("Open accepted it")
			}
		})
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), dir, small); err != nil {
		t.Fatalf("lost+found of a filesystem root: %v", err)
	}
}

func TestAFullFilesystemFreesAChunkOfTheReserveOnce(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	calls := 0
	err := s.room(0, func() error {
		if calls++; calls == 1 {
			return syscall.ENOSPC
		}
		return nil
	})
	st, serr := os.Stat(filepath.Join(dir, reserveName))
	if err != nil || calls != 2 || serr != nil || st.Size() != small.Headroom-LossChunk {
		t.Fatalf("room: %v after %d writes, reserve %d bytes (%v)", err, calls, st.Size(), serr)
	}
	if err := s.room(0, func() error { return syscall.ENOSPC }); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("a write that stays full must fail: %v", err)
	}
}

func TestFlushSealsTheShardOfAnEndedDayWhileDropping(t *testing.T) {
	s := open(t, t.TempDir(), Limits{Cap: shard.WALMaxBytes + 256<<10, ShardMax: 128 << 10, Headroom: shard.WALMaxBytes + 16*LossChunk})
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	onDay(s, 1)
	sealed, err := s.Flush(t.Context())
	if err != nil || len(sealed) != 1 {
		t.Fatalf("Flush on a new day sealed %d shards, %v; the dropping shard must not stay open", len(sealed), err)
	}
}

func TestAnUnknownOpenLeavesTheRecoveryForTheNextOpen(t *testing.T) {
	s := open(t, t.TempDir(), small)
	add(t, s, noon, "a")
	dir := flushedThenCrashed(t, s)
	reserve := filepath.Join(dir, reserveName)
	if err := os.Truncate(reserve, 0); err != nil {
		t.Fatal(err)
	}
	r := open(t, dir, small)
	if r.Health() == "" || len(r.Seals()) != 0 {
		t.Fatalf("health %q, seals %+v; an UNKNOWN Open must not make a recovery final", r.Health(), r.Seals())
	}
	if err := os.Remove(reserve); err != nil {
		t.Fatal(err)
	}
	got := readAll(t, dir)
	if len(got) != 2 || got[1].Provider != HealthProvider {
		t.Fatalf("records %+v", got)
	}
}

func TestOpenRefusesADirectoryOthersCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(t.Context(), dir, small); err == nil {
			t.Fatalf("Open accepted a directory of mode %o", mode)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), link, small); err == nil {
		t.Fatal("Open followed a symlink to its directory")
	}
}

func TestOwnRecordsPastTheCapStayWithinCapAndHeadroom(t *testing.T) {
	// Loss records past the cap trigger checkpoints too; with the reserve they replace, everything the
	// store holds must stay within Cap + Headroom. One large shard keeps its WAL, as in production.
	dir := t.TempDir()
	lim := Limits{Cap: shard.WALMaxBytes + 8<<20, ShardMax: 8 << 20, Headroom: shard.WALMaxBytes + 1024*LossChunk}
	s := open(t, dir, lim)
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	for i := range 60000 {
		add(t, s, noon+int64(i), "dropped")
		if _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
		if i%100 != 0 {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		held := int64(0)
		for _, e := range entries {
			n, err := allocated(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			held += n
		}
		if held > lim.Cap+lim.Headroom {
			t.Fatalf("after %d loss records the store holds %d bytes, over Cap + Headroom %d", i+1, held, lim.Cap+lim.Headroom)
		}
	}
	closeStore(t, s)
}

func TestOneRecoveryRecordCoversEveryRecoveredShard(t *testing.T) {
	s := open(t, t.TempDir(), small)
	for d := range 4 { // four shards: three sealed without index lines below, one left open
		onDay(s, d)
		add(t, s, noon+int64(d)*day, "a")
	}
	dir := flushedThenCrashed(t, s)
	if err := os.Remove(filepath.Join(dir, indexName)); err != nil {
		t.Fatal(err)
	}
	notes := 0
	for _, r := range readAll(t, dir) {
		if r.Provider == HealthProvider {
			notes++
			if !strings.Contains(string(r.Data), `"shards":4`) {
				t.Fatalf("recovery record %s", r.Data)
			}
		}
	}
	if notes != 1 {
		t.Fatalf("%d recovery records for one Open", notes)
	}
}

// A record the collector built from a streamed line keeps the length and hash it carries; the store
// assigns its own seq.
func TestAppendKeepsCallerOrigLenAndSHA(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, Limits{Cap: shard.WALMaxBytes + 32<<20, ShardMax: 16 << 20, Headroom: small.Headroom})
	data := make([]byte, rawrecord.MaxBytes+5)
	for i := range data {
		data[i] = byte(i * 3)
	}
	half := rawrecord.MaxBytes / 2
	r, err := rawrecord.FromParts(999, "laurel", 42, noon, data[:half], data[len(data)-half:], uint64(len(data)), sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	if stored, _, err := s.Append(t.Context(), r); err != nil || !stored {
		t.Fatalf("Append = %v, %v", stored, err)
	}
	closeStore(t, s)
	var got []rawrecord.Record
	for _, l := range s.Seals() {
		if err := shard.Read(t.Context(), filepath.Join(dir, l.Name), l.SHA256, func(r rawrecord.Record) error {
			got = append(got, r)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	want := rawrecord.New(1, "laurel", 42, noon, data)
	if len(got) != 1 || !bytes.Equal(got[0].Encode(), want.Encode()) {
		t.Fatalf("stored %d records, want the record New makes of the data under seq 1", len(got))
	}
}

func TestAppendRefusesUnlistedProvider(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	for _, p := range []string{LossProvider, HealthProvider, "Laurel", "", "auditd"} {
		if stored, _, err := s.Append(t.Context(), rawrecord.New(0, p, 1, noon, []byte("x"))); !errors.Is(err, ErrRefused) || stored {
			t.Fatalf("provider %q: Append = %v, %v", p, stored, err)
		}
	}
	if !add(t, s, noon, "after the refusals") || s.Health() != "" {
		t.Fatalf("store unusable after refusals: %q", s.Health())
	}
	closeStore(t, s)
	if got := readAll(t, dir); len(got) != 1 || string(got[0].Data) != "after the refusals" {
		t.Fatalf("stored %d records", len(got))
	}
}

func TestAppendRefusesInconsistentRecord(t *testing.T) {
	big := make([]byte, rawrecord.MaxBytes+1)
	for name, mutate := range map[string]func(*rawrecord.Record){
		"data shorter than its length": func(r *rawrecord.Record) { r.Data = r.Data[:1] },
		"length longer than its data":  func(r *rawrecord.Record) { r.OrigLen++ },
		"truncated, data not MaxBytes": func(r *rawrecord.Record) {
			*r = rawrecord.New(0, "laurel", 1, noon, big)
			r.Data = r.Data[:rawrecord.MaxBytes-1]
		},
		"whole, data not its hash": func(r *rawrecord.Record) { r.Data[0] ^= 1 },
		"provider seq over int64":  func(r *rawrecord.Record) { r.ProviderSeq = 1 << 63 },
		"length over int64": func(r *rawrecord.Record) {
			*r = rawrecord.New(0, "laurel", 1, noon, big)
			r.OrigLen = 1 << 63
		},
	} {
		s := open(t, t.TempDir(), small)
		r := rawrecord.New(0, "laurel", 1, noon, []byte("ab"))
		mutate(&r)
		if stored, _, err := s.Append(t.Context(), r); !errors.Is(err, ErrRefused) || stored {
			t.Fatalf("%s: Append = %v, %v", name, stored, err)
		}
		if !add(t, s, noon, "fine") || s.Health() != "" {
			t.Fatalf("%s: store unusable after the refusal", name)
		}
		closeStore(t, s)
	}
}

// sealedThree leaves dir with three sealed shards in the index, as a collector that ran three days does.
func sealedThree(t *testing.T, dir string) []Seal {
	t.Helper()
	s := open(t, dir, small)
	for d := range 3 {
		onDay(s, d)
		add(t, s, noon+int64(d)*day, fmt.Sprint("day ", d))
	}
	closeStore(t, s)
	return s.Seals()
}

func TestReadSealsMatchesTheStore(t *testing.T) {
	dir := t.TempDir()
	want := sealedThree(t, dir)
	got, torn, err := ReadSeals(t.Context(), dir)
	if err != nil || torn || fmt.Sprint(got) != fmt.Sprint(want) || len(got) != 3 {
		t.Fatalf("ReadSeals = %v, %v, %v; the store indexed %v", got, torn, err, want)
	}
	if got, torn, err := ReadSeals(t.Context(), t.TempDir()); err != nil || torn || len(got) != 0 {
		t.Fatalf("no index: %v, %v, %v", got, torn, err)
	}
	for _, p := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, indexName)} {
		if got, _, err := ReadSeals(t.Context(), p); err == nil {
			t.Fatalf("%s: ReadSeals = %v, want an error", p, got)
		}
	}
}

func TestReadSealsSkipsTornLastLine(t *testing.T) {
	dir := t.TempDir()
	want := sealedThree(t, dir)
	index := filepath.Join(dir, indexName)
	data, err := os.ReadFile(index) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, data[:len(data)-10], 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	if got, torn, err := ReadSeals(t.Context(), dir); err != nil || !torn || fmt.Sprint(got) != fmt.Sprint(want[:2]) {
		t.Fatalf("ReadSeals = %v, %v, %v; want the first two seals and torn", got, torn, err)
	}
}

func TestReadSealsRefusesMalformedLine(t *testing.T) {
	dir := t.TempDir()
	sealedThree(t, dir)
	index := filepath.Join(dir, indexName)
	data, err := os.ReadFile(index) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	for name, body := range map[string]string{
		"header":  "balistid-seals 2\n" + strings.Join(lines[1:], ""),
		"line":    lines[0] + "x y z\n" + strings.Join(lines[2:], ""),
		"seq gap": lines[0] + lines[1] + lines[3],
	} {
		if err := os.WriteFile(index, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _, err := ReadSeals(t.Context(), dir); err == nil {
			t.Fatalf("%s: ReadSeals = %v, want an error", name, got)
		}
	}
}

// The guest reads a stopped collector's directory; nothing in it may change, even a torn index.
func TestReadSealsWritesNothing(t *testing.T) {
	dir := t.TempDir()
	sealedThree(t, dir)
	index := filepath.Join(dir, indexName)
	data, err := os.ReadFile(index) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, append(data, "000000"...), 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	listing := func() string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&b, e.Name(), info.Size(), info.Mode(), info.ModTime().UnixNano())
		}
		return b.String()
	}
	before := listing()
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // test temp dir
	if _, torn, err := ReadSeals(t.Context(), dir); err != nil || !torn {
		t.Fatalf("ReadSeals on a read-only directory: torn %v, %v", torn, err)
	}
	if after := listing(); after != before {
		t.Fatalf("ReadSeals changed the directory:\n%s\nwas\n%s", after, before)
	}
}

func TestReadSealsHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := ReadSeals(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadSeals after cancel: %v", err)
	}
}
