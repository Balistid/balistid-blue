package store

import (
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

var small = Limits{Cap: 1 << 20, ShardMax: 128 << 10, Headroom: 4 * LossChunk}

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
	stored, _, err := s.Append(t.Context(), "laurel", 7, received, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return stored
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
	for _, lim := range []Limits{{Cap: 1 << 20, ShardMax: 1 << 20, Headroom: 1}, {Cap: 1 << 10, ShardMax: 1 << 20, Headroom: LossChunk},
		{Cap: 1 << 20, ShardMax: 100 << 10, Headroom: LossChunk}} { // a shard that could never admit a record
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
		_, got, err := s.Append(t.Context(), "laurel", uint64(i), noon+int64(i), make([]byte, 8<<10))
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, got...)
	}
	if len(sealed) == 0 {
		t.Fatal("no shard sealed at ShardMax")
	}
	onDay(s, 1)
	_, got, err := s.Append(t.Context(), "laurel", 99, noon+day, []byte("next day"))
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
	s := open(t, dir, Limits{Cap: 256 << 10, ShardMax: 128 << 10, Headroom: LossChunk})
	for i := 0; i < 200 && s.Health() == ""; i++ {
		_, _, _ = s.Append(t.Context(), "laurel", 1, noon+int64(i), []byte(strings.Repeat("x", 4<<10)))
		_, _ = s.Flush(t.Context()) // fails once the reserve is gone
	}
	if s.Health() == "" {
		t.Fatal("a used-up reserve is not UNKNOWN")
	}
	if _, _, err := s.Append(t.Context(), "laurel", 1, noon, []byte("late")); err == nil {
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

func TestOpenRecoversAShardACrashLeftOpen(t *testing.T) {
	s := open(t, t.TempDir(), small)
	for i := range 5 {
		add(t, s, noon, fmt.Sprint(i))
	}
	dir := crashed(t, s)
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
	dir := crashed(t, s)
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
	s := open(t, dir, Limits{Cap: 128 << 10, ShardMax: 128 << 10, Headroom: 4 * LossChunk})
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
	s := open(t, t.TempDir(), Limits{Cap: 256 << 10, ShardMax: 128 << 10, Headroom: 4 * LossChunk})
	add(t, s, noon, "a")
	if add(t, s, noon+1, strings.Repeat("x", 100<<10)) {
		t.Fatal("a record whose two copies pass the cap was stored")
	}
	onDay(s, 1)
	_, sealed, err := s.Append(t.Context(), "laurel", 1, noon+day, []byte("next day, small"))
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
	s := open(t, dir, Limits{Cap: 128 << 10, ShardMax: 128 << 10, Headroom: 4 * LossChunk})
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
	for i := range 20 { // twenty small loss records fit in one chunk of the reserve
		add(t, s, noon+int64(i), strings.Repeat("x", 4<<10))
		if _, err := s.Flush(t.Context()); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}
	st, err := os.Stat(filepath.Join(dir, reserveName))
	if err != nil || st.Size() < 2*LossChunk {
		t.Fatalf("reserve at %d bytes after 20 loss records, %v", st.Size(), err)
	}
}

func TestAReopenAtTheCapDoesNotPayForTheReserveTwice(t *testing.T) {
	dir := t.TempDir()
	lim := Limits{Cap: 128 << 10, ShardMax: 128 << 10, Headroom: 16 * LossChunk}
	s := open(t, dir, lim)
	for i := 0; add(t, s, noon+int64(i), strings.Repeat("x", 4<<10)); i++ {
	}
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
	s := open(t, dir, Limits{Cap: 128 << 10, ShardMax: 128 << 10, Headroom: 16 * LossChunk})
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

func TestStoredRecordsStayUnderTheCap(t *testing.T) {
	dir := t.TempDir()
	lim := Limits{Cap: 512 << 10, ShardMax: 128 << 10, Headroom: 4 * LossChunk}
	s := open(t, dir, lim)
	for i := range 300 {
		add(t, s, noon+int64(i), strings.Repeat("x", 3000+i*37%2000))
	}
	used, err := s.used()
	if err != nil || used > lim.Cap {
		t.Fatalf("records allocate %d bytes under a cap of %d, %v", used, lim.Cap, err)
	}
	closeStore(t, s)
}

func TestARecoveryRecordSurvivesASecondCrash(t *testing.T) {
	s := open(t, t.TempDir(), small)
	add(t, s, noon, "a")
	first := crashed(t, s)
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

func TestNoteHealthIsStoredByFlush(t *testing.T) {
	dir := t.TempDir()
	s := open(t, dir, small)
	add(t, s, noon, "a")
	s.NoteHealth([]byte(`{"schema_version":1,"sensor":"UNKNOWN"}`))
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
	err := s.room(func() error {
		if calls++; calls == 1 {
			return syscall.ENOSPC
		}
		return nil
	})
	st, serr := os.Stat(filepath.Join(dir, reserveName))
	if err != nil || calls != 2 || serr != nil || st.Size() != small.Headroom-LossChunk {
		t.Fatalf("room: %v after %d writes, reserve %d bytes (%v)", err, calls, st.Size(), serr)
	}
	if err := s.room(func() error { return syscall.ENOSPC }); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("a write that stays full must fail: %v", err)
	}
}

func TestFlushSealsTheShardOfAnEndedDayWhileDropping(t *testing.T) {
	s := open(t, t.TempDir(), Limits{Cap: 256 << 10, ShardMax: 128 << 10, Headroom: 16 * LossChunk})
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
	dir := crashed(t, s)
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
