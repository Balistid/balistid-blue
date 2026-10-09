package shard

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

const noon = int64(1791460800000000000)

func record(seq uint64, data string) rawrecord.Record {
	return rawrecord.New(seq, "laurel", seq*10, noon+int64(seq), []byte(data)) //nolint:gosec // test seqs are small
}

// sealed writes records into a new shard, seals it and returns its path and hash.
func sealed(t *testing.T, records ...rawrecord.Record) (string, [32]byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shard.db")
	w, err := Create(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := w.Append(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := w.Seal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return path, sum
}

func readAll(t *testing.T, path string, sum [32]byte) ([]rawrecord.Record, error) {
	var got []rawrecord.Record
	err := Read(t.Context(), path, sum, func(r rawrecord.Record) error {
		got = append(got, r)
		return nil
	})
	return got, err
}

func TestAppendSealRead(t *testing.T) {
	big := bytes.Repeat([]byte{7}, rawrecord.MaxBytes+5)
	want := []rawrecord.Record{record(41, "ab"), record(42, ""), rawrecord.New(43, "laurel", 1, noon, big)}
	path, sum := sealed(t, want...)

	data, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil || sha256.Sum256(data) != sum {
		t.Fatalf("Seal returned %x, the file hashes otherwise (%v)", sum, err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left after Seal: %v", suffix, err)
		}
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o440 {
		t.Errorf("sealed shard mode %v, %v", st.Mode(), err)
	}
	got, err := readAll(t, path, sum)
	if err != nil || len(got) != len(want) {
		t.Fatalf("Read: %d records, %v", len(got), err)
	}
	for i := range want {
		if got[i].Leaf() != want[i].Leaf() || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Fatalf("record %d differs after Read", i)
		}
	}
}

func TestAppendRefusesGapsAndRepeats(t *testing.T) {
	w, err := Create(t.Context(), filepath.Join(t.TempDir(), "shard.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(t.Context(), record(5, "a")); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{5, 7, 4} {
		if err := w.Append(t.Context(), record(seq, "b")); err == nil {
			t.Errorf("Append accepted seq %d after 5", seq)
		}
	}
	if err := w.Append(t.Context(), record(6, "c")); err != nil {
		t.Fatal(err)
	}
}

func TestAppendRefusesNumbersOverInt64(t *testing.T) {
	for name, r := range map[string]rawrecord.Record{
		"seq":          rawrecord.New(1<<63, "laurel", 1, noon, nil),
		"provider seq": rawrecord.New(1, "laurel", 1<<63, noon, nil),
		"orig len":     {Seq: 1, Provider: "laurel", OrigLen: 1 << 63},
	} {
		w, err := Create(t.Context(), filepath.Join(t.TempDir(), "shard.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Append(t.Context(), r); err == nil {
			t.Errorf("Append accepted a %s over int64", name)
		}
	}
}

// A reader holding the WAL keeps the checkpoint from finishing; the seal must fail, not publish.
func TestSealFailsWhileAReaderHoldsTheWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shard.db")
	w, err := Create(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(t.Context(), record(1, "a")); err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck // test cleanup
	tx, err := reader.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // test cleanup
	var n int
	if err := tx.QueryRowContext(t.Context(), "SELECT count(*) FROM records").Scan(&n); err != nil || n != 1 {
		t.Fatalf("reader sees %d records: %v", n, err)
	}
	if err := w.Append(t.Context(), record(2, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Seal(t.Context()); err == nil {
		t.Fatal("Seal succeeded while a reader held the WAL")
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() == 0o440 {
		t.Fatalf("a shard whose seal failed was made final: %v, %v", st.Mode(), err)
	}
}

func TestSealedWriterRefusesWork(t *testing.T) {
	w, err := Create(t.Context(), filepath.Join(t.TempDir(), "shard.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Seal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(t.Context(), record(1, "a")); err == nil {
		t.Error("Append after Seal")
	}
	if _, err := w.Seal(t.Context()); err == nil {
		t.Error("second Seal")
	}
}

func TestCreateRefusesAnExistingOrRelativePath(t *testing.T) {
	path, _ := sealed(t, record(1, "a"))
	if _, err := Create(t.Context(), path); err == nil {
		t.Error("Create overwrote a sealed shard")
	}
	if _, err := Create(t.Context(), "shard.db"); err == nil {
		t.Error("Create accepted a relative path")
	}
	if _, err := os.Lstat("shard.db"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Create made a file for a relative path: %v", err)
	}
	writable := filepath.Join(t.TempDir(), "writable.db")
	if err := os.WriteFile(writable, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(t.Context(), writable); err == nil {
		t.Error("Create took over an existing file")
	}
}

// tampered copies a sealed shard, runs stmt on the copy and returns it with its own SHA-256, so
// the row checks are tested apart from the hash check.
func tampered(t *testing.T, stmt string) (string, [32]byte) {
	t.Helper()
	path, _ := sealed(t, record(1, "ab"), record(2, "cd"), record(3, "ef"))
	data, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	cp := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(cp, data, 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), stmt); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(cp) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return cp, sha256.Sum256(data)
}

func TestReadRefusesATamperedShard(t *testing.T) {
	for name, stmt := range map[string]string{
		"data changed":     "UPDATE records SET data = x'6162' WHERE seq = 2",
		"data and hash":    "UPDATE records SET data = x'6162', orig_sha256 = (SELECT orig_sha256 FROM records WHERE seq = 1) WHERE seq = 2",
		"record removed":   "DELETE FROM records WHERE seq = 2",
		"provider changed": "UPDATE records SET provider = 'other' WHERE seq = 3",
		"other schema":     "UPDATE meta SET schema_version = 2",
		"other label":      "UPDATE meta SET label = 'balistid/raw/v2'",
		"two meta rows":    "INSERT INTO meta VALUES (1, 'balistid/raw/v1')",
		"short leaf":       "UPDATE records SET leaf = x'00' WHERE seq = 1",
		"short hash":       "UPDATE records SET orig_sha256 = x'00' WHERE seq = 1",
		"negative pseq":    "UPDATE records SET provider_seq = -1 WHERE seq = 1",
	} {
		t.Run(name, func(t *testing.T) {
			p, sum := tampered(t, stmt)
			if got, err := readAll(t, p, sum); err == nil {
				t.Fatalf("Read accepted it and returned %d records", len(got))
			}
		})
	}
}

// Data replaced and the leaf recomputed to match: only the data hash of an untruncated record shows it.
func TestReadRefusesDataThatDoesNotMatchItsHash(t *testing.T) {
	forged := record(2, "cd")
	forged.Data = []byte("xx")
	leaf := forged.Leaf()
	stmt := fmt.Sprintf("UPDATE records SET data = x'7878', leaf = x'%x' WHERE seq = 2", leaf)
	p, sum := tampered(t, stmt)
	if got, err := readAll(t, p, sum); err == nil {
		t.Fatalf("Read accepted it and returned %d records", len(got))
	}
}

func TestReadStopsWhenTheCallbackFails(t *testing.T) {
	path, sum := sealed(t, record(1, "a"), record(2, "b"))
	stop := errors.New("stop")
	calls := 0
	err := Read(t.Context(), path, sum, func(rawrecord.Record) error {
		calls++
		return stop
	})
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("Read = %v after %d calls", err, calls)
	}
}

func TestPathWithURICharacters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a?b#c%d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := Create(t.Context(), filepath.Join(dir, "shard.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(t.Context(), record(1, "a")); err != nil {
		t.Fatal(err)
	}
	sum, err := w.Seal(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "shard.db") {
		t.Fatalf("files in the shard directory: %v, %v", entries, err)
	}
	if got, err := readAll(t, filepath.Join(dir, "shard.db"), sum); err != nil || len(got) != 1 {
		t.Fatalf("Read: %d records, %v", len(got), err)
	}
}

func TestReadRefusesAnotherHashAnUnsealedShardAndNonFiles(t *testing.T) {
	a, _ := sealed(t, record(1, "a"), record(2, "b"))
	_, sumB := sealed(t, record(1, "a"))
	if got, err := readAll(t, a, sumB); err == nil {
		t.Errorf("Read accepted a sealed shard with another shard's hash and returned %d records", len(got))
	}
	_, sumA := sealed(t, record(1, "a"), record(2, "b"))
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(t, link, sumA); err == nil {
		t.Error("Read followed a symlink")
	}
	fifo := filepath.Join(t.TempDir(), "fifo.db")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(t, fifo, sumA); err == nil {
		t.Error("Read accepted a FIFO")
	}
	// A shard still in WAL mode whose main file already holds the tables and some records.
	open := filepath.Join(t.TempDir(), "open.db")
	w, err := Create(t.Context(), open)
	if err != nil {
		t.Fatal(err)
	}
	for seq := uint64(1); seq <= 60; seq++ {
		if err := w.Append(t.Context(), record(seq, "x")); err != nil {
			t.Fatal(err)
		}
		if seq == 3 {
			if _, err := w.db.ExecContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
				t.Fatal(err)
			}
		}
	}
	data, err := os.ReadFile(open) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if got, err := readAll(t, open, sha256.Sum256(data)); err == nil {
		t.Errorf("Read accepted a shard still in WAL mode and returned %d of 60 records", len(got))
	}
}

// Negative numbers with a leaf recomputed for their unsigned reading: only the sign checks see them.
func TestReadRefusesNegativeNumbers(t *testing.T) {
	for name, c := range map[string]struct {
		col string
		set func(*rawrecord.Record)
	}{
		"provider seq": {"provider_seq", func(r *rawrecord.Record) { r.ProviderSeq = math.MaxUint64 }},
		"orig len":     {"orig_len", func(r *rawrecord.Record) { r.OrigLen = math.MaxUint64 }},
	} {
		t.Run(name, func(t *testing.T) {
			forged := record(2, "cd")
			c.set(&forged)
			leaf := forged.Leaf()
			p, sum := tampered(t, fmt.Sprintf("UPDATE records SET %s = -1, leaf = x'%x' WHERE seq = 2", c.col, leaf))
			if got, err := readAll(t, p, sum); err == nil {
				t.Fatalf("Read accepted it and returned %d records", len(got))
			}
		})
	}
}

func TestAppendRefusesDataThatContradictsItsLengthOrHash(t *testing.T) {
	for name, r := range map[string]rawrecord.Record{
		"longer than the original": {Seq: 1, Provider: "laurel", Data: []byte("abc"), OrigLen: 2},
		"short but not truncated":  {Seq: 1, Provider: "laurel", Data: []byte("ab"), OrigLen: 2},
	} {
		w, err := Create(t.Context(), filepath.Join(t.TempDir(), "shard.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Append(t.Context(), r); err == nil {
			t.Errorf("Append stored a record whose data is %s", name)
		}
	}
}

func TestAppendRefusesDataOverMaxBytes(t *testing.T) {
	w, err := Create(t.Context(), filepath.Join(t.TempDir(), "shard.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := record(1, "a")
	r.Data = make([]byte, rawrecord.MaxBytes+1)
	if err := w.Append(t.Context(), r); err == nil {
		t.Error("Append stored data over MaxBytes")
	}
}

// crashed returns a copy of a shard's files as a crash after the last Append leaves them: the
// records committed to the WAL, the main file not yet checkpointed, no seal.
func crashed(t *testing.T, records ...rawrecord.Record) string {
	t.Helper()
	return crashedAfter(t, nil, records...)
}

// crashedAfter is crashed with stmts run through the writer's own connection last, so their effect
// sits in the WAL like the records' does.
func crashedAfter(t *testing.T, stmts []string, records ...rawrecord.Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shard.db")
	w, err := Create(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.db.Close() }) //nolint:errcheck,gosec // test cleanup
	for _, r := range records {
		if err := w.Append(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range stmts {
		if _, err := w.db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	cp := filepath.Join(t.TempDir(), "shard.db")
	for _, suffix := range []string{"", "-wal"} {
		if _, err := os.Stat(path + suffix); errors.Is(err, fs.ErrNotExist) && suffix != "" {
			continue
		}
		data, err := os.ReadFile(path + suffix) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cp+suffix, data, 0o600); err != nil { //nolint:gosec // test temp dir
			t.Fatal(err)
		}
	}
	return cp
}

func exec(t *testing.T, path, stmt string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), stmt); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func journalMode(t *testing.T, path string) byte {
	t.Helper()
	header := make([]byte, 100)
	f, err := os.Open(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // test
	if _, err := f.Read(header); err != nil {
		t.Fatal(err)
	}
	return header[18]
}

func TestRecoverSealsRecordsStillInTheWAL(t *testing.T) {
	path := crashed(t, record(5, "ab"), record(6, "cd"), record(7, "ef"))
	if st, err := os.Stat(path + "-wal"); err != nil || st.Size() == 0 {
		t.Fatalf("the crash copy should hold its records in the WAL: %v", err)
	}
	got, err := Recover(t.Context(), path)
	if err != nil || got.Empty || got.First != 5 || got.Last != 7 {
		t.Fatalf("Recover = %+v, %v; want records 5..7", got, err)
	}
	read, err := readAll(t, path, got.SHA256)
	if err != nil || len(read) != 3 || string(read[2].Data) != "ef" {
		t.Fatalf("the recovered shard reads %d records, %v", len(read), err)
	}
	if _, err := os.Stat(path + "-wal"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a sealed shard keeps no WAL: %v", err)
	}
}

func TestRecoverRefusesAnEmptyFileBesideAWAL(t *testing.T) {
	path := crashed(t, record(1, "ab"))
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path + "-wal") //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(t.Context(), path); err == nil || !strings.Contains(err.Error(), "non-empty WAL") {
		t.Fatalf("Recover = %v; want a refusal before opening", err)
	}
	if after, err := os.ReadFile(path + "-wal"); err != nil || !bytes.Equal(after, before) { //nolint:gosec // test temp dir
		t.Fatalf("the WAL beside an empty file must survive untouched: %v", err)
	}
}

func TestRecoverFindsAShardWithoutRecordsEmpty(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"zero bytes, no WAL": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "shard.db")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"zero bytes, empty WAL": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "shard.db")
			for _, p := range []string{path, path + "-wal"} {
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return path
		},
		"tables, no records": func(t *testing.T) string { return crashed(t) },
		"zero bytes, WAL header only": func(t *testing.T) string {
			wal, err := os.ReadFile(crashed(t, record(1, "ab")) + "-wal")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "shard.db")
			if err := errors.Join(os.WriteFile(path, nil, 0o600), os.WriteFile(path+"-wal", wal[:32], 0o600)); err != nil { //nolint:gosec // test temp dir
				t.Fatal(err)
			}
			return path
		},
		"meta only": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "shard.db")
			exec(t, path, "CREATE TABLE meta (schema_version INTEGER NOT NULL, label TEXT NOT NULL) STRICT")
			return path
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := Recover(t.Context(), build(t)); err != nil || !got.Empty {
				t.Fatalf("Recover = %+v, %v; want Empty", got, err)
			}
		})
	}
}

func TestRecoverLeavesABadShardUnsealed(t *testing.T) {
	for name, stmt := range map[string]string{
		"leaf":     "UPDATE records SET leaf = zeroblob(32) WHERE seq = 2",
		"seq gap":  "DELETE FROM records WHERE seq = 2",
		"data":     "UPDATE records SET data = x'0000' WHERE seq = 2",
		"meta":     "UPDATE meta SET schema_version = 2",
		"no meta":  "DELETE FROM meta",
		"bad leaf": "UPDATE records SET leaf = x'00' WHERE seq = 3",
	} {
		t.Run(name, func(t *testing.T) {
			path := crashedAfter(t, []string{stmt}, record(1, "ab"), record(2, "cd"), record(3, "ef"))
			if st, err := os.Stat(path + "-wal"); err != nil || st.Size() == 0 {
				t.Fatalf("the damage should sit in the WAL: %v", err)
			}
			if _, err := Recover(t.Context(), path); err == nil {
				t.Fatal("Recover sealed a shard that fails Read's checks")
			}
			if mode := journalMode(t, path); mode != 2 {
				t.Fatalf("header byte 18 = %d; a refused shard must stay in WAL mode, unsealed", mode)
			}
		})
	}
}

func TestRecoverTouchesOnlyARegularFileAtAnAbsolutePath(t *testing.T) {
	path := crashed(t, record(1, "ab"))
	dir := t.TempDir()
	link, fifo := filepath.Join(dir, "link.db"), filepath.Join(dir, "fifo.db")
	if err := errors.Join(os.Symlink(path, link), syscall.Mkfifo(fifo, 0o600)); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(path))
	for p, want := range map[string]string{"shard.db": "not absolute", link: "not a regular file",
		fifo: "not a regular file", filepath.Join(dir, "missing.db"): "no such file"} {
		if got, err := Recover(t.Context(), p); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Recover(%q) = %+v, %v; want %q", p, got, err, want)
		}
	}
	if mode := journalMode(t, path); mode != 2 {
		t.Fatalf("header byte 18 = %d; the shard behind the refused paths must stay unsealed", mode)
	}
}

// flip changes one byte of the file at path, at off counted from its start (negative: from its end).
func flip(t *testing.T, path string, off int) []byte {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if off < 0 {
		off += len(data)
	}
	data[off] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // test temp dir
		t.Fatal(err)
	}
	return data
}

func walFrame(t *testing.T, path string, n int) int {
	t.Helper()
	data, err := os.ReadFile(path + "-wal") //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	size := 24 + int(binary.BigEndian.Uint32(data[8:]))
	if frames := (len(data) - 32) / size; n < 0 {
		n += frames
	}
	return 32 + n*size + 24 + 100 // a byte of the frame's page
}

func TestRecoverRefusesADamagedWALBeforeOpeningIt(t *testing.T) {
	for name, off := range map[string]func(t *testing.T, path string) int{
		"header salt":  func(*testing.T, string) int { return 17 },
		"middle frame": func(t *testing.T, path string) int { return walFrame(t, path, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			path := crashed(t, record(1, "ab"), record(2, "cd"), record(3, "ef"), record(4, "gh"))
			wal := flip(t, path+"-wal", off(t, path))
			main, err := os.ReadFile(path) //nolint:gosec // test temp dir
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Recover(t.Context(), path); err == nil || !strings.Contains(err.Error(), "WAL") {
				t.Fatalf("Recover = %v; want a refusal of the WAL", err)
			}
			for file, want := range map[string][]byte{path: main, path + "-wal": wal} {
				if got, err := os.ReadFile(file); err != nil || !bytes.Equal(got, want) { //nolint:gosec // test temp dir
					t.Fatalf("%s changed: %v", file, err)
				}
			}
		})
	}
}

func TestRecoverTakesDamageInTheLastTransactionForATornWrite(t *testing.T) {
	// SQLite cannot tell damage to the last committed transaction from a torn uncommitted one; the
	// transaction is lost either way, whether its commit frame or a page inside it is hit.
	path := crashed(t, record(1, "ab"), record(2, "cd"), record(3, "ef"), record(4, "gh"))
	flip(t, path+"-wal", walFrame(t, path, -1))
	if got, err := Recover(t.Context(), path); err != nil || got.First != 1 || got.Last != 3 {
		t.Fatalf("last frame damaged: Recover = %+v, %v; want records 1..3", got, err)
	}
	path = crashed(t, record(1, "ab"), record(2, "cd"), record(3, strings.Repeat("x", 200000)))
	data := flip(t, path+"-wal", walFrame(t, path, -3))
	for i := walFrame(t, path, -3) - 124; i < walFrame(t, path, -2)-124; i++ {
		data[i] = 0 // the whole frame, as a power loss leaves an unwritten one
	}
	if err := os.WriteFile(path+"-wal", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Recover(t.Context(), path); err != nil || got.Last != 2 {
		t.Fatalf("zeroed frame inside the last transaction: Recover = %+v, %v; want records 1..2", got, err)
	}
}

func TestRecoverRefusesAWALWhoseSaltWasHitBeforeTheLastCommit(t *testing.T) {
	path := crashed(t, record(1, "ab"), record(2, "cd"), record(3, "ef"), record(4, "gh"))
	flip(t, path+"-wal", walFrame(t, path, -2)-100-24+9) // a salt byte of the second-to-last frame
	if _, err := Recover(t.Context(), path); err == nil || !strings.Contains(err.Error(), "committed transaction after it") {
		t.Fatalf("Recover = %v; want a refusal", err)
	}
}

func TestRecoverFinishesASealStoppedAfterTheJournalSwitch(t *testing.T) {
	path := crashedAfter(t, []string{"PRAGMA journal_mode=DELETE"}, record(1, "ab"), record(2, "cd"))
	got, err := Recover(t.Context(), path)
	if err != nil || got.Last != 2 {
		t.Fatalf("Recover = %+v, %v", got, err)
	}
	if read, err := readAll(t, path, got.SHA256); err != nil || len(read) != 2 {
		t.Fatalf("read %d records, %v", len(read), err)
	}
}

func TestRecoverRollsBackAHotJournal(t *testing.T) {
	// A crash inside a transaction on a shard out of WAL mode leaves a hot rollback journal.
	path, _ := sealed(t, record(1, "ab"), record(2, "cd"))
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=cache_size(2)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck // test
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck // test
	for i := uint64(3); i < 200; i++ {
		r := record(i, strings.Repeat("x", 3000))
		leaf := r.Leaf()
		if _, err := tx.ExecContext(t.Context(), "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?)", int64(i), r.Provider,
			int64(r.ProviderSeq), r.Received, r.Data, int64(r.OrigLen), r.OrigSHA256[:], leaf[:]); err != nil { //nolint:gosec // test seqs are small
			t.Fatal(err)
		}
	}
	cp := filepath.Join(t.TempDir(), "shard.db")
	for _, suffix := range []string{"", "-journal"} {
		data, err := os.ReadFile(path + suffix) //nolint:gosec // test temp dir
		if err != nil || len(data) == 0 {
			t.Fatalf("%s: %v", suffix, err)
		}
		if err := os.WriteFile(cp+suffix, data, 0o600); err != nil { //nolint:gosec // test temp dir
			t.Fatal(err)
		}
	}
	got, err := Recover(t.Context(), cp)
	if err != nil || got.First != 1 || got.Last != 2 {
		t.Fatalf("Recover = %+v, %v; want only the two committed records", got, err)
	}
}

func TestRecoverSkipsFramesOfAnEarlierWALGeneration(t *testing.T) {
	// After a checkpoint the WAL restarts at its start with new salts; the old frames behind are stale.
	path := crashedAfter(t, []string{"PRAGMA wal_checkpoint(RESTART)", "PRAGMA user_version = 7"},
		record(1, "ab"), record(2, "cd"), record(3, "ef"), record(4, "gh"))
	got, err := Recover(t.Context(), path)
	if err != nil || got.First != 1 || got.Last != 4 {
		t.Fatalf("Recover = %+v, %v; want records 1..4", got, err)
	}
}
