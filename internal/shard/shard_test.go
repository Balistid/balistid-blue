package shard

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
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
