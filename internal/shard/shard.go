// Package shard stores raw records in one SQLite database per shard and seals it (ADR 0005, point 3):
// the collector appends, Seal makes the file final and returns its hash, and Read gives back the
// records of a file with that hash, each checked against its leaf. A shard counts as sealed only
// once its hash is recorded (the seals index, ADR 0013); the file's mode or journal state alone
// proves nothing.
package shard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/rawrecord"

	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go (ADR 0003)
)

// SchemaVersion of the tables Create makes; Read refuses any other.
const SchemaVersion = 1

// Writer appends records with gap-free sequence numbers to one shard until Seal.
type Writer struct {
	db      *sql.DB
	path    string
	next    uint64
	started bool
}

func open(path, query string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path, RawQuery: query}).String())
	if err != nil {
		return nil, fmt.Errorf("open shard: %w", err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// Create makes a new shard at the absolute path, which must not exist.
func Create(ctx context.Context, path string) (*Writer, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("shard path %q is not absolute", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // the collector's own directory
	if err != nil {
		return nil, fmt.Errorf("create shard: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("create shard: %w", err)
	}
	db, err := open(path, "_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	for _, s := range []string{
		`CREATE TABLE meta (schema_version INTEGER NOT NULL, label TEXT NOT NULL) STRICT`,
		`CREATE TABLE records (seq INTEGER PRIMARY KEY, provider TEXT NOT NULL, provider_seq INTEGER NOT NULL,
			received INTEGER NOT NULL, data BLOB NOT NULL, orig_len INTEGER NOT NULL, orig_sha256 BLOB NOT NULL,
			leaf BLOB NOT NULL) STRICT`,
	} {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return nil, errors.Join(fmt.Errorf("create shard tables: %w", err), db.Close())
		}
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO meta VALUES (?, ?)", SchemaVersion, rawrecord.Label); err != nil {
		return nil, errors.Join(fmt.Errorf("create shard meta: %w", err), db.Close())
	}
	return &Writer{db: db, path: path}, nil
}

// Append stores r, whose Seq must follow the previous record's. Each record is its own transaction.
func (w *Writer) Append(ctx context.Context, r rawrecord.Record) error {
	if w.db == nil {
		return errors.New("shard is sealed")
	}
	if w.started && r.Seq != w.next {
		return fmt.Errorf("record seq %d, want %d", r.Seq, w.next)
	}
	if r.Seq > math.MaxInt64 || r.ProviderSeq > math.MaxInt64 || r.OrigLen > math.MaxInt64 || len(r.Data) > rawrecord.MaxBytes {
		return fmt.Errorf("record seq %d: a number over SQLite's int64 or data over %d bytes", r.Seq, rawrecord.MaxBytes)
	}
	if uint64(len(r.Data)) > r.OrigLen || (!r.Truncated() && sha256.Sum256(r.Data) != r.OrigSHA256) {
		return fmt.Errorf("record seq %d: data does not match its original length and hash", r.Seq)
	}
	leaf := r.Leaf()
	_, err := w.db.ExecContext(ctx, "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		int64(r.Seq), r.Provider, int64(r.ProviderSeq), r.Received, append([]byte{}, r.Data...),
		int64(r.OrigLen), r.OrigSHA256[:], leaf[:])
	if err != nil {
		return fmt.Errorf("append record %d: %w", r.Seq, err)
	}
	w.started, w.next = true, r.Seq+1
	return nil
}

// Seal leaves WAL mode (which checkpoints), closes the database, fsyncs the file Create made and its
// directory, makes it group-readable only and returns its SHA-256. The writer is unusable afterwards,
// whatever the outcome; a shard whose seal failed has no hash to record and is never read.
func (w *Writer) Seal(ctx context.Context) ([32]byte, error) {
	if w.db == nil {
		return [32]byte{}, errors.New("shard is sealed")
	}
	db := w.db
	w.db = nil
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil || mode != "delete" {
		return [32]byte{}, errors.Join(fmt.Errorf("seal: journal mode %q: %w", mode, err), db.Close())
	}
	if err := db.Close(); err != nil {
		return [32]byte{}, fmt.Errorf("seal: close: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only descriptor
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, fmt.Errorf("seal: hash: %w", err)
	}
	if err := errors.Join(f.Chmod(0o440), f.Sync()); err != nil { // group-readable for balistid-normalize (ADR 0007)
		return [32]byte{}, fmt.Errorf("seal: %w", err)
	}
	dir, err := os.Open(filepath.Dir(w.path))
	if err != nil {
		return [32]byte{}, fmt.Errorf("seal: directory: %w", err)
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		return [32]byte{}, fmt.Errorf("seal: directory: %w", err)
	}
	return [32]byte(h.Sum(nil)), nil
}

// sealedFile fails unless path is a regular file, not a symlink, with the SQLite header of a database
// out of WAL mode (bytes 18 and 19 are 1) and the SHA-256 want.
func sealedFile(path string, want [32]byte) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the caller names the shard; the hash check decides
	if err != nil {
		return fmt.Errorf("read shard: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("read shard: not a regular file (%w)", err)
	}
	header := make([]byte, 100)
	if _, err := io.ReadFull(f, header); err != nil {
		return fmt.Errorf("read shard header: %w", err)
	}
	if !bytes.HasPrefix(header, []byte("SQLite format 3\x00")) || header[18] != 1 || header[19] != 1 {
		return errors.New("read shard: not a sealed SQLite database (WAL mode or no header)")
	}
	h := sha256.New()
	h.Write(header)
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read shard: hash: %w", err)
	}
	if [32]byte(h.Sum(nil)) != want {
		return errors.New("read shard: the file's SHA-256 is not the sealed one")
	}
	return nil
}

// Read calls fn with every record of the shard at path, whose SHA-256 must be want (what Seal
// returned), in seq order. It refuses another schema version or label, a gap in seq, a stored leaf
// that differs from the record's, and an untruncated record whose data does not match its hash.
func Read(ctx context.Context, path string, want [32]byte, fn func(rawrecord.Record) error) error {
	if err := sealedFile(path, want); err != nil {
		return err
	}
	db, err := open(path, "mode=ro&immutable=1")
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // read-only
	var version, metaRows int
	var label string
	if err := db.QueryRowContext(ctx, "SELECT schema_version, label, (SELECT count(*) FROM meta) FROM meta").
		Scan(&version, &label, &metaRows); err != nil {
		return fmt.Errorf("read shard meta: %w", err)
	}
	if version != SchemaVersion || label != rawrecord.Label || metaRows != 1 {
		return fmt.Errorf("shard is schema %d, label %q, %d meta rows; want %d, %q, 1", version, label, metaRows, SchemaVersion, rawrecord.Label)
	}
	rows, err := db.QueryContext(ctx, "SELECT seq, provider, provider_seq, received, data, orig_len, orig_sha256, leaf FROM records ORDER BY seq")
	if err != nil {
		return fmt.Errorf("read shard records: %w", err)
	}
	defer rows.Close() //nolint:errcheck // read-only; rows.Err reports a failed read
	var prev int64
	for first := true; rows.Next(); first = false {
		var seq, pseq, origLen int64
		var r rawrecord.Record
		var sum, leaf []byte
		if err := rows.Scan(&seq, &r.Provider, &pseq, &r.Received, &r.Data, &origLen, &sum, &leaf); err != nil {
			return fmt.Errorf("read shard record: %w", err)
		}
		if seq < 0 || pseq < 0 || origLen < 0 || len(sum) != 32 || len(leaf) != 32 || (!first && seq != prev+1) {
			return fmt.Errorf("shard record %d after %d: malformed or out of sequence", seq, prev)
		}
		prev = seq
		r.Seq, r.ProviderSeq, r.OrigLen, r.OrigSHA256 = uint64(seq), uint64(pseq), uint64(origLen), [32]byte(sum)
		if r.Leaf() != [32]byte(leaf) || (!r.Truncated() && sha256.Sum256(r.Data) != r.OrigSHA256) {
			return fmt.Errorf("shard record %d: stored leaf or data hash does not match", seq)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read shard records: %w", err)
	}
	return nil
}
