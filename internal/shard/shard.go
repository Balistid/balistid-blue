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
	"encoding/binary"
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

const (
	pageSize        = 4096
	checkpointPages = 512 // SQLite checkpoints the WAL into the main file past this many pages
	// WALMaxBytes bounds a shard's WAL, and so what one checkpoint can add to its main file: the
	// autocheckpoint plus one transaction of the largest record, each page with its 24-byte frame
	// header, plus 1 MiB for the b-tree and overflow pages around it. The store's cap reserves it.
	WALMaxBytes = (checkpointPages*pageSize+rawrecord.MaxBytes)/pageSize*(pageSize+24) + 1<<20
)

// Writer appends records with gap-free sequence numbers to one shard until Seal.
type Writer struct {
	db      *sql.DB
	path    string
	next    uint64
	started bool
	tx      *sql.Tx // the open transaction, nil between commits
	pending int64   // the most page bytes the records in tx can take
	broken  error   // a failed write: what the file holds is for Recover to establish
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
	if err := errors.Join(f.Sync(), f.Close(), syncDir(path)); err != nil {
		return nil, fmt.Errorf("create shard: %w", err)
	}
	db, err := open(path, fmt.Sprintf("_pragma=page_size(%d)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"+
		"&_pragma=busy_timeout(5000)&_pragma=wal_autocheckpoint(%d)", pageSize, checkpointPages))
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

// Append adds r, whose Seq must follow the previous record's, to the open transaction; it is durable
// only after Commit or Seal. A transaction holds one record, or several that take at most
// rawrecord.MaxBytes of pages, so WALMaxBytes holds. After a failed write the Writer refuses everything, Seal included.
func (w *Writer) Append(ctx context.Context, r rawrecord.Record) error {
	if w.db == nil {
		return errors.New("shard is sealed")
	}
	if w.broken != nil {
		return w.broken
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
	// A row takes at most its bytes plus two pages: a leaf page it may have alone and the unused
	// part of its last overflow page. Counting encoded bytes alone lets small rows pass the budget.
	size := int64(r.EncodedLen()) + 2*pageSize
	if w.pending > 0 && w.pending+size > rawrecord.MaxBytes {
		if err := w.Commit(ctx); err != nil {
			return err
		}
	}
	if w.tx == nil {
		// Not bound to ctx: database/sql would roll a cancelled transaction back unseen.
		tx, err := w.db.BeginTx(context.WithoutCancel(ctx), nil)
		if err != nil {
			return w.fail(fmt.Errorf("append record %d: begin: %w", r.Seq, err))
		}
		w.tx = tx
	}
	leaf := r.Leaf()
	_, err := w.tx.ExecContext(ctx, "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		int64(r.Seq), r.Provider, int64(r.ProviderSeq), r.Received, append([]byte{}, r.Data...),
		int64(r.OrigLen), r.OrigSHA256[:], leaf[:])
	if err != nil {
		return w.fail(fmt.Errorf("append record %d: %w", r.Seq, err))
	}
	w.started, w.next, w.pending = true, r.Seq+1, w.pending+size
	return nil
}

// Commit makes the appended records durable; without any it does nothing.
func (w *Writer) Commit(ctx context.Context) error {
	if w.broken != nil {
		return w.broken
	}
	if w.tx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return w.fail(fmt.Errorf("commit: %w", err))
	}
	tx := w.tx
	w.tx, w.pending = nil, 0
	if err := tx.Commit(); err != nil {
		return w.fail(fmt.Errorf("commit: %w", err))
	}
	return nil
}

// Pending is the most page bytes the records appended since the last commit can take.
func (w *Writer) Pending() int64 { return w.pending }

// fail rolls back the open transaction and breaks the Writer: after a failed write it cannot tell
// which records the file holds, so it seals nothing and leaves the shard to Recover.
func (w *Writer) fail(err error) error {
	if w.tx != nil {
		err = errors.Join(err, w.tx.Rollback())
		w.tx, w.pending = nil, 0
	}
	w.broken = fmt.Errorf("shard: an earlier write failed; recover the shard: %w", err)
	return err
}

// Seal commits the open transaction, leaves WAL mode (which checkpoints), closes the database, fsyncs the file Create made and its
// directory, makes it group-readable only and returns its SHA-256. The writer is unusable afterwards,
// whatever the outcome; a shard whose seal failed has no hash to record and is never read.
func (w *Writer) Seal(ctx context.Context) ([32]byte, error) {
	if w.db == nil {
		return [32]byte{}, errors.New("shard is sealed")
	}
	err := w.Commit(ctx)
	db := w.db
	w.db = nil
	if err != nil {
		return [32]byte{}, errors.Join(err, db.Close())
	}
	return seal(ctx, db, w.path)
}

// seal takes db, open on path, out of WAL mode, closes it and makes the file final (see Seal).
func seal(ctx context.Context, db *sql.DB, path string) ([32]byte, error) {
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode); err != nil || mode != "delete" {
		return [32]byte{}, errors.Join(fmt.Errorf("seal: journal mode %q: %w", mode, err), db.Close())
	}
	if err := db.Close(); err != nil {
		return [32]byte{}, fmt.Errorf("seal: close: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the shard Create or Recover opened
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
	if err := syncDir(path); err != nil {
		return [32]byte{}, fmt.Errorf("seal: %w", err)
	}
	return [32]byte(h.Sum(nil)), nil
}

func syncDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	return nil
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
	return records(ctx, db, fn)
}

// records checks the meta row and calls fn with every record of db in seq order, as Read describes.
func records(ctx context.Context, db *sql.DB, fn func(rawrecord.Record) error) error {
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

// Recovered is what Recover found in a shard that was never sealed.
type Recovered struct {
	// Empty: the shard holds no records (a crash in Create or before the first Append). It is not
	// evidence; the caller removes it with its -wal and -shm files.
	Empty bool
	// First and Last are the seq range of a recovered shard, SHA256 its hash as Seal returns it.
	First, Last uint64
	SHA256      [32]byte
}

// Recover seals a shard a crash left unsealed (ADR 0013, point 5). Before any open it refuses a damaged
// WAL (see walIntact) and a zero-byte file beside a WAL with frames, which SQLite would delete. Then
// the shard is opened read-write, so SQLite applies its WAL; one without a records table or rows is
// Empty, and any other is checked as Read checks a sealed one, then sealed. A shard that fails a
// check after the open is left unsealed, with its WAL checkpointed into it.
func Recover(ctx context.Context, path string) (Recovered, error) {
	if !filepath.IsAbs(path) {
		return Recovered{}, fmt.Errorf("shard path %q is not absolute", path)
	}
	st, err := os.Lstat(path)
	if err != nil {
		return Recovered{}, fmt.Errorf("recover shard: %w", err)
	}
	if !st.Mode().IsRegular() {
		return Recovered{}, fmt.Errorf("recover shard: %s is not a regular file", path)
	}
	wal, err := walIntact(path + "-wal")
	if err != nil {
		return Recovered{}, fmt.Errorf("recover shard: %w", err)
	}
	if st.Size() == 0 && wal {
		return Recovered{}, errors.New("recover shard: an empty file beside a non-empty WAL")
	}
	db, err := open(path, "_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return Recovered{}, err
	}
	var tables, rows int
	err = db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'records'").Scan(&tables)
	if err == nil && tables == 1 {
		err = db.QueryRowContext(ctx, "SELECT count(*) FROM records").Scan(&rows)
	}
	if err != nil {
		return Recovered{}, errors.Join(fmt.Errorf("recover shard: %w", err), db.Close())
	}
	if rows == 0 {
		if err := db.Close(); err != nil {
			return Recovered{}, fmt.Errorf("recover shard: close: %w", err)
		}
		return Recovered{Empty: true}, nil
	}
	var r Recovered
	seen := false
	err = records(ctx, db, func(rec rawrecord.Record) error {
		if !seen {
			r.First, seen = rec.Seq, true
		}
		r.Last = rec.Seq
		return nil
	})
	if err != nil {
		return Recovered{}, errors.Join(fmt.Errorf("recover shard: %w", err), db.Close())
	}
	if r.SHA256, err = seal(ctx, db, path); err != nil {
		return Recovered{}, fmt.Errorf("recover shard: %w", err)
	}
	return r, nil
}

// walIntact reports whether the WAL at path holds frames, and fails when SQLite would silently drop a
// committed transaction from it. SQLite reads frames until the first whose salt differs from the
// header's or whose checksum fails (sqlite.org/fileformat2.html, section 4). A transaction is written
// only after the one before it is synced, so a crash can damage only the last one: damage followed by
// a second commit frame (at or beyond where reading stops) is refused, and so is a bad header with
// frames behind it. Damage inside the last transaction looks like a torn write and is accepted, and
// that transaction's seq numbers are issued again; a zeroed frame header can hide the one before it
// too (ADR 0013, point 5). After a WAL restart a frame the crash left unwritten can still hold an
// earlier generation's commit, so such a crash is refused: Open fails and the maintainer decides.
func walIntact(path string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the shard's own WAL, beside the shard path
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read WAL: %w", err)
	}
	const headerSize, frameHeader = 32, 24
	if len(data) <= headerSize {
		return false, nil // no frame was ever written
	}
	// The checksum covers the magic and the page size. SQLite checksums in the host's byte order, and
	// every supported host is little-endian, so a big-endian WAL fails here too.
	be, order := binary.BigEndian, binary.LittleEndian
	pageSize := int(be.Uint32(data[8:]))
	if s0, s1 := walSum(order, 0, 0, data[:24]); s0 != be.Uint32(data[24:]) || s1 != be.Uint32(data[28:]) {
		return false, errors.New("the WAL header is damaged, and frames follow it")
	}
	s0, s1 := be.Uint32(data[24:]), be.Uint32(data[28:])
	end, commits := -1, 0
	for off := headerSize; off+frameHeader+pageSize <= len(data); off += frameHeader + pageSize {
		frame := data[off : off+frameHeader+pageSize]
		current := bytes.Equal(frame[8:16], data[16:24])
		if end < 0 && current {
			s0, s1 = walSum(order, s0, s1, frame[:8])
			s0, s1 = walSum(order, s0, s1, frame[frameHeader:])
			if s0 == be.Uint32(frame[16:]) && s1 == be.Uint32(frame[20:]) {
				continue
			}
		}
		if end < 0 {
			end = off // SQLite reads no further
		} else if !current {
			continue // a frame of an earlier checkpoint generation
		}
		if be.Uint32(frame[4:]) != 0 {
			if commits++; commits == 2 {
				return false, fmt.Errorf("WAL damaged at byte %d with a committed transaction after it", end)
			}
		}
	}
	return true, nil
}

// walSum continues SQLite's WAL checksum over b, whose length is a multiple of 8.
func walSum(order binary.ByteOrder, s0, s1 uint32, b []byte) (uint32, uint32) {
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:]) + s1
		s1 += order.Uint32(b[i+4:]) + s0
	}
	return s0, s1
}
