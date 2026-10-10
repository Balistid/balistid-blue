package rangerun

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// MaxLedgerBytes caps the ledger file; a ledger at every other cap is about 0.32 MiB.
const MaxLedgerBytes = 1 << 20

// maxKeyBytes is the longest key Next makes: "taken:" + 64 hex + ":" + 64 hex = 135.
const maxKeyBytes = 135

const ledgerSchema = 2

// Errors of LoadLedger. A lost or unreadable ledger must not read as an empty one, which would
// reset the quota and the once-per-name rule. ErrNoLedger also matches fs.ErrNotExist.
var (
	ErrNoLedger      = errors.New("no ledger")
	ErrCorruptLedger = errors.New("ledger is corrupt")
)

// ledgerFile is the ledger as stored, so Ledger{} stays a valid empty ledger in memory.
// The pointers tell a missing or null field from an empty one.
type ledgerFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Entries       *[]Entry              `json:"entries"`
	Clock         *map[string]time.Time `json:"clock"`
	Evidence      *Evidence             `json:"evidence"`
}

// LoadLedger reads path, without following a link or blocking, if it is a regular file of at most
// MaxLedgerBytes holding exactly one ledger object of schema version ledgerSchema within every cap. A missing
// file is ErrNoLedger, anything else wrong ErrCorruptLedger, whose text never quotes the file.
func LoadLedger(path string) (Ledger, error) {
	data, err := readLedger(path)
	if err != nil {
		return Ledger{}, err
	}
	l, err := decodeLedger(data)
	if err != nil {
		return Ledger{}, fmt.Errorf("%w: %s: %w", ErrCorruptLedger, path, err)
	}
	return l, nil
}

// SaveLedger replaces the ledger at path through rangevm.WriteFileAtomic (mode 0600). It refuses,
// leaving the old file, a ledger LoadLedger would refuse.
func SaveLedger(path string, l Ledger) error {
	data, err := encodeLedger(l)
	if err != nil {
		return fmt.Errorf("save ledger %s: %w", path, err)
	}
	if err := rangevm.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("save ledger: %w", err)
	}
	return nil
}

func readLedger(path string) ([]byte, error) {
	data, err := readFile(path, MaxLedgerBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrNoLedger, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorruptLedger, err)
	}
	return data, nil
}

// readFile reads the regular file at path, at most limit bytes, without following a link in its
// last component or blocking on a FIFO.
func readFile(path string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the runner's own files; O_NOFOLLOW refuses a link
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return data, nil
}

// decodeLedger returns the ledger in data with its times in UTC. Its errors are fixed text,
// because json's own would quote the file.
func decodeLedger(data []byte) (Ledger, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f ledgerFile
	if err := dec.Decode(&f); err != nil {
		return Ledger{}, errors.New("not a ledger object, or a field is unknown or of the wrong type")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Ledger{}, errors.New("data after the ledger object")
	}
	if f.SchemaVersion != ledgerSchema {
		return Ledger{}, fmt.Errorf("schema_version must be %d", ledgerSchema)
	}
	if f.Entries == nil || f.Clock == nil || f.Evidence == nil {
		return Ledger{}, errors.New("entries, clock and evidence are required")
	}
	l := Ledger{Entries: *f.Entries, Clock: *f.Clock, Evidence: *f.Evidence}
	if err := l.check(); err != nil {
		return Ledger{}, err
	}
	for i := range l.Entries {
		l.Entries[i].Seen = l.Entries[i].Seen.UTC()
	}
	for id, t := range l.Clock {
		l.Clock[id] = t.UTC()
	}
	return l, nil
}

// encodeLedger returns l as stored, only if decodeLedger accepts the result.
func encodeLedger(l Ledger) ([]byte, error) {
	entries := make([]Entry, 0, len(l.Entries))
	for _, e := range l.Entries {
		entries = append(entries, Entry{Key: e.Key, Seen: e.Seen.UTC(), Status: e.Status})
	}
	clock := make(map[string]time.Time, len(l.Clock))
	for id, t := range l.Clock {
		clock[id] = t.UTC()
	}
	ev := l.Evidence
	if !ev.LastPass.IsZero() {
		ev.LastPass = ev.LastPass.UTC()
	}
	if ev.Failed == nil {
		ev.Failed = []FailedRun{}
	}
	data, err := json.Marshal(ledgerFile{SchemaVersion: ledgerSchema, Entries: &entries, Clock: &clock, Evidence: &ev})
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	if len(data) > MaxLedgerBytes {
		return nil, fmt.Errorf("over %d bytes", MaxLedgerBytes)
	}
	if _, err := decodeLedger(data); err != nil {
		return nil, err
	}
	return data, nil
}

// check refuses a ledger Next could not have made.
func (l Ledger) check() error {
	if len(l.Entries) > MaxLedger {
		return fmt.Errorf("more than %d entries", MaxLedger)
	}
	if len(l.Clock) > MaxInboxEntries {
		return fmt.Errorf("more than %d clock times", MaxInboxEntries)
	}
	for _, e := range l.Entries {
		if !validKey(e.Key) {
			return errors.New("an entry key is empty, too long or outside the key alphabet")
		}
		if !validTime(e.Seen) {
			return errors.New("an entry seen time is zero or out of range")
		}
		if e.Status != Taken && e.Status != Rejected {
			return errors.New("an entry status is neither taken nor rejected")
		}
	}
	for id, t := range l.Clock {
		if !validKey(id) {
			return errors.New("a clock key is empty, too long or outside the key alphabet")
		}
		if !validTime(t) {
			return errors.New("a clock time is zero or out of range")
		}
	}
	e := l.Evidence
	if e.Commit == "" && !e.LastPass.IsZero() || e.Commit != "" && (!buildinfo.IsCommitID(e.Commit) || !validTime(e.LastPass)) {
		return errors.New("evidence commit or time is malformed")
	}
	if e.Pending != "" && !resultName.MatchString(e.Pending) {
		return errors.New("the pending evidence run is malformed")
	}
	if e.Failed == nil || len(e.Failed) > MaxFailed {
		return fmt.Errorf("evidence needs a list of at most %d failed runs", MaxFailed)
	}
	for _, f := range e.Failed {
		if !buildinfo.IsCommitID(f.Commit) || !resultName.MatchString(f.ID) {
			return errors.New("a failed evidence run is malformed")
		}
	}
	return nil
}

// validTime refuses the zero time and a UTC year JSON cannot write back (an offset can carry
// 9999-12-31 into 10000).
func validTime(t time.Time) bool {
	y := t.UTC().Year()
	return !t.IsZero() && y >= 1970 && y <= 9999
}

// validKey accepts Next's alphabet, which JSON never escapes, so a loaded ledger fits when saved.
func validKey(key string) bool {
	if key == "" || len(key) > maxKeyBytes {
		return false
	}
	for _, c := range []byte(key) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return true
}
