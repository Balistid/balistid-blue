package watch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

const (
	stateName   = "state.json"
	stateSchema = 1
	// maxState holds 64 range hashes and 255 partial entries in base64 with room to spare.
	maxState = 1 << 20
	maxRange = 64
)

// saved is the state file: written whole by the Pi, read back strictly.
type saved struct {
	Schema  int      `json:"schema_version"`
	Origin  string   `json:"origin"`
	Size    uint64   `json:"size"`
	Root    []byte   `json:"root"`
	Hashes  [][]byte `json:"hashes"`
	Partial [][]byte `json:"partial"`
	Rules   Rules    `json:"rules"`
	QuietS  *int64   `json:"quiet_s,omitempty"` // the open quiet episode's age
}

// Store is the Pi's directory for one origin: the state file and the complete bundles verified, in
// Tessera's layout. Not safe for concurrent use.
type Store struct {
	dir    string
	origin string
	cap    int64
	stored int64
	full   bool
}

// OpenStore opens origin's directory under state, named by the origin's hash (an origin may hold "/"),
// and counts the bundles it keeps.
func OpenStore(state, origin string, capBytes int64) (*Store, error) {
	if !filepath.IsAbs(state) || origin == "" || capBytes <= 0 {
		return nil, errors.New("watch: store: an absolute directory, an origin and a cap")
	}
	sum := sha256.Sum256([]byte(origin))
	s := &Store{dir: filepath.Join(state, hex.EncodeToString(sum[:16])), origin: origin, cap: capBytes}
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return nil, fmt.Errorf("watch: store: %w", err)
	}
	err := filepath.WalkDir(filepath.Join(s.dir, "tile"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("watch: store: %w", err)
		}
		s.stored += info.Size()
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("watch: store: %w", err)
	}
	s.full = s.stored >= s.cap
	return s, nil
}

// Full says the store reached its cap: bundles are no longer kept, verification goes on.
func (s *Store) Full() bool { return s.full }

// Keep writes a complete bundle, unless that would pass the cap.
func (s *Store) Keep(idx uint64, entries [][]byte) error {
	if s.full {
		return nil
	}
	data := appendBundle(nil, entries)
	path := filepath.Join(s.dir, filepath.FromSlash(layout.EntriesPath(idx, 0)))
	grow := int64(len(data))
	if info, err := os.Lstat(path); err == nil {
		grow -= info.Size()
	}
	if s.stored+grow > s.cap {
		s.full = true
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("watch: store: %w", err)
	}
	if err := wholefile.Write(path, data, 0o600); err != nil {
		return fmt.Errorf("watch: store: %w", err)
	}
	s.stored += grow
	return nil
}

// Save writes l and the quiet episode's age after the bundles it counts.
func (s *Store) Save(l Log, quiet *time.Duration) error {
	v := saved{Schema: stateSchema, Origin: s.origin, Size: l.Size, Root: l.Root[:], Hashes: l.Hashes,
		Partial: l.Partial, Rules: l.Rules}
	if quiet != nil {
		q := int64(quiet.Seconds())
		v.QuietS = &q
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("watch: state: %w", err)
	}
	if err := wholefile.Write(filepath.Join(s.dir, stateName), b, 0o600); err != nil {
		return fmt.Errorf("watch: state: %w", err)
	}
	return nil
}

// Load reads the state file; none yet is an empty log. A file that does not parse is an error, never a
// fresh start: that would verify the host's log from scratch with its history forgotten (R6).
func (s *Store) Load() (Log, *time.Duration, error) {
	f, err := os.OpenFile(filepath.Join(s.dir, stateName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return Log{}, nil, nil
	}
	if err != nil {
		return Log{}, nil, fmt.Errorf("watch: state: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxState+1))
	if err != nil || len(b) > maxState {
		return Log{}, nil, errors.Join(errors.New("watch: state unreadable or over its cap"), err)
	}
	var v saved
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil || d.More() {
		return Log{}, nil, errors.Join(errors.New("watch: state does not parse"), err)
	}
	l, err := v.log(s.origin)
	if err != nil {
		return Log{}, nil, err
	}
	var quiet *time.Duration
	if v.QuietS != nil {
		if *v.QuietS < 0 {
			return Log{}, nil, errors.New("watch: state: negative quiet age")
		}
		q := time.Duration(*v.QuietS) * time.Second
		quiet = &q
	}
	return l, quiet, nil
}

func (v saved) log(origin string) (Log, error) {
	switch {
	case v.Schema != stateSchema:
		return Log{}, fmt.Errorf("watch: state schema %d", v.Schema)
	case v.Origin != origin:
		return Log{}, errors.New("watch: state of another origin")
	case len(v.Root) != 32 || len(v.Hashes) > maxRange || uint64(len(v.Partial)) != v.Size%width:
		return Log{}, errors.New("watch: state with a malformed root, range or partial bundle")
	}
	for _, h := range v.Hashes {
		if len(h) != sha256.Size {
			return Log{}, errors.New("watch: state with a malformed range hash")
		}
	}
	for _, e := range v.Partial {
		if len(e) == 0 || len(e) > entry.MaxBytes {
			return Log{}, errors.New("watch: state with a malformed partial entry")
		}
	}
	l := Log{Size: v.Size, Hashes: v.Hashes, Partial: v.Partial, Rules: v.Rules}
	copy(l.Root[:], v.Root)
	return l, nil
}
