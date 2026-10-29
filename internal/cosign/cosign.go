// Package cosign reads the checkpoint the witness cosigned, as the relay keeps it (ADR 0006, 0029).
// The ledger's signature and the witness's cosignature/v1 must both verify, and the witness's time
// comes from its signed line, never from a clock on the host. The ledger and the collector each
// check the same note, so neither trusts another process's reading of it.
package cosign

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// Name is the file, in the relay's directory, holding the last checkpoint the witness cosigned: the
// ledger's note with the witness's verified line appended.
const Name = "checkpoint.cosigned"

// MaxNote bounds a cosigned checkpoint: a note with a few signatures.
const MaxNote = 16 << 10

// A witness time outside these bounds is refused: a Pi without a clock source starts in 1970, and
// past 2262 the time no longer fits a time.Duration from now.
var (
	minTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	maxTime = time.Date(2262, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Keys are what a cosigned checkpoint must verify with.
type Keys struct {
	Origin  string        // the log's origin line
	Log     note.Verifier // the ledger's checkpoint key
	Witness note.Verifier // the witness's cosignature/v1 key
}

// Checkpoint is a cosigned checkpoint whose two signatures verified.
type Checkpoint struct {
	Size uint64
	Root []byte    // the log's root hash at Size
	Time time.Time // the witness's, from its signed line, UTC
	Note []byte    // the note as it verified
}

// Open verifies a cosigned checkpoint: at most MaxNote bytes, the ledger's and the witness's signature
// both verified, the origin k names and a witness time within bounds. Lines of other keys are ignored.
func Open(b []byte, k Keys) (Checkpoint, error) {
	if k.Origin == "" || k.Log == nil || k.Witness == nil {
		return Checkpoint{}, errors.New("cosign: incomplete keys")
	}
	if len(b) > MaxNote {
		return Checkpoint{}, fmt.Errorf("cosign: note of %d bytes", len(b))
	}
	n, err := note.Open(b, note.VerifierList(k.Log, k.Witness))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("cosign: %w", err)
	}
	if len(n.Sigs) != 2 { // note.Open keeps one verified line per key
		return Checkpoint{}, errors.New("cosign: not signed by both the ledger and the witness")
	}
	var cp log.Checkpoint
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		return Checkpoint{}, fmt.Errorf("cosign: %w", err)
	}
	if cp.Origin != k.Origin {
		return Checkpoint{}, fmt.Errorf("cosign: origin %q", cp.Origin)
	}
	i := slices.IndexFunc(n.Sigs, func(s note.Signature) bool {
		return s.Name == k.Witness.Name() && s.Hash == k.Witness.KeyHash()
	})
	if i < 0 {
		return Checkpoint{}, errors.New("cosign: no witness line")
	}
	t, err := fnote.CoSigV1Timestamp(n.Sigs[i])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("cosign: witness time: %w", err)
	}
	if t.Before(minTime) || t.After(maxTime) {
		return Checkpoint{}, fmt.Errorf("cosign: witness time %d out of bounds", t.Unix())
	}
	return Checkpoint{Size: cp.Size, Root: cp.Hash, Time: t.UTC(), Note: slices.Clone(b)}, nil
}

// maxKeyBytes bounds a verifier key file: a name and a base64 key.
const maxKeyBytes = 4 << 10

// ReadKeys reads the ledger's and the witness's verifier keys as the install writes them; the origin
// is the ledger key's name.
func ReadKeys(logKey, witnessKey string) (Keys, error) {
	lv, err := readVerifier(logKey, note.NewVerifier)
	if err != nil {
		return Keys{}, err
	}
	wv, err := readVerifier(witnessKey, fnote.NewVerifierForCosignatureV1)
	if err != nil {
		return Keys{}, err
	}
	return Keys{Origin: lv.Name(), Log: lv, Witness: wv}, nil
}

// readVerifier reads a public verifier key: no secret, but a size cap and no symlink (ENGINEERING 7).
func readVerifier(path string, parse func(string) (note.Verifier, error)) (note.Verifier, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the key's path is configuration
	if err != nil {
		return nil, fmt.Errorf("cosign: verifier key: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxKeyBytes+1))
	if err != nil || len(b) > maxKeyBytes {
		return nil, errors.Join(fmt.Errorf("cosign: verifier key %s: unreadable or too large", path), err)
	}
	v, err := parse(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("cosign: verifier key %s: %w", path, err)
	}
	return v, nil
}

// Read opens the cosigned checkpoint at path, which another uid writes: no symlink, no FIFO, never
// more than MaxNote+1 bytes held.
func Read(path string, k Keys) (Checkpoint, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // a fixed name in the relay's directory
	if err != nil {
		return Checkpoint{}, fmt.Errorf("cosign: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return Checkpoint{}, errors.Join(errors.New("cosign: not a regular file"), err)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxNote+1))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("cosign: %w", err)
	}
	return Open(b, k)
}
