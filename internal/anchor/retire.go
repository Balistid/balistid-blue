package anchor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
)

// retiringSuffix marks an old log being deleted: renamed first, so a crash leaves no half log under its name.
const retiringSuffix = ".retiring"

// Retirement deletes old yearly logs beside the current one (ADR 0030, point 7).
type Retirement struct {
	Dir        string // the current log; old ones are its siblings <name>.<n>
	Relay      Relay  // the current log's cosigned checkpoint: the latest witness time
	WitnessKey string // the witness's verifier key file, which also cosigned the old logs' finals
	Keep       time.Duration
	Now        func() time.Time
}

// Run finishes any deletion a crash interrupted, then deletes each old log whose final entry's cosign
// time is Keep behind both the latest witness time and the host's clock. An old log without a final
// that verifies is kept and named in the error; without a readable relay checkpoint nothing is deleted.
func (r Retirement) Run() (retired []string, err error) {
	if r.Keep <= 0 || r.Now == nil || !filepath.IsAbs(r.Dir) {
		return nil, errors.New("anchor: retire: no retention, clock or absolute log directory") // a zero Keep would delete at once
	}
	parent, name := filepath.Dir(r.Dir), filepath.Base(r.Dir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, fmt.Errorf("anchor: retire: %w", err)
	}
	old := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + `\.[0-9]{1,9}$`)
	var errs []error
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, retiringSuffix) && old.MatchString(strings.TrimSuffix(n, retiringSuffix)) {
			errs = append(errs, removeAll(parent, n))
		}
	}
	latest, err := cosign.Read(r.Relay.Path, r.Relay.Keys)
	if err != nil {
		return nil, errors.Join(append(errs, fmt.Errorf("anchor: retire nothing: %w", err))...)
	}
	for _, e := range entries {
		if !e.IsDir() || !old.MatchString(e.Name()) {
			continue
		}
		at, err := r.finalTime(filepath.Join(parent, e.Name()))
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("anchor: old log %s kept: %w", e.Name(), err))
		case latest.Time.Sub(at) >= r.Keep && r.Now().Sub(at) >= r.Keep:
			if err := os.Rename(filepath.Join(parent, e.Name()), filepath.Join(parent, e.Name()+retiringSuffix)); err != nil {
				errs = append(errs, fmt.Errorf("anchor: retire: %w", err))
				continue
			}
			if err := errors.Join(syncDir(parent), removeAll(parent, e.Name()+retiringSuffix)); err != nil {
				errs = append(errs, err)
				continue
			}
			retired = append(retired, e.Name())
		}
	}
	return retired, errors.Join(errs...)
}

// finalTime is the witness's time on the old log's cosigned final, verified with the key saved beside it.
func (r Retirement) finalTime(dir string) (time.Time, error) {
	keys, err := cosign.ReadKeys(filepath.Join(dir, FinalKeyName), r.WitnessKey)
	if err != nil {
		return time.Time{}, err //nolint:wrapcheck // cosign errors carry their context
	}
	cp, err := cosign.Read(filepath.Join(dir, FinalCosignedName), keys)
	if err != nil {
		return time.Time{}, err //nolint:wrapcheck // as above
	}
	return cp.Time, nil
}

// removeAll deletes parent/name and syncs parent. RemoveAll removes links, never what they point to.
func removeAll(parent, name string) error {
	if err := os.RemoveAll(filepath.Join(parent, name)); err != nil {
		return fmt.Errorf("anchor: retire: %w", err)
	}
	return syncDir(parent)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // the ledger's own state directory
	if err != nil {
		return fmt.Errorf("anchor: retire: %w", err)
	}
	return errors.Join(d.Sync(), d.Close())
}
