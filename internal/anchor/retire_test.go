package anchor

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
)

const keep = 400 * 24 * time.Hour

// retirement sets up a state directory with the current log and one old log, log.1, whose final the
// witness cosigned at witnessAt, and a relay checkpoint cosigned at latest.
func retirement(t *testing.T, latest, now time.Time) (Retirement, string) {
	t.Helper()
	f := cosigntest.New(t)
	old, _ := oldLog(t, f)
	state := t.TempDir()
	if err := os.Rename(old, filepath.Join(state, "log.1")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(state, "log.1", FinalKeyName), []byte(f.LogKey+"\n"))
	witnessKey := filepath.Join(state, "witness.vkey")
	write(t, witnessKey, []byte(f.Witness+"\n"))
	relay := Relay{Path: filepath.Join(state, cosign.Name), Keys: f.Keys}
	write(t, relay.Path, f.Cosigned(t, 9, latest))
	return Retirement{Dir: filepath.Join(state, "log"), Relay: relay, WitnessKey: witnessKey, Keep: keep,
		Now: func() time.Time { return now }}, state
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestRetiredLogKeptUntilBothClocks(t *testing.T) {
	early, late := witnessAt.Add(keep-time.Hour), witnessAt.Add(keep+time.Hour)
	for name, c := range map[string]struct {
		latest, now time.Time
		retired     bool
	}{
		"the witness's clock short": {early, late, false},
		"the host's clock short":    {late, early, false},
		"both past":                 {late, late, true},
	} {
		t.Run(name, func(t *testing.T) {
			r, state := retirement(t, c.latest, c.now)
			got, err := r.Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) == 1) != c.retired || exists(t, filepath.Join(state, "log.1")) == c.retired {
				t.Fatalf("retired %v", got)
			}
			if exists(t, filepath.Join(state, "log.1"+retiringSuffix)) {
				t.Fatal("a .retiring log left behind")
			}
		})
	}
}

// A crash between the rename and the removal leaves log.N.retiring, which the next run removes, even
// before it can read the relay's checkpoint; nothing else beside the log is touched.
func TestARetiringLogIsFinished(t *testing.T) {
	r, state := retirement(t, witnessAt, witnessAt)
	if err := os.Rename(filepath.Join(state, "log.1"), filepath.Join(state, "log.1"+retiringSuffix)); err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"log.x" + retiringSuffix, "other.1" + retiringSuffix} {
		if err := os.Mkdir(filepath.Join(state, other), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	remove(t, r.Relay.Path)
	if _, err := r.Run(t.Context()); err == nil {
		t.Fatal("ran without the relay's checkpoint")
	}
	if exists(t, filepath.Join(state, "log.1"+retiringSuffix)) {
		t.Fatal("the interrupted deletion was not finished")
	}
	for _, other := range []string{"log.x" + retiringSuffix, "other.1" + retiringSuffix} {
		if !exists(t, filepath.Join(state, other)) {
			t.Fatalf("%s removed", other)
		}
	}
}

func TestAnOldLogWithoutAVerifiedFinalIsKept(t *testing.T) {
	late := witnessAt.Add(2 * keep)
	for name, change := range map[string]func(t *testing.T, state string){
		"no final": func(t *testing.T, state string) { remove(t, filepath.Join(state, "log.1", FinalCosignedName)) },
		"no key":   func(t *testing.T, state string) { remove(t, filepath.Join(state, "log.1", FinalKeyName)) },
		"another key": func(t *testing.T, state string) {
			write(t, filepath.Join(state, "log.1", FinalKeyName), []byte(cosigntest.New(t).LogKey))
		},
		"not a log.N": func(t *testing.T, state string) { mv(t, filepath.Join(state, "log.1"), filepath.Join(state, "log.1a")) },
		"another name": func(t *testing.T, state string) {
			mv(t, filepath.Join(state, "log.1"), filepath.Join(state, "other.1"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, state := retirement(t, late, late)
			change(t, state)
			got, _ := r.Run(t.Context())
			if len(got) != 0 {
				t.Fatalf("retired %v", got)
			}
			entries, err := os.ReadDir(state)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.IsDir() }) {
				t.Fatal("the old log is gone")
			}
		})
	}
}

func mv(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

// A zero retention would delete every old log with a final at once; no clock or a relative directory
// cannot be measured against.
func TestRetirementRefusesAnIncompleteConfig(t *testing.T) {
	late := witnessAt.Add(2 * keep)
	for name, change := range map[string]func(*Retirement){
		"zero keep":    func(r *Retirement) { r.Keep = 0 },
		"no clock":     func(r *Retirement) { r.Now = nil },
		"relative dir": func(r *Retirement) { r.Dir = "log" },
	} {
		t.Run(name, func(t *testing.T) {
			r, state := retirement(t, late, late)
			change(&r)
			if got, err := r.Run(t.Context()); err == nil || len(got) != 0 || !exists(t, filepath.Join(state, "log.1")) {
				t.Fatalf("retired %v, %v", got, err)
			}
		})
	}
}

// A note dates an old log only when its last entry is that log's own final entry: neither another log's
// note copied beside an empty one, nor an older, genuine note of the same log replayed as its final.
func TestOnlyTheLogsOwnFinalDatesIt(t *testing.T) {
	late := witnessAt.Add(keep + time.Hour)
	t.Run("another log's note", func(t *testing.T) {
		r, state := retirement(t, late, late)
		if err := os.Mkdir(filepath.Join(state, "log.2"), 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{FinalCosignedName, FinalKeyName} {
			b, err := os.ReadFile(filepath.Join(state, "log.1", name)) //nolint:gosec // the test's own directory
			if err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(state, "log.2", name), b)
		}
		if got, err := r.Run(t.Context()); err == nil || !slices.Equal(got, []string{"log.1"}) || !exists(t, filepath.Join(state, "log.2")) {
			t.Fatalf("retired %v, %v", got, err)
		}
	})
	t.Run("an older note replayed", func(t *testing.T) {
		f := cosigntest.New(t)
		state, c := t.TempDir(), &clock{t: time.Unix(1e9, 0)}
		dir := filepath.Join(state, "log.1")
		cfg := Config{Dir: dir, Signer: f.Log, CapBytes: 1 << 30, CheckpointInterval: 100 * time.Millisecond, Now: c.now}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		l := openLog(t, cfg)
		records(t, l, 1, 2)
		closeLog(t, l)
		early, err := os.ReadFile(filepath.Join(dir, layout.CheckpointPath)) //nolint:gosec // the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		l = openLog(t, cfg)
		if _, err := l.Final(t.Context(), next); err != nil {
			t.Fatal(err)
		}
		closeLog(t, l)
		// The final itself was cosigned at witnessAt; the replayed note of size 1 carries a time 300 days older.
		write(t, filepath.Join(dir, FinalCosignedName), f.Cosign(t, early, witnessAt.Add(-300*24*time.Hour)))
		write(t, filepath.Join(dir, FinalKeyName), []byte(f.LogKey+"\n"))
		witnessKey := filepath.Join(state, "witness.vkey")
		write(t, witnessKey, []byte(f.Witness+"\n"))
		now := witnessAt.Add(150 * 24 * time.Hour)
		relay := Relay{Path: filepath.Join(state, cosign.Name), Keys: f.Keys}
		write(t, relay.Path, f.Cosigned(t, 9, now))
		r := Retirement{Dir: filepath.Join(state, "log"), Relay: relay, WitnessKey: witnessKey, Keep: keep, Now: func() time.Time { return now }}
		if got, err := r.Run(t.Context()); err == nil || len(got) != 0 || !exists(t, dir) {
			t.Fatalf("retired %v, %v", got, err)
		}
	})
}
