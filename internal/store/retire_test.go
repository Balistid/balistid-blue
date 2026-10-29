package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const month = 30 * 24 * time.Hour

// sealedFour opens a store whose clock is on day 0 and seals a shard on each of days 0 to 3; the store
// stays open on day 4 with the shards' records in its index.
func sealedFour(t *testing.T, dir string) *Store {
	t.Helper()
	s := open(t, dir, small)
	for d := range 5 {
		onDay(s, d)
		add(t, s, noon+int64(d)*day, fmt.Sprint("day ", d))
	}
	if got := len(s.Seals()); got != 4 {
		t.Fatalf("%d seals, want 4", got)
	}
	return s
}

// at is the witness's time days after the first shard's seal.
func at(days int) time.Time { return time.Unix(0, noon+int64(days)*day) }

func mark(t *testing.T, s *Store, i int, when time.Time) {
	t.Helper()
	l := s.Seals()[i]
	if err := s.MarkCosigned(l.First, l.Last, l.SHA256, when); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionUsesCosignTimesNotHostClock(t *testing.T) {
	for _, c := range []struct {
		name          string
		witness, host int // days after the first shard's seal (day 1)
		retired       bool
	}{
		{"the host clock alone, 60 days on", 1, 61, false},
		{"the witness alone, 30 days on", 31, 2, false},
		{"both, a second short of 30 days", 31, 30, false},
		{"both 30 days on", 31, 31, true},
		{"both far on", 400, 400, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := sealedFour(t, t.TempDir())
			mark(t, s, 0, at(1))
			onDay(s, c.host)
			if c.name == "both, a second short of 30 days" {
				s.now = func() time.Time { return time.Unix(0, noon+31*day-int64(time.Second)) }
			}
			got, err := s.Expire(at(c.witness), month)
			if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != c.retired {
				t.Fatalf("retired %v, want %v", got, c.retired)
			}
			if c.retired && (got.First != 1 || s.Seals()[0].First == 1) {
				t.Fatalf("retired %+v, index starts at %d", got, s.Seals()[0].First)
			}
		})
	}
}

func TestIneligibleShardKept(t *testing.T) {
	s := sealedFour(t, t.TempDir())
	onDay(s, 100)
	if got, err := s.Expire(at(100), month); err != nil || got != nil {
		t.Fatalf("a shard no cosigned checkpoint covers: retired %v, %v", got, err)
	}
	mark(t, s, 1, at(50))
	// A latest time below a stored one is a stale or replayed checkpoint: nothing retires on it.
	if got, err := s.Expire(at(49), month); err != nil || got != nil {
		t.Fatalf("a witness time older than a stored one: retired %v, %v", got, err)
	}
	if _, err := s.Expire(at(100), 0); err == nil {
		t.Fatal("a zero retention age was taken")
	}
}

func TestExpireNeverRetiresTheLastSealedShard(t *testing.T) {
	s := sealedFour(t, t.TempDir())
	mark(t, s, 3, at(5))
	onDay(s, 1000)
	for range 3 {
		if got, err := s.Expire(at(1000), month); err != nil || got == nil {
			t.Fatalf("an old shard: retired %v, %v", got, err)
		}
	}
	if got, err := s.Expire(at(1000), month); err != nil || got != nil || len(s.Seals()) != 1 {
		t.Fatalf("the last sealed shard: retired %v, %v, %d left", got, err, len(s.Seals()))
	}
}

func TestMarkCosignedNeverOverwritesOrFalls(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	mark(t, s, 0, at(10))
	l := s.Seals()[2]
	if err := s.MarkCosigned(l.First, l.Last, l.SHA256, at(5)); !errors.Is(err, ErrUndated) { // a replayed older checkpoint
		t.Fatalf("a time older than a stored one: %v", err)
	}
	mark(t, s, 1, at(20))
	mark(t, s, 0, at(30)) // a stored time stays
	want := []int64{at(10).Unix(), at(20).Unix(), 0, 0}
	for i, l := range s.Seals() {
		if l.Cosigned != want[i] {
			t.Fatalf("shard %d: cosign time %d, want %d", i, l.Cosigned, want[i])
		}
	}
	if err := s.MarkCosigned(1, 1, [32]byte{1}, at(30)); !errors.Is(err, ErrNotIndexed) {
		t.Fatalf("a seal the store never made: %v", err)
	}
	closeStore(t, s)
	again := open(t, dir, small)
	defer closeStore(t, again)
	for i, l := range again.Seals()[:4] {
		if l.Cosigned != want[i] {
			t.Fatalf("after a reopen, shard %d: cosign time %d, want %d", i, l.Cosigned, want[i])
		}
	}
}

func TestRetiredShardLeavesTheIndexAndTheDisk(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	before, err := s.used()
	if err != nil {
		t.Fatal(err)
	}
	mark(t, s, 1, at(2))
	onDay(s, 40)
	got, err := s.Expire(at(40), month)
	if err != nil || got == nil {
		t.Fatalf("retired %v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, got.Name)); !os.IsNotExist(err) {
		t.Fatalf("the retired shard's file: %v", err)
	}
	if after, err := s.used(); err != nil || after >= before {
		t.Fatalf("used %d after retiring, %d before (%v)", after, before, err)
	}
	if _, _, err := s.Leaves(t.Context(), 0, 10, 1<<20); err == nil {
		t.Fatal("leaves of a retired shard were read")
	}
	add(t, s, noon+40*day, "after")
	closeStore(t, s)
	again := open(t, dir, small)
	defer closeStore(t, again)
	seals := again.Seals()
	if seals[0].First != got.Last+1 || nextAfter(seals) != again.next {
		t.Fatalf("after a reopen the index starts at %d, next seq %d", seals[0].First, again.next)
	}
	if read, err := ReadSeals(t.Context(), dir); err != nil || len(read) != len(seals) {
		t.Fatalf("ReadSeals = %d seals, %v", len(read), err)
	}
}

// A crash after the index lost the shard and before its file went leaves the file below the first line.
func TestOpenFinishesARetirementACrashLeftHalfDone(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	closeStore(t, s)
	seals := s.Seals()
	leftover := filepath.Join(dir, seals[0].Name)
	if err := s.writeIndex(seals[1:]); err != nil {
		t.Fatal(err)
	}
	if read, err := ReadSeals(t.Context(), dir); err != nil || len(read) != len(seals)-1 {
		t.Fatalf("ReadSeals beside a half-retired shard = %d seals, %v", len(read), err)
	}
	if _, err := os.Stat(leftover); err != nil {
		t.Fatal("ReadSeals removed a file")
	}
	again := open(t, dir, small)
	defer closeStore(t, again)
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("Open left the retired shard's file: %v", err)
	}
}

func TestOpenRefusesShardsNotFromSeqOneWithoutAnIndex(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	mark(t, s, 1, at(2))
	onDay(s, 40)
	if got, err := s.Expire(at(40), month); err != nil || got == nil {
		t.Fatalf("retired %v, %v", got, err)
	}
	closeStore(t, s)
	if err := os.Remove(filepath.Join(dir, indexName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), dir, small); err == nil || !strings.Contains(err.Error(), "does not start at seq 1") {
		t.Fatalf("Open without an index after a retirement: %v", err)
	}
}

func TestRetiringRefillsTheReserve(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	if err := s.free(); err != nil {
		t.Fatal(err)
	}
	if s.given != LossChunk {
		t.Fatalf("given %d", s.given)
	}
	mark(t, s, 1, at(2))
	onDay(s, 40)
	if got, err := s.Expire(at(40), month); err != nil || got == nil {
		t.Fatalf("retired %v, %v", got, err)
	}
	st, err := os.Stat(filepath.Join(dir, reserveName))
	if err != nil || s.given != 0 || st.Size() != small.Headroom {
		t.Fatalf("reserve %v bytes, given %d (%v)", st.Size(), s.given, err)
	}
}

func TestMarkingAndRetiringLeaveAnUnknownStoreAlone(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	l := s.Seals()[1]
	s.unknown = "a test"
	if err := s.MarkCosigned(l.First, l.Last, l.SHA256, at(1)); !errors.Is(err, ErrUndated) {
		t.Fatalf("an UNKNOWN store: %v", err)
	}
	if s.Seals()[1].Cosigned != 0 {
		t.Fatal("an UNKNOWN store took a cosign time")
	}
	s.seals[0].Cosigned = at(1).Unix()
	onDay(s, 400)
	if got, err := s.Expire(at(400), month); err != nil || got != nil {
		t.Fatalf("an UNKNOWN store retired %v, %v", got, err)
	}
}

func TestIndexTimesAreRefusedWhenMalformed(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	mark(t, s, 0, at(1))
	closeStore(t, s)
	index := filepath.Join(dir, indexName)
	data, err := os.ReadFile(index) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	with := func(i int, f func([]string) []string) string {
		out := slices.Clone(lines)
		out[i] = strings.Join(f(strings.Fields(lines[i])), " ") + "\n"
		return strings.Join(out, "")
	}
	for name, body := range map[string]string{
		"a seal time with a sign":       with(1, func(f []string) []string { f[4] = "+" + f[4]; return f }),
		"a seal time with a zero ahead": with(1, func(f []string) []string { f[4] = "0" + f[4]; return f }),
		"a seal time before 1970":       with(1, func(f []string) []string { f[4] = "-1"; return f }),
		"a cosign time of zero":         with(2, func(f []string) []string { return append(f, "0") }),
		"a cosign time that falls":      with(2, func(f []string) []string { return append(f, "1") }),
		"a cosign time after a gap":     with(3, func(f []string) []string { return append(f, f[4]) }),
		"seven fields":                  with(1, func(f []string) []string { return append(f, "1") }),
		"a zero hash":                   with(1, func(f []string) []string { f[3] = strings.Repeat("0", 64); return f }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(index, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := ReadSeals(t.Context(), dir); err == nil {
				t.Fatalf("ReadSeals = %v", got)
			}
		})
	}
}

// A checkpoint dates only the seals it does not predate by more than ClockSkew; the later ones wait.
func TestACosignTimeDatesOnlySealsItDoesNotPredate(t *testing.T) {
	s := sealedFour(t, t.TempDir())
	seals := s.Seals()
	sealed := time.Unix(seals[2].Sealed, 0)
	if err := s.MarkCosigned(seals[2].First, seals[2].Last, seals[2].SHA256, time.Unix(0, 0)); err == nil {
		t.Fatal("a cosign time of 1970 was taken")
	}
	early := sealed.Add(-ClockSkew - time.Second) // after the first two seals, an hour and a second before the third
	if err := s.MarkCosigned(seals[2].First, seals[2].Last, seals[2].SHA256, early); !errors.Is(err, ErrUndated) {
		t.Fatalf("the named seal left undated: %v", err)
	}
	if got := s.Seals(); got[0].Cosigned != early.Unix() || got[1].Cosigned != early.Unix() || got[2].Cosigned != 0 {
		t.Fatalf("cosign times %d %d %d", got[0].Cosigned, got[1].Cosigned, got[2].Cosigned)
	}
	if err := s.MarkCosigned(seals[2].First, seals[2].Last, seals[2].SHA256, sealed.Add(-ClockSkew)); err != nil {
		t.Fatal(err)
	}
	if got := s.Seals(); got[1].Cosigned != early.Unix() || got[2].Cosigned != sealed.Add(-ClockSkew).Unix() {
		t.Fatalf("cosign times %d %d", got[1].Cosigned, got[2].Cosigned)
	}
}

// An unlink that fails leaves the shard out of the index; the next Expire finishes it before another
// shard leaves, so there is never more than one file below the first line and Open still opens.
func TestAFailedUnlinkIsFinishedBeforeAnotherRetirement(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a test temp dir back to its owner
	s := sealedFour(t, dir)
	mark(t, s, 2, at(3))
	onDay(s, 100)
	s.crashAt = func(point string) {
		if point == "retired" {
			_ = os.Chmod(dir, 0o500) //nolint:gosec // the unlink fails, as on a filesystem error
		}
	}
	got, err := s.Expire(at(100), month)
	if got == nil || err == nil {
		t.Fatalf("retired %v, %v", got, err)
	}
	s.crashAt = func(string) {}
	if again, err := s.Expire(at(100), month); again != nil || err == nil { // still failing: nothing else leaves
		t.Fatalf("a second retirement while the first is unfinished: %v, %v", again, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a test temp dir back to its owner
		t.Fatal(err)
	}
	if again, err := s.Expire(at(100), month); again != nil || err != nil {
		t.Fatalf("finishing the first: %v, %v", again, err)
	}
	if _, err := os.Stat(filepath.Join(dir, got.Name)); !os.IsNotExist(err) {
		t.Fatalf("the retired shard's file: %v", err)
	}
	if next, err := s.Expire(at(100), month); next == nil || err != nil || next.First != got.Last+1 {
		t.Fatalf("the next retirement: %v, %v", next, err)
	}
	closeStore(t, s)
	closeStore(t, open(t, dir, small))
}

func FuzzParseSeal(f *testing.F) {
	f.Add("00000000000000000001.db 1 3 " + strings.Repeat("ab", 32) + " 5 7")
	f.Add("00000000000000000001.db 1 3 " + strings.Repeat("ab", 32) + " 0")
	f.Fuzz(func(t *testing.T, line string) {
		l, err := parseSeal(line)
		if err == nil && (l.line() != line+"\n" || int64(len(l.line())) > maxLineBytes) {
			t.Fatalf("accepted %q", line)
		}
	})
}

// Whatever readSeals accepts is the index writeIndex would write, up to a torn last line, with seqs that
// run on and cosign times that cover a prefix and never fall.
func FuzzReadSeals(f *testing.F) {
	sum := strings.Repeat("ab", 32)
	f.Add([]byte(indexHeader + "00000000000000000003.db 3 3 " + sum + " 5 7\n"))
	f.Add([]byte(indexHeader + "00000000000000000003.db 3 4 " + sum + " 5 7\n00000000000000000005.db 5 9 " + sum + " 6\n"))
	f.Add([]byte(indexHeader + "00000000000000000001.db 1 1 " + sum + " 5\n0000000000000000000"))
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, indexName), b, 0o600); err != nil {
			t.Fatal(err)
		}
		seals, torn, err := readSeals(t.Context(), dir)
		if err != nil {
			return
		}
		var w strings.Builder
		w.WriteString(indexHeader)
		for i, l := range seals {
			w.WriteString(l.line())
			if i > 0 && (l.First != seals[i-1].Last+1 || l.Cosigned != 0 && (seals[i-1].Cosigned == 0 || l.Cosigned < seals[i-1].Cosigned)) {
				t.Fatalf("accepted %+v after %+v", l, seals[i-1])
			}
		}
		if !strings.HasPrefix(string(b), w.String()) || !torn && len(b) != w.Len() {
			t.Fatalf("accepted %q as %q (torn %v)", b, w.String(), torn)
		}
	})
}

// Expire retires one shard at a time: two files below the first line are no crash, and Open removes neither.
func TestOpenRefusesTwoShardsBelowTheFirstLine(t *testing.T) {
	dir := t.TempDir()
	s := sealedFour(t, dir)
	closeStore(t, s)
	seals := s.Seals()
	if err := s.writeIndex(seals[2:]); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), dir, small); err == nil || !strings.Contains(err.Error(), "below the index's first line") {
		t.Fatalf("Open = %v", err)
	}
	for _, l := range seals[:2] {
		if _, err := os.Stat(filepath.Join(dir, l.Name)); err != nil {
			t.Fatalf("%s: %v", l.Name, err)
		}
	}
}

func TestParseSealRefusesSeqZero(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	for _, line := range []string{"00000000000000000000.db 0 1 " + sum + " 5", "00000000000000000000.db 0 0 " + sum + " 5"} {
		if l, err := parseSeal(line); err == nil {
			t.Fatalf("accepted %+v", l)
		}
	}
	if _, err := parseSeal("00000000000000000001.db 1 1 " + sum + " 5"); err != nil {
		t.Fatal(err)
	}
}
