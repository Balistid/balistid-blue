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
	mark(t, s, 2, at(5)) // an earlier time than one stored takes the stored one
	mark(t, s, 1, at(20))
	want := []int64{at(10).Unix(), at(10).Unix(), at(10).Unix(), 0}
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
	mark(t, s, 1, at(1))
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
	mark(t, s, 1, at(1))
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
	mark(t, s, 1, at(1))
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
	if err := s.MarkCosigned(l.First, l.Last, l.SHA256, at(1)); err != nil {
		t.Fatal(err)
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
