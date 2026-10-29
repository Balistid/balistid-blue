package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
)

// The crash tests run this test binary again as a child that works on a store and kills itself with
// SIGKILL at a named point (crashAt). After every Flush the child prints "ack N" for each record
// Append stored since the last one, which the Flush made durable, and "flushed D", D being the drops
// so far; the parent then opens the store.
const childEnv = "BALISTID_STORE_CRASH"

var crashLimits = Limits{Cap: shard.WALMaxBytes + 512<<10, ShardMax: 160 << 10, Headroom: shard.WALMaxBytes + 8*LossChunk}

func TestCrashChild(t *testing.T) {
	spec := os.Getenv(childEnv)
	if spec == "" {
		t.Skip("runs only as the child of a crash test")
	}
	parts := strings.SplitN(spec, ":", 3)
	at, _ := strconv.Atoi(parts[1])
	hits := 0
	s, err := openWith(t.Context(), parts[2], crashLimits, func(point string) {
		if point == parts[0] {
			if hits++; hits == at {
				syscall.Kill(os.Getpid(), syscall.SIGKILL) //nolint:errcheck,gosec // the crash under test
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	retire := parts[0] == "retired"
	if retire { // a store clock a second on at every reading, so shards come of age within one day
		var tick int64
		s.now = func() time.Time { tick++; return time.Unix(0, noon+tick*int64(time.Second)) }
	}
	drops, stored := 0, []int{}
	for i := 1; i <= 2000; i++ {
		ok, _, err := s.Append(t.Context(), rawrecord.New(0, "laurel", uint64(i), noon+int64(i/200)*day, []byte(fmt.Sprintf("rec-%d-%s", i, strings.Repeat("x", 900)))))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			stored = append(stored, i)
		} else {
			drops++
		}
		if i%7 == 0 {
			if _, err := s.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, n := range stored {
				fmt.Printf("ack %d\n", n)
			}
			stored = stored[:0]
			fmt.Printf("flushed %d\n", drops)
			if seals := s.Seals(); retire && len(seals) > 1 {
				l, now := seals[len(seals)-1], s.now()
				if err := s.MarkCosigned(l.First, l.Last, l.SHA256, now); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Expire(now.Add(time.Hour), time.Second); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	t.Fatal("the crash point was never reached")
}

func crash(t *testing.T, point string, at int) (dir string, acked []int, flushed int) {
	t.Helper()
	dir = t.TempDir()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCrashChild$", "-test.v=false") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s:%d:%s", childEnv, point, at, dir))
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child did not die by SIGKILL at %s #%d: %v\n%s", point, at, err, out)
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if n, ok := strings.CutPrefix(sc.Text(), "ack "); ok {
			i, _ := strconv.Atoi(n)
			acked = append(acked, i)
		}
		if n, ok := strings.CutPrefix(sc.Text(), "flushed "); ok {
			flushed, _ = strconv.Atoi(n)
		}
	}
	return dir, acked, flushed
}

func TestEveryAcknowledgedRecordSurvivesAKill(t *testing.T) {
	for _, c := range []struct {
		point string
		at    int
	}{
		{"created", 1}, {"created", 3}, {"appended", 10}, {"appended", 40}, {"appended", 100}, {"sealed", 1}, {"sealed", 2}, {"sealed", 4}, {"sealed", 9},
		{"dropped", 1}, {"dropped", 30},
	} {
		t.Run(fmt.Sprintf("%s#%d", c.point, c.at), func(t *testing.T) {
			dir, acked, flushed := crash(t, c.point, c.at)
			if len(acked) == 0 && c.point != "created" {
				t.Fatal("the child acknowledged nothing")
			}
			got := readAll(t, dir)
			seen, counted := map[int]bool{}, 0
			for _, r := range got {
				switch r.Provider {
				case "laurel":
					seen[int(r.ProviderSeq)] = true //nolint:gosec // small
				case LossProvider:
					var loss struct{ Dropped int }
					if err := json.Unmarshal(r.Data, &loss); err != nil {
						t.Fatal(err)
					}
					counted += loss.Dropped
				}
			}
			for _, i := range acked {
				if !seen[i] {
					t.Fatalf("acknowledged record %d is gone after the crash", i)
				}
			}
			if counted < flushed {
				t.Fatalf("loss records count %d drops; %d were flushed before the crash", counted, flushed)
			}
		})
	}
}

// A kill between a retirement's index rewrite and its unlink leaves a file below the first line; Open
// removes it and the kept shards read gap-free from the first line.
func TestARetirementSurvivesAKill(t *testing.T) {
	for _, at := range []int{1, 3} {
		t.Run(fmt.Sprint("retired#", at), func(t *testing.T) {
			dir, _, _ := crash(t, "retired", at)
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			seals, err := ReadSeals(t.Context(), dir)
			if err != nil && !errors.Is(err, ErrUnindexed) {
				t.Fatal(err)
			}
			if len(seals) == 0 || seals[0].First == 1 || !slices.ContainsFunc(before, func(e os.DirEntry) bool { return e.Name() < seals[0].Name }) {
				t.Fatalf("no half-done retirement: index from %v, files %v", seals, before)
			}
			got := readAll(t, dir)
			if len(got) == 0 || got[0].Seq != seals[0].First {
				t.Fatalf("records from %v, index from %d", got, seals[0].First)
			}
			after, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range after {
				if shardName.MatchString(e.Name()) && e.Name() < seals[0].Name {
					t.Fatalf("Open left %s below the first line", e.Name())
				}
			}
		})
	}
}
