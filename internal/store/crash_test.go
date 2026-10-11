package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

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
