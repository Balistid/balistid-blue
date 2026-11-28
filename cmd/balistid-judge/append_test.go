package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// TestAFailedShardAppendsNothing: the newer shards' runs stay in exec.jsonl, the failed shard adds none.
func TestAFailedShardAppendsNothing(t *testing.T) {
	ts := threeShards(t)
	oldest := filepath.Join(ts.dir, readStateDocOf(t, ts).Read[3].Name)
	b, err := os.ReadFile(oldest) //nolint:gosec // the test's store
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.Chmod(oldest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldest, b, 0o600); err != nil { //nolint:gosec // the test's store
		t.Fatal(err)
	}
	status, out, err := judgeOnce(t, ts.dir, nil)
	if d := readStateDoc(t, out); status != statusUnknown || err == nil || len(d.Read) != 3 || len(d.NotRead) != 1 {
		t.Fatalf("status %s, read %v, not read %v, %v", status, d.Read, d.NotRead, err)
	}
	if got := names(readExec(t, out)); got != "tool-c" {
		t.Errorf("exec.jsonl %q, want only the shards read whole", got)
	}
}

// TestASealTimeOutOfRangeIsUnknown: a last seal whose time has no nanoseconds in an int64 is UNKNOWN, never a
// wrapped date to count the 7 days from.
func TestASealTimeOutOfRangeIsUnknown(t *testing.T) {
	ts := threeShards(t)
	index := filepath.Join(ts.dir, "seals")
	b, err := os.ReadFile(index) //nolint:gosec // the test's store
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	last := strings.Fields(lines[len(lines)-1])
	last[4] = "9223372036854775807"
	lines[len(lines)-1] = strings.Join(last, " ")
	if err := os.WriteFile(index, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil { //nolint:gosec // the test's store
		t.Fatal(err)
	}
	status, out, err := judgeOnce(t, ts.dir, nil)
	d := readStateDoc(t, out)
	if status != statusUnknown || err == nil || d.Status != statusUnknown || !strings.Contains(d.Reason, "last seal's time") {
		t.Errorf("status %s %q, %v", status, d.Reason, err)
	}
}

// TestUnlistedExecsAreCounted: execveat, a 32-bit execve and an exec the strict reading refuses are not listed and
// not lost: state.json counts each.
func TestUnlistedExecsAreCounted(t *testing.T) {
	ts := newTestStore(t, 16<<20)
	ts.laurel(1, tool(1, 1000, "listed"))
	ts.laurel(2, bytes.Replace(bytes.Replace(tool(2, 1000, "at"), []byte(`"syscall":59`), []byte(`"syscall":322`), 1),
		[]byte(`"SYSCALL":"execve"`), []byte(`"SYSCALL":"execveat"`), 1))
	ts.laurel(3, bytes.Replace(bytes.Replace(tool(3, 1000, "i386"), []byte(`"syscall":59`), []byte(`"syscall":11`), 1),
		[]byte(`"arch":"0xc000003e"`), []byte(`"arch":"0x40000003"`), 1))
	ts.laurel(4, bytes.Replace(tool(4, 1000, "twice"), []byte(`"uid":1000,`), []byte(`"uid":1000,"uid":0,`), 1))
	ts.seal(true)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := readStateDoc(t, out)
	if d.Exec.Successful != 1 || d.Exec.Execveat != 1 || d.Exec.OtherArch != 1 || d.Undecoded[refusedKeys] != 1 {
		t.Errorf("exec %+v, undecoded %v", d.Exec, d.Undecoded)
	}
	if got := names(readExec(t, out)); got != "listed" {
		t.Errorf("exec.jsonl %q", got)
	}
}

// TestALossReachesIntoTheOlderShard: a lost record at the start of a shard whose first_at is before the older
// shard's last own record starts its span at first_at, so the time it lost records is not clean.
func TestALossReachesIntoTheOlderShard(t *testing.T) {
	sec := int64(time.Second)
	older := accOf(t, own(store.HealthProvider, 10*sec, `{"schema_version":1,"kind":"health","state":"OK"}`),
		rawrecord.New(0, store.SensorProvider, 1, 50*sec, otherLine(1, "k")),
		own(store.HealthProvider, 100*sec, `{"schema_version":1,"kind":"stats","max_lag_ms":1}`))
	newer := accOf(t, own(store.HealthProvider, 110*sec, `{"schema_version":1,"kind":"lost","stage":"queue","count":1,`+
		`"bytes":0,"first_seq":0,"last_seq":0,"first_at":70000000000,"last_at":70000000000,"at":3,"note_seq":2}`),
		rawrecord.New(0, store.SensorProvider, 2, 111*sec, otherLine(2, "k")))
	st := newState([]store.Seal{{Name: "older"}, {Name: "newer"}}, 0, 0, 90)
	st.merge("newer", newer)
	st.merge("older", older)
	d := st.render(0)
	for _, iv := range d.Clean.Intervals {
		if iv.From < timeText(100*sec) && iv.To > timeText(70*sec) {
			t.Errorf("clean %s to %s covers the loss from 70 s", iv.From, iv.To)
		}
	}
	if len(d.Clean.Intervals) != 2 || d.Clean.Intervals[0].To != timeText(70*sec) {
		t.Errorf("clean %+v", d.Clean.Intervals)
	}
}
