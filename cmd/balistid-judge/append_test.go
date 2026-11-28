package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAFailedShardAppendsNothing: the older shards' runs stay in exec.jsonl, the failed shard adds none.
func TestAFailedShardAppendsNothing(t *testing.T) {
	ts := threeShards(t)
	corrupt(t, ts, readStateDocOf(t, ts).Read[2].Name)
	status, out, err := judgeOnce(t, ts.dir, nil)
	if d := readStateDoc(t, out); status != statusUnknown || err == nil || len(d.Read) != 2 || len(d.NotRead) != 2 {
		t.Fatalf("status %s, read %v, not read %v, %v", status, d.Read, d.NotRead, err)
	}
	if got := names(readExec(t, out)); got != "tool-a" {
		t.Errorf("exec.jsonl %q, want only the shards read whole", got)
	}
}

// TestASealTimeOutOfRangeIsUnknown: a seal whose time has no nanoseconds in an int64 is UNKNOWN, never a wrapped
// date to count the days from.
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
	if status != statusUnknown || err == nil || d.Status != statusUnknown || !strings.Contains(d.Reason, "the time of seal") {
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
	ts.laurel(5, bytes.Replace(tool(5, 1000, "noid"), []byte(`{"ID":"`+eventOf(5)+`",`), []byte(`{`), 1))
	ts.seal(true)
	_, out, err := judgeOnce(t, ts.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := totalOf(readStateDoc(t, out).Days).Exec
	if e.Successful != 2 || e.Partial != 1 || e.Execveat != 1 || e.OtherArch != 1 || e.Refused != 1 {
		t.Errorf("exec %+v", e)
	}
	if got := names(readExec(t, out)); got != "listed" {
		t.Errorf("exec.jsonl %q", got)
	}
}

// TestATornSealIndexIsPartial: an index that ends in a line without its newline may lack a seal, so the read of
// every shard it lists is PARTIAL, never COMPLETE.
func TestATornSealIndexIsPartial(t *testing.T) {
	ts := threeShards(t)
	f, err := os.OpenFile(filepath.Join(ts.dir, "seals"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("0000000000000000099.db 99"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	status, out, err := judgeOnce(t, ts.dir, nil)
	if d := readStateDoc(t, out); status != statusPartial || err == nil || d.Status != statusPartial || !d.TornIndex ||
		len(d.Read) != 4 {
		t.Errorf("status %s, on disk %s %q, torn %v, read %d, %v", status, d.Status, d.Reason, d.TornIndex, len(d.Read), err)
	}
}
