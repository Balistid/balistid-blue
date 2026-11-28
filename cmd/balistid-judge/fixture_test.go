package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
)

// Markers the exec lines of a fixture carry where Laurel puts arguments, environment, directories and paths:
// none of them may reach the judge's files.
const (
	markArg = "ARGMARK7f3a"
	markEnv = "ENVMARK19c2"
	markCWD = "CWDMARK55d0"
	markDir = "DIRMARK0b6e"
)

// agentExe is a Claude Code binary as it is installed: a file named by its version.
const agentExe = "/home/user/.local/share/claude/versions/2.0.14"

// execSpec is one successful execve as Laurel 0.8.2 writes it.
type execSpec struct {
	serial    uint64
	pid, ppid uint32
	uid       uint32
	exe       string
	proc      string // the process's key object, e.g. "EVENT_ID":"..."
	spawner   string // SPAWNED_BY's key, e.g. "START_TIME":"..."; "" for none
	spawnPID  uint32
	spawnExe  string
	ok        bool // success yes
}

func jsonText(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// eventOf is the exec event id Laurel gives a serial in the fixtures.
func eventOf(serial uint64) string { return fmt.Sprintf("1795340222.%03d:%d", serial%1000, serial) }

// line is e as one Laurel line, with the markers in its arguments, environment, directory and paths.
func (e execSpec) line() []byte {
	success := `"yes","exit":0`
	if !e.ok {
		success = `"no","exit":-2`
	}
	proc := e.proc
	if proc == "" {
		proc = `"EVENT_ID":"` + eventOf(e.serial) + `"`
	}
	spawned := ""
	if e.spawner != "" {
		spawned = fmt.Sprintf(`,"SPAWNED_BY":{%s,"pid":%d,"comm":"x","exe":%s,"pid":%d}`, e.spawner, e.spawnPID,
			jsonText(e.spawnExe), e.spawnPID)
	}
	return fmt.Appendf(nil, `{"ID":"%s","SYSCALL":{"arch":"0xc000003e","syscall":59,"success":%s,"items":2,`+
		`"ppid":%d,"pid":%d,"auid":1000,"uid":%d,"gid":%d,"euid":%d,"tty":"(none)","ses":3,"comm":"c","exe":%s,`+
		`"key":"balistid-exec","ARCH":"x86_64","SYSCALL":"execve","AUID":"u","UID":"u","GID":"u","EUID":"u",`+
		`"ARGV":["0x1","0x2","0x3","0x4"],"PID":{%s},"PPID":{"START_TIME":"1795340216.325"}%s},`+
		`"EXECVE":{"argc":2,"ARGV":[%s,"%s"],"ENV":["SECRET=%s"]},"CWD":{"cwd":"/%s"},`+
		`"PATH":[{"item":0,"name":%s,"inode":1}],"PROCTITLE":{"ARGV":[%s,"%s"]}}`,
		eventOf(e.serial), success, e.ppid, e.pid, e.uid, e.uid, e.uid, jsonText(e.exe), proc, spawned,
		jsonText(e.exe), markArg, markEnv, markCWD, jsonText("/"+markDir+"/x"), jsonText(e.exe), markArg)
}

// otherLine is a record of another syscall under key.
func otherLine(serial uint64, key string) []byte {
	return fmt.Appendf(nil, `{"ID":"%s","SYSCALL":{"arch":"0xc000003e","syscall":257,"success":"yes","exit":3,`+
		`"pid":7,"ppid":1,"uid":0,"exe":"/usr/bin/cat","key":%s,"SYSCALL":"openat","UID":"root",`+
		`"PID":{"START_TIME":"1795340216.325"}}}`, eventOf(serial), jsonText(key))
}

// testStore is a store written through internal/store, as the collector writes one.
type testStore struct {
	t       *testing.T
	dir     string
	st      *store.Store
	noteSeq int
	max     int64
}

func newTestStore(t *testing.T, shardMax int64) *testStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a store directory, as the collector keeps it
		t.Fatal(err)
	}
	ts := &testStore{t: t, dir: dir, max: shardMax}
	ts.open(shardMax)
	return ts
}

func (ts *testStore) open(shardMax int64) {
	ts.t.Helper()
	st, err := store.Open(ts.t.Context(), ts.dir, store.Limits{Cap: 64 << 30, ShardMax: shardMax,
		Headroom: shard.WALMaxBytes + store.LossChunk})
	if err != nil {
		ts.t.Fatal(err)
	}
	ts.st = st
}

// laurel appends one sensor line received now.
func (ts *testStore) laurel(serial uint64, data []byte) {
	ts.laurelAt(serial, time.Now().UnixNano(), data)
}

func (ts *testStore) laurelAt(serial uint64, at int64, data []byte) {
	ts.t.Helper()
	if ok, _, err := ts.st.Append(ts.t.Context(), rawrecord.New(0, store.SensorProvider, serial, at, data)); err != nil || !ok {
		ts.t.Fatalf("append: %v %v", ok, err)
	}
}

// own stores one of the collector's own records as its writer encodes them.
func (ts *testStore) own(kind string, fields map[string]any) {
	ts.t.Helper()
	ts.noteSeq++
	f := map[string]any{"kind": kind, "schema_version": 1, "at": time.Now().UnixNano(), "note_seq": ts.noteSeq}
	for k, v := range fields {
		f[k] = v
	}
	b, err := json.Marshal(f)
	if err != nil {
		ts.t.Fatal(err)
	}
	if err := ts.st.NoteHealth(b); err != nil {
		ts.t.Fatal(err)
	}
	if _, err := ts.st.Flush(ts.t.Context()); err != nil {
		ts.t.Fatal(err)
	}
}

// seal closes the store, sealing its shard, and opens it again unless last.
func (ts *testStore) seal(last bool) {
	ts.t.Helper()
	if _, err := ts.st.Close(ts.t.Context()); err != nil {
		ts.t.Fatal(err)
	}
	if !last {
		ts.open(ts.max)
	}
}

// judgeOnce runs the judge over dir into a new results directory and returns its status and the directory.
func judgeOnce(t *testing.T, storeDir string, now func() time.Time) (string, string, error) {
	t.Helper()
	out := t.TempDir()
	if now == nil {
		now = time.Now
	}
	status, err := judge(t.Context(), config{Store: storeDir, Out: out, Scratch: shard.Scratch{Dir: t.TempDir(), Max: 64 << 20},
		Now: now, Limit: readLimit})
	return status, out, err
}

func readStateDoc(t *testing.T, out string) stateDoc {
	t.Helper()
	b, err := os.ReadFile(out + "/" + stateFile) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	var d stateDoc
	if err := strictDecode(b, &d); err != nil {
		t.Fatalf("state.json: %v", err)
	}
	return d
}

func readExec(t *testing.T, out string) []execRun {
	t.Helper()
	b, err := os.ReadFile(out + "/" + execFile) //nolint:gosec // the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	var runs []execRun
	for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r execRun
		if err := strictDecode(line, &r); err != nil || r.Schema != 1 || !nameAlphabet.MatchString(r.Name) {
			t.Fatalf("exec.jsonl line %q: %v", line, err)
		}
		runs = append(runs, r)
	}
	return runs
}

func names(runs []execRun) string {
	var n []string
	for _, r := range runs {
		n = append(n, r.Name)
	}
	return strings.Join(n, " ")
}

// totalOf is the days added up, as one row.
func totalOf(days []dayRow) dayRow {
	t := dayRow{Records: map[string]uint64{}, evidence: evidence{Loss: map[string]uint64{}, Undecoded: map[string]uint64{}}}
	for _, d := range days {
		for k, v := range d.Records {
			t.Records[k] += v
		}
		for k, v := range d.Loss {
			t.Loss[k] += v
		}
		for k, v := range d.Undecoded {
			t.Undecoded[k] += v
		}
		t.Bytes += d.Bytes
		addExecs(&t.Exec, d.Exec)
		t.LossErrors, t.OwnUnknown = t.LossErrors+d.LossErrors, t.OwnUnknown+d.OwnUnknown
		t.Silences, t.ClockBack = t.Silences+d.Silences, t.ClockBack+d.ClockBack
		if d.StoreLag != nil {
			maxOf(&t.StoreLag, *d.StoreLag)
		}
		if d.ArrivalLag != nil {
			maxOf(&t.ArrivalLag, *d.ArrivalLag)
		}
	}
	return t
}

func addExecs(t *execCounts, x execCounts) {
	t.Successful, t.Listed, t.OverCap, t.Outside = t.Successful+x.Successful, t.Listed+x.Listed, t.OverCap+x.OverCap, t.Outside+x.Outside
	t.Partial, t.System, t.Execveat = t.Partial+x.Partial, t.System+x.System, t.Execveat+x.Execveat
	t.OtherArch, t.Refused = t.OtherArch+x.OtherArch, t.Refused+x.Refused
}

// corrupt flips the last byte of a shard of ts, so its hash is no longer its seal's.
func corrupt(t *testing.T, ts *testStore, name string) {
	t.Helper()
	path := ts.dir + "/" + name
	b, err := os.ReadFile(path) //nolint:gosec // the test's store
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // the test's store
		t.Fatal(err)
	}
}
