package rangerun

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func sampleLedger(now time.Time) Ledger {
	return Ledger{
		Entries: []Entry{
			{Key: "taken:a:" + strings.Repeat("0", 64), Seen: now.Add(-time.Hour), Status: Taken},
			{Key: "rejected:b", Seen: now, Status: Rejected},
		},
		Clock:    map[string]time.Time{"a:2049:12": now.Add(-time.Hour), "b:2049:13": now},
		Evidence: Evidence{Commit: strings.Repeat("c", 40), LastPass: now, Failed: []FailedRun{{Commit: strings.Repeat("d", 40), ID: "20261006T090000Z-0000000f"}}},
	}
}

// sameLedger compares instants, not locations: LoadLedger returns UTC.
func sameLedger(a, b Ledger) bool {
	if len(a.Entries) != len(b.Entries) || len(a.Clock) != len(b.Clock) ||
		a.Evidence.Commit != b.Evidence.Commit || !slices.Equal(a.Evidence.Failed, b.Evidence.Failed) || !a.Evidence.LastPass.Equal(b.Evidence.LastPass) {
		return false
	}
	for i, e := range a.Entries {
		f := b.Entries[i]
		if e.Key != f.Key || e.Status != f.Status || !e.Seen.Equal(f.Seen) {
			return false
		}
	}
	for id, t := range a.Clock {
		if u, ok := b.Clock[id]; !ok || !t.Equal(u) {
			return false
		}
	}
	return true
}

func ledgerPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "ledger.json")
}

func writeRaw(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func wantCorrupt(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrCorruptLedger) || errors.Is(err, ErrNoLedger) {
		t.Fatalf("error %v, want ErrCorruptLedger and not ErrNoLedger", err)
	}
}

func TestLedgerRoundTripIsPrivate(t *testing.T) {
	path := ledgerPath(t)
	want := sampleLedger(time.Now())
	if err := SaveLedger(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameLedger(got, want) {
		t.Fatalf("loaded %+v, saved %+v", got, want)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
}

func TestLoadLedgerTellsMissingFromCorrupt(t *testing.T) {
	_, err := LoadLedger(ledgerPath(t))
	if !errors.Is(err, ErrNoLedger) || !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrCorruptLedger) {
		t.Fatalf("missing ledger gave %v, want ErrNoLedger only", err)
	}
}

func TestLoadLedgerRefusesCorrupt(t *testing.T) {
	const seen = `"2026-10-06T10:00:00Z"`
	entry := func(key, status, seen string) string {
		return `{"key":"` + key + `","seen":` + seen + `,"status":"` + status + `"}`
	}
	ledger := func(entries, clock string) string {
		return `{"schema_version":2,"entries":[` + entries + `],"clock":{` + clock + `},"evidence":{"commit":"","last_pass":"0001-01-01T00:00:00Z","failed":[]}}`
	}
	many := func(n int, f func(int) string) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = f(i)
		}
		return strings.Join(parts, ",")
	}
	valid := ledger(entry("zzmarker", Taken, seen), `"zzmarker:1:2":`+seen)
	for name, data := range map[string]string{
		"empty file":             ``,
		"truncated":              valid[:len(valid)-3],
		"top-level array":        `[` + valid + `]`,
		"top-level null":         `null`,
		"unknown field":          strings.Replace(valid, `"clock"`, `"zzmarker":1,"clock"`, 1),
		"unknown entry field":    strings.Replace(valid, `"status"`, `"zzmarker":1,"status"`, 1),
		"trailing data":          valid + `zzmarker`,
		"second object":          valid + valid,
		"schema_version 1":       strings.Replace(valid, `"schema_version":2`, `"schema_version":1`, 1),
		"schema_version 3":       strings.Replace(valid, `"schema_version":2`, `"schema_version":3`, 1),
		"schema_version string":  strings.Replace(valid, `"schema_version":2`, `"schema_version":"2"`, 1),
		"schema_version float":   strings.Replace(valid, `"schema_version":2`, `"schema_version":2.0`, 1),
		"schema_version absent":  strings.Replace(valid, `"schema_version":2,`, ``, 1),
		"entries absent":         `{"schema_version":2,"clock":{}}`,
		"clock null":             `{"schema_version":2,"entries":[],"clock":null}`,
		"bad status":             ledger(entry("zzmarker", "zzmarker", seen), ``),
		"status absent":          ledger(`{"key":"zzmarker","seen":`+seen+`}`, ``),
		"empty key":              ledger(entry("", Taken, seen), ``),
		"key too long":           ledger(entry(strings.Repeat("z", maxKeyBytes+1), Taken, seen), ``),
		"key not in alphabet":    ledger(entry("zzmarker\\u00ff", Taken, seen), ``),
		"zero seen":              ledger(entry("zzmarker", Taken, `"0001-01-01T00:00:00Z"`), ``),
		"seen absent":            ledger(`{"key":"zzmarker","status":"taken"}`, ``),
		"seen not a time":        ledger(entry("zzmarker", Taken, `"zzmarker"`), ``),
		"empty clock key":        ledger(``, `"":`+seen),
		"clock key upper case":   ledger(``, `"ZZMARKER:1:2":`+seen),
		"zero clock time":        ledger(``, `"zzmarker:1:2":"0001-01-01T00:00:00Z"`),
		"seen before 1970":       ledger(entry("zzmarker", Taken, `"1969-12-31T23:59:59Z"`), ``),
		"clock past 9999 in UTC": ledger(``, `"zzmarker:1:2":"9999-12-31T23:59:59-23:59"`),
		"too many entries": ledger(many(MaxLedger+1, func(i int) string {
			return entry(fmt.Sprintf("taken:zzmarker%d", i), Taken, seen)
		}), ``),
		"too many clock times": ledger(``, many(MaxInboxEntries+1, func(i int) string {
			return fmt.Sprintf(`"zzmarker%d:1:2":%s`, i, seen)
		})),
		"oversize":                   valid + strings.Repeat(" ", MaxLedgerBytes),
		"evidence absent":            strings.Replace(valid, `,`+`"evidence":{"commit":"","last_pass":"0001-01-01T00:00:00Z","failed":[]}`, ``, 1),
		"evidence time, no commit":   strings.Replace(valid, `"last_pass":"0001-01-01T00:00:00Z"`, `"last_pass":`+seen, 1),
		"failed not a list":          strings.Replace(valid, `"failed":[]`, `"failed":"20261006T090000Z-00000001"`, 1),
		"failed null":                strings.Replace(valid, `"failed":[]`, `"failed":null`, 1),
		"evidence commit upper case": strings.Replace(valid, `"commit":"","last_pass":"0001-01-01T00:00:00Z"`, `"commit":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","last_pass":`+seen, 1),
		"evidence commit, zero time": strings.Replace(valid, `"commit":""`, `"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, 1),
		"evidence failed malformed":  strings.Replace(valid, `"failed":[]`, `"failed":[{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","id":"zzmarker"}]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := ledgerPath(t)
			writeRaw(t, path, data)
			l, err := LoadLedger(path)
			wantCorrupt(t, err)
			if strings.Contains(strings.ToLower(err.Error()), "zzmarker") {
				t.Fatalf("error quotes the file: %v", err)
			}
			if l.Entries != nil || l.Clock != nil {
				t.Fatalf("a refused ledger came back with content: %+v", l)
			}
		})
	}
	t.Run("the valid base is accepted", func(t *testing.T) {
		path := ledgerPath(t)
		writeRaw(t, path, valid+"\n")
		if _, err := LoadLedger(path); err != nil {
			t.Fatalf("the table's valid ledger was refused: %v", err)
		}
	})
}

// The runner's state directory is its own, but a link, FIFO or directory at the ledger's name is
// refused unopened or unread, never followed and never waited on.
func TestLoadLedgerRefusesWhatIsNotARegularFile(t *testing.T) {
	good := ledgerPath(t)
	if err := SaveLedger(good, sampleLedger(time.Now())); err != nil {
		t.Fatal(err)
	}
	for name, create := range map[string]func(path string) error{
		"symlink to a valid ledger": func(path string) error { return os.Symlink(good, path) },
		"dangling symlink":          func(path string) error { return os.Symlink(path+".gone", path) },
		"directory":                 func(path string) error { return os.Mkdir(path, 0o700) },
		"fifo":                      func(path string) error { return syscall.Mkfifo(path, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			path := ledgerPath(t)
			if err := create(path); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := LoadLedger(path)
				done <- err
			}()
			select {
			case err := <-done:
				wantCorrupt(t, err)
			case <-time.After(10 * time.Second):
				t.Fatal("LoadLedger blocked")
			}
		})
	}
}

// snapshot is what is at path, without following a link.
func snapshot(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		return "link:" + target
	case fi.IsDir():
		return "dir"
	default:
		data, err := os.ReadFile(path) //nolint:gosec // a test file
		if err != nil {
			t.Fatal(err)
		}
		return "file:" + string(data)
	}
}

func TestSaveLedgerRefusesWhatLoadRefuses(t *testing.T) {
	now := time.Now()
	full := func(n int) []Entry {
		entries := make([]Entry, n)
		for i := range entries {
			entries[i] = Entry{Key: fmt.Sprintf("taken:j%d", i), Seen: now, Status: Taken}
		}
		return entries
	}
	clock := make(map[string]time.Time, MaxInboxEntries+1)
	for i := range MaxInboxEntries + 1 {
		clock[fmt.Sprintf("j%d:1:2", i)] = now
	}
	for name, l := range map[string]Ledger{
		"too many entries":          {Entries: full(MaxLedger + 1)},
		"too many clock times":      {Clock: clock},
		"bad status":                {Entries: []Entry{{Key: "taken:j", Seen: now, Status: "done"}}},
		"empty key":                 {Entries: []Entry{{Key: "", Seen: now, Status: Taken}}},
		"key not in alphabet":       {Entries: []Entry{{Key: "rejected:\xff", Seen: now, Status: Rejected}}},
		"zero seen":                 {Entries: []Entry{{Key: "taken:j", Status: Taken}}},
		"zero clock time":           {Clock: map[string]time.Time{"j:1:2": {}}},
		"year past 9999":            {Entries: []Entry{{Key: "taken:j", Seen: now.AddDate(8000, 0, 0), Status: Taken}}},
		"evidence of no commit":     {Evidence: Evidence{LastPass: now}},
		"evidence of a non-commit":  {Evidence: Evidence{Commit: "dev", LastPass: now}},
		"too many failed runs":      {Evidence: Evidence{Failed: make([]FailedRun, MaxFailed+1)}},
		"pending not a result name": {Evidence: Evidence{Pending: "../x", Failed: []FailedRun{}}},
	} {
		t.Run(name, func(t *testing.T) {
			path := ledgerPath(t)
			if err := SaveLedger(path, sampleLedger(now)); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, path)
			if err := SaveLedger(path, l); err == nil {
				t.Fatal("SaveLedger wrote a ledger LoadLedger refuses")
			}
			if snapshot(t, path) != before {
				t.Fatal("a refused save changed the old ledger")
			}
			if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
				t.Fatalf("directory holds %v %v, want no temp file left", entries, err)
			}
		})
	}
}

// A ledger at every cap, with keys as long as the validator allows, still fits MaxLedgerBytes, so
// no ledger Next can make is refused by SaveLedger.
func TestAFullLedgerFitsTheFile(t *testing.T) {
	now := time.Date(2026, 10, 6, 23, 59, 59, 999999999, time.UTC)
	long := func(prefix string, i int) string {
		s := fmt.Sprintf("%s%d:", prefix, i)
		return s + strings.Repeat("9", maxKeyBytes-len(s))
	}
	l := Ledger{Clock: map[string]time.Time{}}
	for i := range MaxLedger {
		l.Entries = append(l.Entries, Entry{Key: long("rejected:", i), Seen: now, Status: Rejected})
	}
	for i := range MaxInboxEntries {
		l.Clock[long("c", i)] = now
	}
	path := ledgerPath(t)
	if err := SaveLedger(path, l); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("a full ledger is %d bytes", st.Size())
	got, err := LoadLedger(path)
	if err != nil || !sameLedger(got, l) {
		t.Fatalf("a full ledger did not come back: %v", err)
	}
}

// Whatever names the inbox lists, the ledger Next makes is one SaveLedger writes and LoadLedger
// gives back unchanged, so a restart neither rejects a job again nor restarts its expiry.
func TestALedgerFromAnyInboxSurvivesTheDisk(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	addJob(t, dir, "good", runJSON, now)
	addJob(t, dir, "good-job", runJSON, now) // a dash: valid job name, outside the key alphabet
	for _, name := range []string{"Upper", "bad\xff\xfename", "ctl\x01\x1b[31m", "<&>", strings.Repeat("\x7f", 255), "x:1:2"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	var l Ledger
	for {
		_, ok, err := Next(inbox, &l, now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
	}
	if len(l.Entries) != 8 || len(l.Clock) != 8 {
		t.Fatalf("Next recorded %d entries and %d clock times, want 8 of each", len(l.Entries), len(l.Clock))
	}
	path := ledgerPath(t)
	if err := SaveLedger(path, l); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameLedger(loaded, l) {
		t.Fatalf("the ledger changed on disk:\nsaved  %+v\nloaded %+v", l, loaded)
	}
	if _, ok, err := Next(inbox, &loaded, now.Add(time.Minute)); ok || err != nil {
		t.Fatalf("after a reload Next took a job again: %v %v", ok, err)
	}
	if !sameLedger(loaded, l) {
		t.Fatal("after a reload Next rejected a job again or restarted a clock")
	}
}

func FuzzLoadLedger(f *testing.F) {
	for _, s := range []string{
		`{"schema_version":2,"entries":[],"clock":{},"evidence":{"commit":"","last_pass":"0001-01-01T00:00:00Z","failed":[]}}`,
		`{"schema_version":2,"entries":[{"key":"taken:a:00","seen":"2026-10-06T10:00:00.5+02:00","status":"taken"}],"clock":{"a:1:2":"2026-10-06T10:00:00Z"},"evidence":{"commit":"","last_pass":"0001-01-01T00:00:00Z","failed":[]}}`,
		`{"schema_version":2,"entries":[{"key":"rejected:ab","seen":"2026-10-06T10:00:00Z","status":"rejected"}],"clock":{}} `,
		`{"schema_version":2,"entries":[],"clock":{}}{}`,
		`{"schema_version":2,"Entries":[],"CLOCK":{},"entries":null}`,
		`{"schema_version":2,"entries":[],"clock":{}}`,
		`{"schema_version":2,"entries":[{"key":"a","seen":"0000-01-01T00:00:00Z","status":"taken"}],"clock":{"a":"9999-12-31T23:59:59.999999999-23:59"}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "in.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := LoadLedger(path)
		if err != nil {
			if !errors.Is(err, ErrCorruptLedger) {
				t.Fatalf("a file that exists gave %v, want ErrCorruptLedger", err)
			}
			return
		}
		again := filepath.Join(dir, "again.json")
		if err := SaveLedger(again, l); err != nil {
			t.Fatalf("LoadLedger accepted %q, SaveLedger refused it: %v", data, err)
		}
		got, err := LoadLedger(again)
		if err != nil || !sameLedger(got, l) {
			t.Fatalf("accepted %q, but Save and Load gave %+v, %v", data, got, err)
		}
	})
}
