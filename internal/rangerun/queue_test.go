package rangerun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const runJSON = `{"schema_version":1,"kind":"run","trials":1}`

func newInbox(t *testing.T) (string, *os.Root) {
	t.Helper()
	dir := inboxDir(t)
	root, err := OpenInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return dir, root
}

func addJob(t *testing.T, inbox, name, request string, mtime time.Time) {
	t.Helper()
	dir := filepath.Join(inbox, name)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "job.json"), []byte(request), 0o640); err != nil { //nolint:gosec // the runner reads jobs through its group
		t.Fatal(err)
	}
	if err := os.Chtimes(dir, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestNextTakesEachJobOnceInNameOrder(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	addJob(t, dir, "b", `{"schema_version":1,"kind":"run","trials":2}`, now)
	addJob(t, dir, "a", runJSON, now)
	var l Ledger
	for _, want := range []string{"a", "b"} {
		if job, ok, _, err := Next(inbox, &l, now); err != nil || !ok || job.Name != want {
			t.Fatalf("Next = %q %v %v, want %q", job.Name, ok, err, want)
		}
	}
	if job, ok, _, err := Next(inbox, &l, now.Add(time.Hour)); ok || err != nil {
		t.Fatalf("a job was taken twice: %q %v", job.Name, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatalf("the inbox changed: %v %v", entries, err)
	}
}

// Times and inodes are the agent's to set; a job is its name and content.
func TestTheSameJobRunsOnceAndAnotherNameRunsAgain(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	addJob(t, dir, "j", runJSON, now.Add(48*time.Hour))
	var l Ledger
	if _, ok, _, err := Next(inbox, &l, now); !ok || err != nil {
		t.Fatalf("first job not taken: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "j")); err != nil {
		t.Fatal(err)
	}
	addJob(t, dir, "j", runJSON, now.Add(-72*time.Hour))
	if job, ok, _, err := Next(inbox, &l, now.Add(time.Hour)); ok || err != nil {
		t.Fatalf("the same name and content ran again: %q %v", job.Name, err)
	}
	addJob(t, dir, "k", runJSON, now)
	if job, ok, _, err := Next(inbox, &l, now.Add(time.Hour)); err != nil || !ok || job.Name != "k" {
		t.Fatalf("the same request under another name did not run: %q %v %v", job.Name, ok, err)
	}
}

// Expiry runs on the runner's clock from when it first saw the directory.
func TestExpiryUsesTheRunnersClock(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	var l Ledger
	l.Entries = make([]Entry, Quota) // the quota is full, so the job waits
	for i := range l.Entries {
		l.Entries[i] = Entry{Key: string(rune('a' + i)), Seen: now, Status: Taken}
	}
	addJob(t, dir, "waits", runJSON, now.Add(10*24*time.Hour))
	if _, ok, _, err := Next(inbox, &l, now); ok || err != nil {
		t.Fatalf("a job was taken over the quota: %v", err)
	}
	if _, ok, _, err := Next(inbox, &l, now.Add(Expiry)); ok || err != nil {
		t.Fatalf("a job past its expiry on the runner's clock was taken: %v", err)
	}
	if len(l.Clock) != 1 {
		t.Fatalf("clock holds %d directories, want the one in the inbox", len(l.Clock))
	}
	if err := os.RemoveAll(filepath.Join(dir, "waits")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Next(inbox, &l, now.Add(Expiry)); err != nil {
		t.Fatal(err)
	}
	if len(l.Clock) != 0 {
		t.Fatal("the clock kept a directory that left the inbox")
	}
}

// A full inbox does not stop the runner: what the quota cannot reach in a day expires, and a new
// job is taken in the next window.
func TestALargeInboxExpiresAndTheRunnerGoesOn(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	for i := range 41 {
		addJob(t, dir, fmt.Sprintf("j%02d", 40-i), runJSON, now)
	}
	var l Ledger
	var taken []string
	for i := range 41 {
		job, ok, _, err := Next(inbox, &l, now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			taken = append(taken, job.Name)
		}
	}
	if len(taken) != Quota || taken[0] != "j00" {
		t.Fatalf("took %v, want the first %d in name order", taken, Quota)
	}
	later := now.Add(QuotaWindow)
	addJob(t, dir, "new", runJSON, now)
	if job, ok, _, err := Next(inbox, &l, later); err != nil || !ok || job.Name != "new" {
		t.Fatalf("after a window the new job was not taken: %q %v %v", job.Name, ok, err)
	}
}

func TestBrokenJobsCountAgainstTheQuotaOnce(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	for i := range Quota + 2 {
		addJob(t, dir, string(rune('a'+i)), `{}`, now)
	}
	var l Ledger
	for range 3 {
		if _, _, _, err := Next(inbox, &l, now); err != nil {
			t.Fatal(err)
		}
	}
	if got := l.used(now); got != Quota {
		t.Fatalf("used %d of the quota, want exactly %d", got, Quota)
	}
	later := now.Add(QuotaWindow)
	addJob(t, dir, "z", runJSON, later)
	if job, ok, _, err := Next(inbox, &l, later); err != nil || !ok || job.Name != "z" {
		t.Fatalf("the quota did not reopen after its window: %q %v %v", job.Name, ok, err)
	}
}

// An inbox that cannot be listed is an error, not an empty inbox, and it keeps the clock.
func TestNextReportsAnInboxItCannotList(t *testing.T) {
	now := time.Now()
	dir, inbox := newInbox(t)
	addJob(t, dir, "j", runJSON, now)
	l := Ledger{Entries: make([]Entry, Quota)} // the quota is full, so the job is only clocked
	for i := range l.Entries {
		l.Entries[i] = Entry{Key: fmt.Sprintf("taken:x%d", i), Seen: now, Status: Taken}
	}
	if _, _, _, err := Next(inbox, &l, now); err != nil || len(l.Clock) != 1 {
		t.Fatalf("Next = %v with %d clock times, want the job clocked", err, len(l.Clock))
	}
	clock := maps.Clone(l.Clock)
	if err := inbox.Close(); err != nil {
		t.Fatal(err)
	}
	if job, ok, _, err := Next(inbox, &l, now.Add(time.Hour)); err == nil || ok {
		t.Fatalf("Next on an inbox it cannot list = %q %v %v, want an error", job.Name, ok, err)
	}
	if !maps.Equal(l.Clock, clock) {
		t.Fatal("a failed listing changed the clock")
	}
}

// inboxDir makes a directory as the install does: mode 2750 in this process's group.
func inboxDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "inbox")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, inboxMode); err != nil {
		t.Fatal(err)
	}
	return dir
}

// aclGranting is a POSIX ACL in the kernel's xattr form that gives uid rwx past a group mask of r-x.
func aclGranting(uid int) []byte {
	type entry struct {
		tag, perm uint16
		id        uint32
	}
	none := ^uint32(0)
	b := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range []entry{{0x01, 7, none}, {0x02, 7, uint32(uid)}, {0x04, 5, none}, {0x10, 5, none}, {0x20, 0, none}} { //nolint:gosec // a Linux uid is 32 bits
		b = binary.LittleEndian.AppendUint16(b, e.tag)
		b = binary.LittleEndian.AppendUint16(b, e.perm)
		b = binary.LittleEndian.AppendUint32(b, e.id)
	}
	return b
}

// T35: an ACL lets a named user past mode 2750 (the group bits are then only the mask), so an inbox
// with either ACL gives no jobs.
func TestOpenInboxRefusesAnACL(t *testing.T) {
	for _, name := range inboxACLs {
		dir := inboxDir(t)
		if err := syscall.Setxattr(dir, name, aclGranting(os.Getuid()), 0); errors.Is(err, syscall.ENOTSUP) {
			t.Skip("this file system has no ACLs")
		} else if err != nil {
			t.Fatal(err)
		}
		if root, err := OpenInbox(dir); err == nil {
			_ = root.Close()
			t.Errorf("inbox with %s was opened", name)
		}
	}
}

// T35: an inbox others could write gives no jobs.
func TestOpenInboxRefusesALooseInbox(t *testing.T) {
	g := os.ModeSetgid
	for _, mode := range []os.FileMode{0o750, g | 0o770, g | 0o757, g | 0o755, g | os.ModeSticky | 0o750, g | 0o700} {
		dir := inboxDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if root, err := OpenInbox(dir); err == nil {
			_ = root.Close()
			t.Errorf("inbox with mode %o was opened", mode)
		}
	}
}

func TestOpenInboxRefusesALink(t *testing.T) {
	real := inboxDir(t)
	link := filepath.Join(t.TempDir(), "inbox")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if root, err := OpenInbox(link); err == nil {
		_ = root.Close()
		t.Fatal("a symlinked inbox was opened")
	}
}

func TestTheLedgerStaysBounded(t *testing.T) {
	now := time.Now()
	var l Ledger
	for i := range MaxLedger + 50 {
		l.add(string(rune(i)), now, Taken)
	}
	l.prune(now)
	if len(l.Entries) > MaxLedger {
		t.Fatalf("ledger has %d entries", len(l.Entries))
	}
	l = Ledger{Entries: []Entry{{Key: "old", Seen: now.Add(-keepTaken), Status: Taken}}}
	l.prune(now)
	if len(l.Entries) != 0 {
		t.Fatal("a taken job outlived keepTaken")
	}
}
