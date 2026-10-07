// Package rangerun is the range runner of ADR 0011. It runs as its own user and reads agents'
// jobs from an inbox it never changes: what it has looked at, and every limit, lives in its state.
package rangerun

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Limits of the inbox (ADR 0011, point 5). Agents share one uid and own the inbox: each removes
// its job once it has read the result, and one agent filling the inbox can delay the others' jobs,
// which is accepted (agent jobs are never evidence) and only bounded here.
const (
	MaxInboxEntries = 1024                // names listed per scan, then taken in name order
	Expiry          = 24 * time.Hour      // after the runner first saw the directory
	Quota           = 8                   // agent jobs taken or rejected per QuotaWindow
	QuotaWindow     = 24 * time.Hour      //
	MaxLedger       = 256                 // entries kept; the oldest go first (R5)
	keepTaken       = 30 * 24 * time.Hour //
)

// Ledger statuses.
const (
	Taken    = "taken"
	Rejected = "rejected"
)

// Entry is a job the runner has read: a taken one is known by its name and the sha256 of what was
// read, so it runs once per name within 30 days while the same request may run under another name.
type Entry struct {
	Key    string    `json:"key"`
	Seen   time.Time `json:"seen"`
	Status string    `json:"status"`
}

// Ledger is the runner's record of the inbox, kept in its state. Clock holds, for each job
// directory now in the inbox (name, device, inode), when its continuous presence began: expiry runs
// on the runner's clock, not on times the agent sets, and restarts after any scan that did not list
// the directory, which is no more than resubmitting it. Agents build a job outside the inbox and
// rename it in, since a half-written job is rejected.
type Ledger struct {
	Entries  []Entry
	Clock    map[string]time.Time
	Evidence Evidence
}

// Evidence is the runner's record of its own evidence runs (ADR 0011, point 7): the commit and
// time of the last PASS, and every evidence FAIL, which fails its commit for good and whose result
// outlives retention; at MaxFailed of them the runner stops until the maintainer reviews the ledger.
type Evidence struct {
	Commit   string      `json:"commit"`
	LastPass time.Time   `json:"last_pass"`
	Failed   []FailedRun `json:"failed"`
	Pending  string      `json:"pending"` // the evidence run under way, until its verdict is in the ledger
	// Due latches once evidence falls due and only a PASS clears it, so a clock set back cannot.
	Due bool `json:"due"`
}

// FailedRun is an evidence FAIL: the commit and the id of its result.
type FailedRun struct {
	Commit string `json:"commit"`
	ID     string `json:"id"`
}

// MaxFailed caps the failed evidence runs the ledger keeps (R5).
const MaxFailed = 16

// inboxMode is the inbox of ADR 0011 point 5: the maintainer writes it, the runner's group only reads
// it (setgid keeps new job directories in that group), nobody else gets in.
const inboxMode = os.ModeDir | os.ModeSetgid | 0o750

// OpenInbox opens path as the inbox only if it is a directory, not a link to one, with mode 2750 and
// the runner's group: a looser inbox would take jobs from users other than the maintainer.
func OpenInbox(path string) (*os.Root, error) {
	want, err := os.Lstat(path)
	if err != nil || !want.IsDir() {
		return nil, errors.New("inbox is not a plain directory")
	}
	gid := -1
	if st, ok := want.Sys().(*syscall.Stat_t); ok {
		gid = int(st.Gid)
	}
	if want.Mode() != inboxMode || gid != os.Getegid() {
		return nil, fmt.Errorf("inbox is %v group %d, not %v group %d", want.Mode(), gid, inboxMode, os.Getegid())
	}
	inbox, err := os.OpenRoot(path + "/.")
	if err != nil {
		return nil, errors.New("cannot open the inbox")
	}
	if got, err := inbox.Stat("."); err != nil || !os.SameFile(want, got) {
		_ = inbox.Close()
		return nil, errors.New("inbox changed while it was opened")
	}
	return inbox, nil
}

// Rejection is a job Next rejected and recorded in this call: its name, which is the agent's
// bytes, and why ReadJob refused it.
type Rejection struct {
	Name, Reason string
}

// Next returns and records the first job, in name order, not expired and not taken by name and
// content; false when none is left or the quota is used up, an error when the inbox cannot be
// listed. A job that fails to read is rejected once and counts against the quota; the rejections
// this call recorded come back for the caller to log. Next changes l whatever it returns, so the
// caller saves l after every call and before it runs the job.
func Next(inbox *os.Root, l *Ledger, now time.Time) (rangejob.Job, bool, []Rejection, error) {
	l.prune(now)
	names, err := readNames(inbox)
	if err != nil {
		return rangejob.Job{}, false, nil, err // keep the clock: a failed listing must not restart expiry
	}
	slices.Sort(names)
	clock := map[string]time.Time{}
	var live []string
	for _, name := range names {
		fi, err := inbox.Lstat(name)
		if err != nil || !fi.IsDir() {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		id := fmt.Sprintf("%s:%d:%d", nameKey(name), st.Dev, st.Ino)
		first, seen := l.Clock[id]
		if !seen {
			first = now
		}
		clock[id] = first
		if now.Sub(first) < Expiry {
			live = append(live, name)
		}
	}
	l.Clock = clock
	var rejected []Rejection
	for _, name := range live {
		if l.used(now) >= Quota {
			return rangejob.Job{}, false, rejected, nil
		}
		job, err := rangejob.ReadJob(inbox, name)
		if err != nil {
			if key := "rejected:" + nameKey(name); !l.has(key) {
				l.add(key, now, Rejected)
				rejected = append(rejected, Rejection{Name: name, Reason: err.Error()})
			}
			continue
		}
		if key := "taken:" + nameKey(name) + ":" + ContentKey(job); !l.has(key) {
			l.add(key, now, Taken)
			return job, true, rejected, nil
		}
	}
	return rangejob.Job{}, false, rejected, nil
}

// nameKey is the sha256 of an inbox name: any name the file system allows becomes a key that
// JSON keeps byte for byte and that has a fixed length.
func nameKey(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// ContentKey is the sha256 of a job's request and program, each length-prefixed so no split of
// the bytes between them gives the same key.
func ContentKey(job rangejob.Job) string {
	request, _ := json.Marshal(job.Request) // ints and strings always encode
	h := sha256.New()
	for _, part := range [][]byte{request, job.Program} {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(part))))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readNames(inbox *os.Root) ([]string, error) {
	f, err := inbox.Open(".")
	if err != nil {
		return nil, fmt.Errorf("cannot list the inbox: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	names, err := f.Readdirnames(MaxInboxEntries)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("cannot list the inbox: %w", err)
	}
	return names, nil
}

func (l *Ledger) has(key string) bool {
	return slices.ContainsFunc(l.Entries, func(e Entry) bool { return e.Key == key })
}

func (l *Ledger) add(key string, now time.Time, status string) {
	l.Entries = append(l.Entries, Entry{Key: key, Seen: now, Status: status})
	if len(l.Entries) > MaxLedger {
		l.Entries = l.Entries[len(l.Entries)-MaxLedger:]
	}
}

// used counts the jobs taken or rejected within the quota window.
func (l *Ledger) used(now time.Time) int {
	n := 0
	for _, e := range l.Entries {
		if now.Sub(e.Seen) < QuotaWindow {
			n++
		}
	}
	return n
}

// prune drops entries after keepTaken (R5); a directory left in the inbox that long expired on
// the runner's clock long before, so it is not read again.
func (l *Ledger) prune(now time.Time) {
	l.Entries = slices.DeleteFunc(l.Entries, func(e Entry) bool { return now.Sub(e.Seen) >= keepTaken })
}
