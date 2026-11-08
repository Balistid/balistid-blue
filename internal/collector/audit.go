package collector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/auditstat"
	"github.com/Balistid/balistid-blue/internal/status"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

const (
	// StageKernel counts the kernel's lost records, a rise of auditstat's lost: a lower bound (ADR 0038, point 3).
	StageKernel Stage = "kernel"
	// StageDispatcher counts one record each time auditd's dispatcher flag turns from no to yes: a lower bound.
	StageDispatcher Stage = "dispatcher"

	// auditFresh is three of auditd's state writes and of auditstat's reports, 5 s apart (ADR 0038, point 4).
	auditFresh = 15 * time.Second
	// bootGrace bounds the boot clock at a start that gets auditFresh's grace for auditstat's first report:
	// ready_s's 30 s from boot to health OK, which a later start of the collector misses anyway (ADR 0070).
	bootGrace = 30 * time.Second
	// maxStateBytes bounds auditd's state file, which holds a dozen short lines.
	maxStateBytes = 4 << 10
	overflowName  = "plugin queue overflow detected"
	seenSchema    = 1
	maxSeenBytes  = 4 << 10

	// The health of the audit reasons, named only where health would otherwise be OK, in this order (ADR 0038,
	// point 4; ADR 0059, point 3), but auditdRestarted, which is named over every other reason while it holds.
	auditOverflow   = "UNKNOWN dispatcher-overflow"
	rulesDiffer     = "UNKNOWN rules-differ"
	auditdDown      = "UNKNOWN auditd-down"
	auditdRestarted = "UNKNOWN auditd-restarted"
	auditStale      = "UNKNOWN audit-stale"
	// auditStarting is health with no report read yet in the first auditFresh of the boot's first start, under
	// bootGrace into the boot: auditstat starts after the collector's first canary can be stored (ADR 0070).
	auditStarting = "UNKNOWN starting"
)

// AuditConfig names what the collector reads of the kernel's and auditd's loss and health (ADR 0038, point 2):
// auditstat's report and uid, auditd's state file, and its own file of the last report it stored, kept per boot.
type AuditConfig struct {
	ReportPath string
	ReportUID  int // -1 when the account could not be resolved: every report is refused
	StatePath  string
	SeenPath   string
	BootID     string // "" matches no stored report, so every restart counts from zero
}

// seen is what the store holds of the kernel's and auditd's state in one boot: the last lost and flag counted
// and the last auditd pid. The seen file gets only values whose losses the store committed.
type seen struct {
	SchemaVersion int    `json:"schema_version"`
	BootID        string `json:"boot_id"`
	Lost          uint32 `json:"lost"`
	Overflow      bool   `json:"overflow"`
	PID           uint32 `json:"auditd_pid"`
}

// Audit follows auditstat's report and auditd's state file on the writer's tick; only the writer's goroutine
// calls it. A read that fails any check refreshes nothing (ADR 0038, point 2).
type Audit struct {
	readReport func() (auditstat.Report, error)
	readState  func() (overflow bool, mtime int64, err error)
	boottime   func() (uint64, error) // CLOCK_BOOTTIME in ns (status.Boottime)
	shipped    auditstat.Loaded       // what the report must say is loaded (ADR 0059, point 3)
	seenPath   string
	bootID     string

	start                 time.Time
	grace                 bool   // the boot's first start, under bootGrace into the boot, until graceEnd (ADR 0070)
	graceEnd              uint64 // the boot clock auditFresh after the start: a suspend does not stop it
	report                auditstat.Report
	loaded                auditstat.Loaded // the last report's, journaled when it changes to one not shipped
	haveReport, haveState bool
	reportAt, stateAt     time.Time // when the report's seq and the state's mtime last changed
	stateMtime            int64
	overflow              bool
	base, stored          seen      // counted, and in the seen file
	restartAt             time.Time // when a new auditd pid was seen; zero when none is held
	reportErr, stateErr   bool      // the last read failed: its next failure is not journaled again
	seenErr               bool
}

// NewAudit reads what cfg names.
func NewAudit(cfg AuditConfig) *Audit {
	return &Audit{
		readReport: func() (auditstat.Report, error) { return auditstat.ReadReport(cfg.ReportPath, cfg.ReportUID) },
		readState:  func() (bool, int64, error) { return readAuditdState(cfg.StatePath) },
		boottime:   status.Boottime,
		shipped:    auditstat.Shipped(),
		seenPath:   cfg.SeenPath, bootID: cfg.BootID,
	}
}

// begin takes the stored report of this boot, if any, as what was counted, so a restart counts only what changed
// since (ADR 0038, point 3); without one a non-zero lost or a yes counts once.
func (a *Audit) begin(now time.Time, log *slog.Logger) {
	a.start, a.reportAt, a.stateAt = now, now, now
	up, err := a.boottime()
	a.grace, a.graceEnd = err == nil && up < uint64(bootGrace), up+uint64(auditFresh) // no clock, no grace (R6)
	s, err := readSeen(a.seenPath)
	switch {
	case err == nil && s.BootID == a.bootID: // a restart in this boot; a seen file always has a boot id
		a.base, a.stored, a.grace = s, s, false
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		log.Error("stored audit report not read, counting this boot's losses from zero", "err", err)
	}
	a.base.SchemaVersion, a.base.BootID = seenSchema, a.bootID
}

// started is what the started record carries of the audit: lost, the flag and auditd's pid as first read, null
// where that read failed (ADR 0017, point 5, as ADR 0038 amends it).
func (a *Audit) started() map[string]any {
	m := map[string]any{"lost": nil, "overflow": nil, "auditd_pid": nil}
	if a.haveReport {
		m["lost"], m["auditd_pid"] = a.report.Status.Lost, a.report.Status.PID
	}
	if a.haveState {
		m["overflow"] = "no"
		if a.overflow {
			m["overflow"] = "yes"
		}
	}
	return m
}

// check reads the report and the state file and returns the kernel's and the dispatcher's losses since what was
// counted: a rise of lost, a fall as a reset of max(new, 1), and one for a flag turned from no to yes.
func (a *Audit) check(now time.Time, log *slog.Logger) (kernel, dispatcher uint64) {
	r, err := a.readReport()
	journalRead(log, &a.reportErr, "auditstat's report not read", err)
	if err == nil {
		if !a.haveReport || r.Seq != a.report.Seq {
			a.reportAt = now
		}
		a.report, a.haveReport = r, true
		if l := r.Loaded(); l != a.loaded {
			a.loaded = l
			if l != a.shipped {
				log.Error("the loaded audit rules differ from the shipped ones", "count", l.Rules.Count,
					"digest", hex.EncodeToString(l.Rules.Digest[:]), "failure", l.Failure, "rate_limit", l.RateLimit,
					"backlog_limit", l.BacklogLimit, "backlog_wait_time", l.BacklogWaitTime, "rule", auditstat.ShippedRulesSHA256)
			}
		}
		s := r.Status
		switch {
		case s.Lost > a.base.Lost:
			kernel = uint64(s.Lost - a.base.Lost)
		case s.Lost < a.base.Lost:
			kernel = uint64(max(s.Lost, 1))
		}
		a.base.Lost = s.Lost
		if s.PID != 0 {
			if a.base.PID != 0 && s.PID != a.base.PID {
				a.restartAt = now       // a restart may take an unseen overflow with it
				a.base.Overflow = false // a new auditd starts at no, so its first yes is a loss of its own
			}
			a.base.PID = s.PID
		}
	}
	ov, mtime, err := a.readState()
	journalRead(log, &a.stateErr, "auditd's state file not read", err)
	if err == nil {
		if !a.haveState || mtime != a.stateMtime {
			a.stateAt = now
		}
		a.stateMtime, a.haveState, a.overflow = mtime, true, ov
		if ov && !a.base.Overflow {
			dispatcher = 1
		}
		a.base.Overflow = ov
	}
	return kernel, dispatcher
}

// journalRead logs a read's or write's first failure and its recovery, not every tick's.
func journalRead(log *slog.Logger, failing *bool, msg string, err error) {
	switch {
	case err != nil && !*failing:
		log.Error(msg, "err", err)
	case err == nil && *failing:
		log.Info(msg + ": recovered")
	}
	*failing = err != nil
}

// inGrace is whether the start's grace holds on the boot clock too, which runs through a suspend (ENGINEERING §7,
// Time): once a read of it fails or reaches graceEnd, the grace is over for good.
func (a *Audit) inGrace() bool {
	up, err := a.boottime()
	a.grace = a.grace && err == nil && up < a.graceEnd
	return a.grace
}

// restarting holds health UNKNOWN for a new auditd pid until that auditd's first fresh state, or auditFresh.
func (a *Audit) restarting(now time.Time) bool {
	return !a.restartAt.IsZero() && !a.stateAt.After(a.restartAt) && now.Sub(a.restartAt) < auditFresh
}

// reason is the audit's UNKNOWN, "" for none: the fresh flag reads yes; no report read yet, starting in the first
// auditFresh of a start with the grace, on both clocks, and stale otherwise; a fresh report shows rules or status
// fields other than the shipped ones; a fresh report has no auditd or audit not locked; the report's seq or the
// state's mtime did not change within auditFresh. The last two wait the collector's first auditFresh; the rules do
// not, as a fresh report that differs is evidence, not an absence. The clock is the writer's monotonic one, which a
// suspend stops; the grace also ends on the boot clock.
func (a *Audit) reason(now time.Time) string {
	warm := now.Sub(a.start) >= auditFresh
	reportFresh := a.haveReport && now.Sub(a.reportAt) < auditFresh
	stateFresh := a.haveState && now.Sub(a.stateAt) < auditFresh
	switch {
	case stateFresh && a.overflow:
		return auditOverflow
	case !a.haveReport && !warm && a.inGrace(): // never OK without a report, alerted past the boot's grace (ADR 0070)
		return auditStarting
	case !a.haveReport: // nothing yet says which rules are loaded (ADR 0059, point 3)
		return auditStale
	case reportFresh && a.report.Loaded() != a.shipped:
		return rulesDiffer
	case warm && reportFresh && (a.report.Status.PID == 0 || a.report.Status.Enabled != 2):
		return auditdDown
	case warm && (!reportFresh || !stateFresh):
		return auditStale
	}
	return ""
}

// persist writes what was counted to the seen file once the store committed every loss counted from it
// (!waiting): a crash before the write counts those losses again after the restart, never not at all.
func (a *Audit) persist(waiting bool, log *slog.Logger) {
	if waiting || a.base == a.stored {
		return
	}
	b, err := json.Marshal(a.base)
	if err == nil {
		err = wholefile.Write(a.seenPath, b, 0o600)
	}
	if err == nil {
		a.stored = a.base
	}
	journalRead(log, &a.seenErr, "audit report not stored, a restart counts its losses again", err)
}

// readSeen reads the seen file: not through a symlink, a regular file of the collector's own uid, at most
// maxSeenBytes.
func readSeen(path string) (seen, error) {
	b, _, err := readSmall(path, maxSeenBytes, os.Getuid())
	if err != nil {
		return seen{}, err
	}
	return decodeSeen(b)
}

// decodeSeen decodes the seen file strictly: the known fields of the known schema, and a boot id.
func decodeSeen(b []byte) (seen, error) {
	var s seen
	switch err := strict(b, &s); {
	case err != nil:
		return seen{}, fmt.Errorf("collector: stored audit report: %w", err)
	case s.SchemaVersion != seenSchema:
		return seen{}, errors.New("collector: stored audit report of an unknown schema")
	case s.BootID == "":
		return seen{}, errors.New("collector: stored audit report without a boot id")
	}
	return s, nil
}

// readAuditdState reads auditd's state file at path (ADR 0038, point 2): not through a symlink, a regular file of
// root, at most maxStateBytes, with exactly one overflow line. It returns the flag and the file's mtime.
func readAuditdState(path string) (bool, int64, error) {
	b, mtime, err := readSmall(path, maxStateBytes, 0)
	if err != nil {
		return false, 0, err
	}
	ov, err := parseAuditdState(b)
	return ov, mtime, err
}

// readSmall reads the regular file at path, owned by uid, of at most limit bytes, not through a
// symlink and without waiting on a FIFO; it returns the bytes and the mtime in nanoseconds.
func readSmall(path string, limit int64, uid int) ([]byte, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // main's fixed paths
	if err != nil {
		return nil, 0, fmt.Errorf("collector: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, fmt.Errorf("collector: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, 0, fmt.Errorf("collector: %s is not a regular file", path)
	case !ok || int64(st.Uid) != int64(uid):
		return nil, 0, fmt.Errorf("collector: %s is not of uid %d", path, uid)
	case fi.Size() > limit:
		return nil, 0, fmt.Errorf("collector: %s is over %d bytes", path, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1)) // auditd rewrites its file in place: it can grow after the stat
	switch {
	case err != nil:
		return nil, 0, fmt.Errorf("collector: %w", err)
	case int64(len(b)) > limit:
		return nil, 0, fmt.Errorf("collector: %s is over %d bytes", path, limit)
	}
	return b, fi.ModTime().UnixNano(), nil
}

// parseAuditdState is the overflow flag of a state file: exactly one line names it, and it reads exactly
// "plugin queue overflow detected = yes" or "= no" (audisp/queue.c). Errors never quote b.
func parseAuditdState(b []byte) (bool, error) {
	var ov bool
	n := 0
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		if !bytes.Contains(line, []byte(overflowName)) {
			continue
		}
		n++
		switch string(line) {
		case overflowName + " = yes":
			ov = true
		case overflowName + " = no":
			ov = false
		default:
			return false, errors.New("collector: auditd's overflow line reads neither yes nor no")
		}
	}
	if n != 1 {
		return false, fmt.Errorf("collector: %d overflow lines in auditd's state, not one", n)
	}
	return ov, nil
}
