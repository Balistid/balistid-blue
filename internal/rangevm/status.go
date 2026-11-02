package rangevm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a status trial (status_false_ok, ADR 0048): the uid the CLI ran as, the balistid units the image
// installed, and one fact per run of StatusRuns named FactStatusRun + its name.
const (
	FactStatusUID      = "status_uid"
	FactUnitsInstalled = "units_installed"
	FactStatusRun      = "status_"
	// FactStatusPolls is every CLI call of the trial, waits included, as "<run index>:<exit>:<shows>:<store health>,...".
	FactStatusPolls = "status_polls"
)

// How a status run breaks the floor: not at all, a unit masked and stopped, or a process frozen by SIGSTOP.
const (
	StatusHealthy      = "healthy"
	StatusStopUnit     = "stop"
	StatusFreezeAuditd = "freeze-auditd"
	StatusFreezeLaurel = "freeze-laurel"
)

// StatusRun is one run of the CLI in a status trial: what the guest breaks first and the part the CLI must then
// show not OK. auditd refuses a manual stop and Laurel is no unit, so both are frozen: their units stay active and
// only the collector's health can tell.
type StatusRun struct{ Name, Kind, Part string }

// statusUnits are the floor-0 units of the host as the judge knows them, apart from the CLI's own list.
var statusUnits = []string{
	"auditd.service", "balistid-collector.socket", "balistid-collector.service", "balistid-auditstat.service",
	"balistid-ledger.service", "balistid-relay.service", "balistid-net.service", "balistid-announce.service",
}

// statusOther are the balistid units of the image that are not floor-0 units of the host: the range's own, the
// Pi's (on the host only in local mode, ADR 0043) and the suspend announcement, a oneshot of sleep.target.
func statusOther(unit string) bool {
	return strings.HasPrefix(unit, "balistid-range-") || unit == "balistid-pi.service" ||
		unit == "balistid-pi-failed.service" || unit == "balistid-announce-suspend.service"
}

// StatusUnits are the floor-0 units the trial breaks and checks active.
func StatusUnits() []string { return slices.Clone(statusUnits) }

// StatusRuns are the runs in order: healthy, each unit in turn, Laurel frozen with every unit active, healthy.
func StatusRuns() []StatusRun {
	runs := []StatusRun{{Name: "healthy", Kind: StatusHealthy}}
	for _, u := range statusUnits {
		if u == "auditd.service" {
			runs = append(runs, StatusRun{Name: u, Kind: StatusFreezeAuditd, Part: statusHealth})
			continue
		}
		runs = append(runs, StatusRun{Name: u, Kind: StatusStopUnit, Part: u})
	}
	return append(runs, StatusRun{Name: "laurel", Kind: StatusFreezeLaurel, Part: statusHealth},
		StatusRun{Name: "end", Kind: StatusHealthy})
}

const statusHealth = "health"

// MaxStatusOut caps one run's output, in the guest and the judge: the CLI prints well under 2 KiB.
const MaxStatusOut = 16 << 10

// statusResult is the CLI's JSON as the judge reads it, decoded strictly.
type statusResult struct {
	SchemaVersion int  `json:"schema_version"`
	OK            bool `json:"ok"`
	Parts         []struct {
		Name   string `json:"part"`
		State  string `json:"state"`
		Detail string `json:"detail"`
		Hint   string `json:"hint,omitempty"`
	} `json:"parts"`
}

// judgeStatus judges a run of status trial tr. The facts are closed, each run's value is its exit, its output as
// the store's health over the CLI's run, its output as canonical base64 and the guest's proof that the break held
// from before the CLI ran to after it: anything else, a run as root, another kernel, a proof not "yes" or a
// floor-0 unit of the image the trial does not break is INVALID. The store decides healthy and frozen runs: a
// healthy run is one the store shows OK throughout, a freeze one it shows UNKNOWN throughout; a run the store
// leaves open is INVALID, but the CLI showing OK over an UNKNOWN store is a false OK whatever the run. A broken
// run not shown not OK with its part not OK, or a healthy run not OK, is a MISS: what status_false_ok counts.
func judgeStatus(tr rangejob.Trial, o Outcome) (string, string) {
	runs := StatusRuns()
	names := []string{FactTrial, FactPhase, FactKernel, FactStatusUID, FactUnitsInstalled, FactStatusPolls}
	for _, r := range runs {
		names = append(names, FactStatusRun+r.Name)
	}
	f, err := closedFacts(o.Facts, names)
	if err != nil {
		return Invalid, err.Error()
	}
	uid, uidErr := plainNumber(f[FactStatusUID])
	switch {
	case f[FactTrial] != tr.Name:
		return Invalid, "the guest ran another trial"
	case f[FactKernel] != TargetKernel:
		return Invalid, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	case uidErr != nil || uid == 0:
		return Invalid, "the CLI did not run as an unprivileged uid"
	}
	if why := unitsUnbroken(f[FactUnitsInstalled]); why != "" {
		return Invalid, why
	}
	// Every false OK the facts show is found before any run that proves nothing can end the judging: a MISS is
	// never hidden by an INVALID, which a later run could replace.
	misses, unproven := pollMisses(f[FactStatusPolls], runs)
	for _, r := range runs {
		why, invalid := judgeRun(r, f[FactStatusRun+r.Name])
		switch {
		case invalid:
			unproven = append(unproven, fmt.Sprintf("run %s: %s", r.Name, why))
		case why != "":
			misses = append(misses, r.Name+": "+why)
		}
	}
	switch {
	case len(misses) > 0:
		return Miss, fmt.Sprintf("%d false OK or healthy runs not OK: %s", len(misses), strings.Join(misses, "; "))
	case len(unproven) > 0:
		return Invalid, strings.Join(unproven, "; ")
	}
	return Pass, fmt.Sprintf("%d runs: every break showed its part not OK, every healthy run OK", len(runs))
}

// unitsUnbroken is why the image's balistid units are not exactly the ones the trial breaks, or "".
func unitsUnbroken(installed string) string {
	var floor []string
	for _, u := range strings.Split(installed, ",") {
		if !statusOther(u) {
			floor = append(floor, u)
		}
	}
	want := slices.DeleteFunc(slices.Clone(statusUnits), func(u string) bool { return !strings.HasPrefix(u, "balistid-") })
	slices.Sort(floor)
	slices.Sort(want)
	if !slices.Equal(floor, want) {
		return fmt.Sprintf("the image's floor-0 units \"%s\" are not the ones the trial breaks", Printable(strings.Join(floor, ","), 512))
	}
	return ""
}

// The store's health over a run as the guest reports it: OK or UNKNOWN throughout, both, no record before the
// run, or not read for a stopped unit, whose collector may be the stopped one.
const (
	StoreOK      = "OK"
	StoreUnknown = "UNKNOWN"
	StoreMixed   = "mixed"
	StoreNone    = "none"
	StoreUnread  = "-"
)

// judgeRun is why run r's value is a false OK or a healthy run not OK (a MISS), or why it proves nothing (invalid),
// or "" for a sound run.
func judgeRun(r StatusRun, v string) (string, bool) {
	exit, health, before, out, err := statusOf(v)
	if err != nil {
		return err.Error(), true
	}
	freeze := r.Kind == StatusFreezeAuditd || r.Kind == StatusFreezeLaurel
	if freeze && before != StoreOK || !freeze && before != StoreUnread {
		return fmt.Sprintf("the store's health when the break began was %s", before), true
	}
	res, bad := resultOf(out)
	why, invalid := storeShows(r, res, exit, health)
	switch {
	case invalid, why != "":
		return why, invalid
	case bad != "":
		return bad, false
	}
	return statusMiss(r, res, exit), false
}

// statusOf decodes one run's value: "<exit> <store health over the CLI's run> <store health when the break began>
// <base64 output> <proof>", the proof "yes" or the guest's reason.
func statusOf(v string) (int, string, string, []byte, error) {
	parts := strings.SplitN(v, " ", 5)
	if len(parts) != 5 {
		return 0, "", "", nil, fmt.Errorf("not an exit, two store healths, output and proof")
	}
	if parts[4] != "yes" {
		return 0, "", "", nil, fmt.Errorf("the break is not proven: \"%s\"", Printable(parts[4], 256))
	}
	exit, err := strconv.Atoi(parts[0])
	if err != nil || strconv.Itoa(exit) != parts[0] {
		return 0, "", "", nil, fmt.Errorf("the exit is not a plain number")
	}
	for _, h := range parts[1:3] {
		if !slices.Contains(storeStates, h) && h != StoreUnread {
			return 0, "", "", nil, fmt.Errorf("a store health is not one the guest reports")
		}
	}
	out, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || base64.StdEncoding.EncodeToString(out) != parts[3] || len(out) > MaxStatusOut {
		return 0, "", "", nil, fmt.Errorf("the output is not canonical base64 within %d bytes", MaxStatusOut)
	}
	return exit, parts[1], parts[2], out, nil
}

// storeStates are the store's health over a CLI call the guest computes.
var storeStates = []string{StoreOK, StoreUnknown, StoreMixed, StoreNone}

// resultOf is the CLI's result in out, or why out is not exactly the canonical encoding of one: the CLI's own
// encoder writes one object and a newline, so a missing or repeated key, trailing bytes or any other spelling
// differ from it.
func resultOf(out []byte) (statusResult, string) {
	var res statusResult
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if err := d.Decode(&res); err != nil || res.SchemaVersion != 1 {
		return statusResult{}, "the output is not a status result of schema 1"
	}
	canonical, err := json.Marshal(res)
	if err != nil || !bytes.Equal(append(canonical, '\n'), out) {
		return statusResult{}, "the output is not exactly one canonical status result"
	}
	return res, ""
}

// The CLI's own verdict in a call's output, as the guest reads it with ShowsOK.
const (
	ShowsOK    = "ok"
	ShowsNotOK = "not-ok"
	ShowsBad   = "bad"
)

// ShowsOKOf is what out says, read as the judge reads a run's output: ShowsBad unless it is exactly one canonical
// status result. The guest keeps this, not the output, for every call it made while waiting.
func ShowsOKOf(out []byte) string {
	res, bad := resultOf(out)
	switch {
	case bad != "":
		return ShowsBad
	case res.OK:
		return ShowsOK
	}
	return ShowsNotOK
}

// pollMisses checks every CLI call of the trial, "<run>:<exit>:<shows>:<store health>": one that exited 0, said
// ok or printed no canonical result while the store was UNKNOWN throughout is a false OK, whichever wait it was in.
// An entry it cannot read is unproven, and the entries after it are still checked.
func pollMisses(polls string, runs []StatusRun) (misses, unproven []string) {
	for _, entry := range strings.Split(polls, ",") {
		fields := strings.Split(entry, ":")
		if len(fields) != 4 {
			unproven = append(unproven, fmt.Sprintf("a poll \"%s\" is not run, exit, verdict and store health", Printable(entry, 64)))
			continue
		}
		i, errI := plainNumber(fields[0])
		exit, errE := plainNumber(fields[1])
		switch {
		case errI != nil || i >= uint64(len(runs)) || errE != nil || !slices.Contains(storeStates, fields[3]) ||
			fields[2] != ShowsOK && fields[2] != ShowsNotOK && fields[2] != ShowsBad:
			unproven = append(unproven, fmt.Sprintf("a poll \"%s\" of no known run, exit, verdict or store health", Printable(entry, 64)))
		case fields[3] == StoreUnknown && (exit == 0 || fields[2] != ShowsNotOK):
			misses = append(misses, runs[i].Name+": false OK in a poll while the store was UNKNOWN throughout")
		}
	}
	return misses, unproven
}

// storeShows judges run r by the store's health over it: why it is a false OK (a MISS), or why the run proves
// nothing (invalid), or "" when the CLI's result decides.
func storeShows(r StatusRun, res statusResult, exit int, health string) (string, bool) {
	cliOK := res.OK || exit == 0
	switch {
	case r.Kind == StatusStopUnit && health != StoreUnread:
		return "the store's health is read for a stopped unit", true
	case r.Kind == StatusStopUnit:
		return "", false
	case health == StoreUnknown && cliOK:
		return "false OK: the store's health was UNKNOWN throughout", false
	case r.Kind == StatusHealthy && health == StoreUnknown:
		return "the floor was not healthy: the store's health was UNKNOWN throughout", true
	case r.Kind == StatusHealthy && health != StoreOK, r.Kind != StatusHealthy && health != StoreUnknown:
		return fmt.Sprintf("the store's health over the run was %s", health), true
	}
	return "", false
}

// statusMiss is why run r's result is a false OK or a healthy run not shown OK, or "". The parts must be exactly
// the judge's units and the health: a part the CLI does not show is one it can show OK while broken.
func statusMiss(r StatusRun, res statusResult, exit int) string {
	state := map[string]string{}
	for _, p := range res.Parts {
		if _, dup := state[p.Name]; dup {
			return fmt.Sprintf("part \"%s\" shown twice", Printable(p.Name, 64))
		}
		state[p.Name] = p.State
	}
	for _, want := range append(slices.Clone(statusUnits), statusHealth) {
		if _, ok := state[want]; !ok {
			return "part " + want + " not shown"
		}
	}
	if len(state) != len(statusUnits)+1 {
		return "a part the judge does not know"
	}
	for name, s := range state {
		if s != "OK" && s != "FAIL" && s != "UNKNOWN" {
			return fmt.Sprintf("part %s in a state of no known kind \"%s\"", name, Printable(s, 32))
		}
	}
	if r.Kind == StatusHealthy {
		for name, s := range state {
			if s != "OK" {
				return fmt.Sprintf("healthy, but %s \"%s\"", name, Printable(s, 32))
			}
		}
		if !res.OK || exit != 0 {
			return fmt.Sprintf("healthy, but ok %v, exit %d", res.OK, exit)
		}
		return ""
	}
	switch {
	case res.OK || exit != 1:
		return fmt.Sprintf("false OK: ok %v, exit %d", res.OK, exit)
	case state[r.Part] == "OK":
		return "false OK: part " + r.Part + " OK"
	}
	return ""
}
