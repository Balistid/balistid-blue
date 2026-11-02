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
	names := []string{FactTrial, FactPhase, FactKernel, FactStatusUID, FactUnitsInstalled}
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
	var misses []string
	for _, r := range runs {
		res, exit, health, err := statusOf(f[FactStatusRun+r.Name])
		if err != nil {
			return Invalid, fmt.Sprintf("run %s: %s", r.Name, err)
		}
		why, invalid := storeShows(r, res, exit, health)
		if invalid {
			return Invalid, fmt.Sprintf("run %s: %s", r.Name, why)
		}
		if why == "" {
			why = statusMiss(r, res, exit)
		}
		if why != "" {
			misses = append(misses, r.Name+": "+why)
		}
	}
	if len(misses) > 0 {
		return Miss, fmt.Sprintf("%d of %d runs: %s", len(misses), len(runs), strings.Join(misses, "; "))
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

// statusOf decodes one run's value: "<exit> <store health> <base64 output> <proof>", the proof "yes" or the
// guest's reason.
func statusOf(v string) (statusResult, int, string, error) {
	parts := strings.SplitN(v, " ", 4)
	if len(parts) != 4 {
		return statusResult{}, 0, "", fmt.Errorf("not an exit, store health, output and proof")
	}
	if parts[3] != "yes" {
		return statusResult{}, 0, "", fmt.Errorf("the break is not proven: \"%s\"", Printable(parts[3], 256))
	}
	exit, err := strconv.Atoi(parts[0])
	if err != nil || strconv.Itoa(exit) != parts[0] {
		return statusResult{}, 0, "", fmt.Errorf("the exit is not a plain number")
	}
	if !slices.Contains([]string{StoreOK, StoreUnknown, StoreMixed, StoreNone, StoreUnread}, parts[1]) {
		return statusResult{}, 0, "", fmt.Errorf("the store health is not one the guest reports")
	}
	out, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || base64.StdEncoding.EncodeToString(out) != parts[2] || len(out) > MaxStatusOut {
		return statusResult{}, 0, "", fmt.Errorf("the output is not canonical base64 within %d bytes", MaxStatusOut)
	}
	var res statusResult
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if err := d.Decode(&res); err != nil || d.More() || res.SchemaVersion != 1 {
		return statusResult{}, 0, "", fmt.Errorf("the output is not one status result of schema 1")
	}
	return res, exit, parts[1], nil
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
