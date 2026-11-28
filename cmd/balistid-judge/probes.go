package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// probe is one line of the probes' manifest: a uniquely named copy of /usr/bin/true an agent ran (ADR 0082 point 6).
type probe struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	At   string `json:"at"`
	Ran  bool   `json:"ran"`
}

type manifestDoc struct {
	Tag        string  `json:"tag"`
	Session    string  `json:"session"`
	UnitProbes bool    `json:"unit_probes"`
	Probes     []probe `json:"probes"`
}

// The kinds of probe (ADR 0082 point 6): run by the agent, run first in a subshell, detached by a double fork.
// Only direct has a bar; the other two are reported.
const (
	kindDirect   = "direct"
	kindSubshell = "subshell"
	kindDetached = "detached"
)

// readManifests reads every manifest given. Probe names are unique across them all, and one manifest marked void
// fails the whole view: whoever ran those probes gave them up, and counting them would count probes that may not
// have run as they say.
func readManifests(paths []string) ([]probe, error) {
	var all []probe
	seen := map[string]bool{}
	for _, path := range paths {
		probes, err := readManifest(path)
		if err != nil {
			return nil, fmt.Errorf("%w (%s)", err, filepath.Base(path))
		}
		for _, p := range probes {
			if seen[p.Name] {
				return nil, fmt.Errorf("view: probe %s is in two manifests", p.Name)
			}
			seen[p.Name] = true
		}
		all = append(all, probes...)
	}
	return all, nil
}

func readManifest(path string) ([]probe, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the maintainer names the manifest
	if err != nil {
		return nil, fmt.Errorf("view: manifest: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, failed("view: manifest is not a regular file", err)
	}
	b, err := io.ReadAll(io.LimitReader(f, manifestMax+1))
	if err != nil || len(b) > manifestMax {
		return nil, failed("view: manifest over %d bytes or unreadable", err, manifestMax)
	}
	return decodeManifest(b)
}

func decodeManifest(b []byte) ([]probe, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("view: manifest: %w", err)
	}
	if _, void := top["void"]; void {
		return nil, errors.New("view: the manifest is void: its probes are not counted")
	}
	var m manifestDoc
	if err := strictDecode(b, &m); err != nil {
		return nil, fmt.Errorf("view: manifest: %w", err)
	}
	switch {
	case len(m.Probes) == 0:
		return nil, errors.New("view: the manifest holds no probe")
	case m.UnitProbes:
		return nil, errors.New("view: the manifest's probes ran from a unit, a kind the judge has no bar for")
	}
	seen := map[string]bool{}
	for _, p := range m.Probes {
		_, err := time.Parse(time.RFC3339Nano, p.At)
		switch {
		case !nameAlphabet.MatchString(p.Name) || seen[p.Name]:
			return nil, fmt.Errorf("view: manifest: probe name %q is repeated or outside the alphabet", p.Name)
		case p.Kind != kindDirect && p.Kind != kindSubshell && p.Kind != kindDetached:
			return nil, fmt.Errorf("view: manifest: probe %s has kind %q", p.Name, p.Kind)
		case err != nil:
			return nil, fmt.Errorf("view: manifest: probe %s: %w", p.Name, err)
		}
		seen[p.Name] = true
	}
	return m.Probes, nil
}

// kindCount is one kind of probe: how many, found in exec.jsonl, and assigned under an agent.
type kindCount struct {
	Count    int `json:"count"`
	Found    int `json:"found"`
	Assigned int `json:"assigned"`
}

type probesDoc struct {
	Direct   kindCount     `json:"direct"`
	Subshell kindCount     `json:"subshell"`
	Detached kindCount     `json:"detached"`
	Each     []probeResult `json:"each"`
	Missing  string        `json:"a_run_missing"`
}

type probeResult struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Ran      bool   `json:"ran"`
	Runs     int    `json:"runs"`
	Assigned bool   `json:"assigned"`
	Why      string `json:"not_assigned,omitempty"`
}

const missingIs = "a run can be missing from exec.jsonl because the store lacks it, because it " +
	"was received before listed_from, or because its shard is not sealed yet"

// probeSkew is how far a probe's run may be from its manifest's time (ADR 0082 point 6).
const probeSkew = 5 * time.Second

// Why a probe is not assigned.
const (
	notComplete = "read not complete"
	notRun      = "not run"
	notListed   = "not in exec.jsonl"
	moreThanOne = "more than one run"
	timeOff     = "time off"
)

// checkProbes finds each probe by its name. It is assigned only when the judge's read is COMPLETE, exactly one
// run listed in exec.jsonl has its name (a unique copy runs once; a name with more is a program's), that run is under
// an agent and its event time is within probeSkew of the manifest's (acceptance probes_assigned). One with no run
// is only not in exec.jsonl: missingIs says why that can be.
func checkProbes(probes []probe, runs []execRun, where []string, complete bool) probesDoc {
	byName := map[string][]int{}
	for i, r := range runs {
		byName[r.Name] = append(byName[r.Name], i)
	}
	d := probesDoc{Each: []probeResult{}, Missing: missingIs}
	kinds := map[string]*kindCount{kindDirect: &d.Direct, kindSubshell: &d.Subshell, kindDetached: &d.Detached}
	for _, p := range probes {
		at, _ := time.Parse(time.RFC3339Nano, p.At) // decodeManifest parsed it
		found := byName[p.Name]
		res := probeResult{Name: p.Name, Kind: p.Kind, Ran: p.Ran, Runs: len(found)}
		switch {
		case !complete:
			res.Why = notComplete
		case !p.Ran:
			res.Why = notRun
		case len(found) == 0:
			res.Why = notListed
		case len(found) > 1:
			res.Why = moreThanOne
		case where[found[0]] != underAgent:
			res.Why = "chain " + where[found[0]]
		case runs[found[0]].eventAt.Sub(at).Abs() > probeSkew:
			res.Why = timeOff
		default:
			res.Assigned = true
		}
		k := kinds[p.Kind]
		k.Count++
		k.Found += count(res.Runs > 0)
		k.Assigned += count(res.Assigned)
		d.Each = append(d.Each, res)
	}
	return d
}

func count(b bool) int {
	if b {
		return 1
	}
	return 0
}
