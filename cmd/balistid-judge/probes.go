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

// kindCount is one kind of probe: how many, found in exec.jsonl, assigned under an agent, and timed outside the
// judge's period, which none of them is assigned.
type kindCount struct {
	Count       int `json:"count"`
	Found       int `json:"found"`
	Assigned    int `json:"assigned"`
	OutOfPeriod int `json:"out_of_period"`
}

type probesDoc struct {
	Direct   kindCount     `json:"direct"`
	Subshell kindCount     `json:"subshell"`
	Detached kindCount     `json:"detached"`
	Each     []probeResult `json:"each"`
}

type probeResult struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Ran      bool   `json:"ran"`
	Runs     int    `json:"runs"`
	Assigned bool   `json:"assigned"`
	InPeriod bool   `json:"in_period"`
}

// checkProbes finds each probe by its name. It is assigned only when it ran inside the judge's period, is in
// exec.jsonl and every run of its name is under an agent; one the store lacks is a miss (acceptance
// probes_assigned). A run of the name outside the period is some other program's.
func checkProbes(probes []probe, runs []execRun, where []string, period *periodDoc) probesDoc {
	byName := map[string][]int{}
	for i, r := range runs {
		byName[r.Name] = append(byName[r.Name], i)
	}
	var from, to time.Time
	if period != nil {
		from, _ = time.Parse(time.RFC3339Nano, period.From) // a period that does not read covers no probe
		to, _ = time.Parse(time.RFC3339Nano, period.To)
	}
	d := probesDoc{Each: []probeResult{}}
	kinds := map[string]*kindCount{kindDirect: &d.Direct, kindSubshell: &d.Subshell, kindDetached: &d.Detached}
	for _, p := range probes {
		at, _ := time.Parse(time.RFC3339Nano, p.At) // decodeManifest parsed it
		res := probeResult{Name: p.Name, Kind: p.Kind, Ran: p.Ran, Runs: len(byName[p.Name]),
			InPeriod: period != nil && !at.Before(from) && !at.After(to)}
		// A unique copy runs once: a name with more runs is a program's, not the probe's.
		res.Assigned = p.Ran && res.Runs == 1 && res.InPeriod
		for _, i := range byName[p.Name] {
			res.Assigned = res.Assigned && where[i] == underAgent
		}
		k := kinds[p.Kind]
		k.Count++
		k.Found += count(res.Runs > 0)
		k.Assigned += count(res.Assigned)
		k.OutOfPeriod += count(!res.InPeriod)
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
