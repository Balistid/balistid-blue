package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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

const (
	kindDirect   = "direct"
	kindDetached = "detached"
)

// readManifest reads the probes' manifest strictly. One marked void was given up by whoever ran the probes, and
// counting it would count probes that may not have run as they say.
func readManifest(path string) ([]probe, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the maintainer names the manifest
	if err != nil {
		return nil, fmt.Errorf("view: manifest: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("view: manifest is not a regular file: %w", errors.Join(err))
	}
	b, err := io.ReadAll(io.LimitReader(f, manifestMax+1))
	if err != nil || len(b) > manifestMax {
		return nil, fmt.Errorf("view: manifest over %d bytes or unreadable: %w", manifestMax, errors.Join(err))
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
	if len(m.Probes) == 0 {
		return nil, errors.New("view: the manifest holds no probe")
	}
	seen := map[string]bool{}
	for _, p := range m.Probes {
		_, err := time.Parse(time.RFC3339Nano, p.At)
		switch {
		case !nameAlphabet.MatchString(p.Name) || seen[p.Name]:
			return nil, fmt.Errorf("view: manifest: probe name %q is repeated or outside the alphabet", p.Name)
		case p.Kind != kindDirect && p.Kind != kindDetached:
			return nil, fmt.Errorf("view: manifest: probe %s has kind %q", p.Name, p.Kind)
		case err != nil:
			return nil, fmt.Errorf("view: manifest: probe %s: %w", p.Name, err)
		}
		seen[p.Name] = true
	}
	return m.Probes, nil
}

type probesDoc struct {
	Direct           int           `json:"direct"`
	DirectFound      int           `json:"direct_found"`
	DirectAssigned   int           `json:"direct_assigned"`
	Detached         int           `json:"detached"`
	DetachedFound    int           `json:"detached_found"`
	DetachedAssigned int           `json:"detached_assigned"`
	Each             []probeResult `json:"each"`
}

type probeResult struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Ran      bool   `json:"ran"`
	Runs     int    `json:"runs"`
	Assigned bool   `json:"assigned"`
	InPeriod bool   `json:"in_period"`
}

// checkProbes finds each probe by its name. It is assigned only when it ran, is in exec.jsonl and every run of its
// name is under an agent; one the store lacks is a miss (acceptance probes_assigned).
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
	for _, p := range probes {
		at, _ := time.Parse(time.RFC3339Nano, p.At) // decodeManifest parsed it
		res := probeResult{Name: p.Name, Kind: p.Kind, Ran: p.Ran, Runs: len(byName[p.Name]),
			InPeriod: period != nil && !at.Before(from) && !at.After(to)}
		res.Assigned = p.Ran && res.Runs > 0
		for _, i := range byName[p.Name] {
			res.Assigned = res.Assigned && where[i] == underAgent
		}
		found := res.Runs > 0
		if p.Kind == kindDirect {
			d.Direct++
			d.DirectFound += count(found)
			d.DirectAssigned += count(res.Assigned)
		} else {
			d.Detached++
			d.DetachedFound += count(found)
			d.DetachedAssigned += count(res.Assigned)
		}
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
