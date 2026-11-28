package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// Caps on what view reads (T20): state.json holds at most maxEvents changes and spans, exec.jsonl a week of runs.
const (
	stateMax    = 64 << 20
	lineMax     = 4 << 10
	runsMax     = 1 << 25
	manifestMax = 1 << 20
	topN        = 20
	listMax     = 1000
)

// Where a run is: under an agent when an ancestor is an agent's binary; outside when its chain reaches a process
// Laurel read from /proc that is no agent's binary, whose own ancestors are not known; not assigned when a link of
// its chain is missing from exec.jsonl (lost, filtered or older than the 7 days).
const (
	underAgent  = "agent"
	outside     = "outside"
	notAssigned = "not-assigned"
)

type viewDoc struct {
	Schema   int         `json:"schema_version"`
	Covers   coversDoc   `json:"covers"`
	Programs []nameCount `json:"programs_under_agents"`
	Clean    viewClean   `json:"clean"`
	Probes   *probesDoc  `json:"probes,omitempty"`
}

// coversDoc is what the programs list covers: the judge's status, its period and what it did not read.
type coversDoc struct {
	Status   string       `json:"status"`
	Reason   string       `json:"reason,omitempty"`
	Period   *periodDoc   `json:"period"`
	Since    string       `json:"exec_since"`
	Runs     int          `json:"runs"`
	NotRead  []notReadDoc `json:"shards_not_read"`
	Unsealed []string     `json:"unsealed_not_read"`
	Clean    string       `json:"clean_state"`
}

type nameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// viewClean is printed for runs inside the clean intervals only (ADR 0082 point 5).
type viewClean struct {
	State          string      `json:"state"`
	Seconds        float64     `json:"seconds"`
	Runs           int         `json:"runs"`
	UnderAgent     int         `json:"under_agent"`
	Outside        int         `json:"outside"`
	NotAssigned    int         `json:"not_assigned"`
	Top            []nameCount `json:"top_under_agents"`
	Once           []string    `json:"once_under_agents"`
	NotAssignedRun []runRef    `json:"not_assigned_runs"`
	Shown          int         `json:"not_assigned_shown"`
}

type runRef struct {
	Time   string `json:"time"`
	Serial uint64 `json:"serial"`
	Name   string `json:"name"`
}

// view reads dir's state.json and exec.jsonl, assigns every run and, with a manifest, checks the probes in it.
func view(dir, manifest string, w io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	sd, err := readState(root)
	if err != nil {
		return err
	}
	runs, err := readRuns(root)
	if err != nil {
		return err
	}
	var probes []probe
	if manifest != "" {
		if probes, err = readManifest(manifest); err != nil {
			return err
		}
	}
	where := assign(runs)
	doc := viewDoc{Schema: 1, Covers: coversDoc{Status: sd.Status, Reason: sd.Reason, Period: sd.Period,
		Since: sd.Exec.Since, Runs: len(runs), NotRead: sd.NotRead, Unsealed: sd.Unsealed, Clean: sd.Clean.State}}
	doc.Programs = programs(runs, where)
	doc.Clean = cleanView(sd.Clean, runs, where)
	if manifest != "" {
		p := checkProbes(probes, runs, where, sd.Period)
		doc.Probes = &p
	}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	_, err = w.Write(append(b, '\n'))
	return err //nolint:wrapcheck // stdout
}

// ownedFile checks a file of the judge's: a regular file, one link, that no one but its owner can write.
func ownedFile(root *os.Root, name string) error {
	fi, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Nlink != 1 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("view: %s is not a regular file only its owner can write", name)
	}
	return nil
}

func readState(root *os.Root) (stateDoc, error) {
	var sd stateDoc
	if err := ownedFile(root, stateFile); err != nil {
		return sd, err
	}
	b, err := wholefile.ReadIn(root, stateFile, stateMax)
	if err != nil {
		return sd, fmt.Errorf("view: %s: %w", stateFile, err)
	}
	if err := strictDecode(b, &sd); err != nil || sd.Schema != 1 {
		return sd, fmt.Errorf("view: %s is not the judge's state of schema 1: %w", stateFile, errors.Join(err))
	}
	for _, iv := range sd.Clean.Intervals {
		from, err1 := time.Parse(time.RFC3339Nano, iv.From)
		to, err2 := time.Parse(time.RFC3339Nano, iv.To)
		if err := errors.Join(err1, err2); err != nil || to.Before(from) {
			return sd, fmt.Errorf("view: %s: a clean interval does not read", stateFile)
		}
	}
	return sd, nil
}

// readRuns reads exec.jsonl line by line, each strictly: a line it cannot read fails the whole view.
func readRuns(root *os.Root) ([]execRun, error) {
	if err := ownedFile(root, execFile); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(execFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("view: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	return decodeRuns(f)
}

func decodeRuns(r io.Reader) ([]execRun, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, lineMax), lineMax)
	var runs []execRun
	for sc.Scan() {
		if len(runs) >= runsMax {
			return nil, fmt.Errorf("view: %s has more than %d runs", execFile, runsMax)
		}
		var x execRun
		if err := strictDecode(sc.Bytes(), &x); err != nil || x.Schema != 1 {
			return nil, fmt.Errorf("view: %s line %d is not a run of schema 1: %w", execFile, len(runs)+1, errors.Join(err))
		}
		if _, err := time.Parse(time.RFC3339Nano, x.Time); err != nil {
			return nil, fmt.Errorf("view: %s line %d: %w", execFile, len(runs)+1, err)
		}
		if !nameAlphabet.MatchString(x.Name) {
			return nil, fmt.Errorf("view: %s line %d: a name outside the alphabet", execFile, len(runs)+1)
		}
		runs = append(runs, x)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("view: %s: %w", execFile, err)
	}
	return runs, nil
}

// assign says where every run is, walking SPAWNED_BY through the exec events' own keys: a pid alone is reused.
func assign(runs []execRun) []string {
	byEvent := make(map[string]int, len(runs))
	for i, r := range runs {
		if r.Process.EventID != "" {
			byEvent[r.Process.EventID] = i
		}
	}
	where := make([]string, len(runs))
	for i := range runs {
		where[i] = chainOf(runs, byEvent, where, i)
	}
	return where
}

func chainOf(runs []execRun, byEvent map[string]int, where []string, i int) string {
	var chain []int
	seen := map[int]bool{}
	result := notAssigned
	for {
		r := runs[i]
		if where[i] != "" && len(chain) > 0 {
			result = where[i]
			break
		}
		chain, seen[i] = append(chain, i), true
		sp := r.SpawnedBy
		if sp == nil {
			break
		}
		if r.SpawnerAgent {
			result = underAgent
			break
		}
		if sp.StartTime != "" {
			result = outside
			break
		}
		p, ok := byEvent[sp.EventID]
		if !ok || seen[p] {
			break
		}
		if runs[p].Agent {
			result = underAgent
			break
		}
		i = p
	}
	for _, j := range chain {
		where[j] = result
	}
	return result
}

func programs(runs []execRun, where []string) []nameCount {
	counts := map[string]int{}
	for i, r := range runs {
		if where[i] == underAgent {
			counts[r.Name]++
		}
	}
	return sorted(counts)
}

func sorted(counts map[string]int) []nameCount {
	out := make([]nameCount, 0, len(counts))
	for n, c := range counts {
		out = append(out, nameCount{Name: n, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func cleanView(c cleanDoc, runs []execRun, where []string) viewClean {
	v := viewClean{State: c.State, Seconds: c.Seconds, Top: []nameCount{}, Once: []string{}, NotAssignedRun: []runRef{}}
	if c.State != "KNOWN" {
		return v
	}
	ivs := make([][2]time.Time, 0, len(c.Intervals))
	for _, iv := range c.Intervals {
		from, _ := time.Parse(time.RFC3339Nano, iv.From) // readState parsed every interval
		to, _ := time.Parse(time.RFC3339Nano, iv.To)
		ivs = append(ivs, [2]time.Time{from, to})
	}
	counts := map[string]int{}
	for i, r := range runs {
		at, _ := time.Parse(time.RFC3339Nano, r.Time) // decodeRuns parsed every time
		if !inside(ivs, at) {
			continue
		}
		v.Runs++
		switch where[i] {
		case underAgent:
			v.UnderAgent++
			counts[r.Name]++
		case outside:
			v.Outside++
		default:
			v.NotAssigned++
			if len(v.NotAssignedRun) < listMax {
				v.NotAssignedRun = append(v.NotAssignedRun, runRef{Time: r.Time, Serial: r.Serial, Name: r.Name})
			}
		}
	}
	all := sorted(counts)
	v.Top = all[:min(topN, len(all))]
	for _, nc := range all {
		if nc.Count == 1 {
			v.Once = append(v.Once, nc.Name)
		}
	}
	sort.Strings(v.Once)
	v.Shown = len(v.NotAssignedRun)
	return v
}

func inside(ivs [][2]time.Time, at time.Time) bool {
	i := sort.Search(len(ivs), func(i int) bool { return !ivs[i][1].Before(at) })
	return i < len(ivs) && !at.Before(ivs[i][0])
}
