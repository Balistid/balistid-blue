package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/unixsock"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// Caps on what view reads (T20): state.json holds at most maxEvents changes and spans. A run takes some 400 bytes
// in memory, so runsMax is about 13 GiB: far over a week of runs, it only stops a file that is not the judge's.
const (
	stateMax    = 64 << 20
	lineMax     = 4 << 10
	runsMax     = 1 << 25
	manifestMax = 1 << 20
	topN        = 20
	listMax     = 1000
)

// Where a run's chain of spawners ended. Only agent is a claim: an ancestor is an agent's binary. Every other run
// may still be an agent's (ADR 0082 point 5): observed is a process Laurel named by its start time only, read from
// /proc or forked without an exec (a subshell); broken is a link exec.jsonl lacks (lost, filtered or older).
const (
	underAgent    = "agent"
	endedObserved = "ended-observed"
	broken        = "broken"
)

type viewDoc struct {
	Schema   int        `json:"schema_version"`
	Covers   coversDoc  `json:"covers"`
	Programs namesShown `json:"programs_under_agents"`
	Clean    viewClean  `json:"clean"`
	Probes   *probesDoc `json:"probes,omitempty"`
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

// namesShown is a list cut at listMax, with how many there are.
type namesShown struct {
	Shown int         `json:"shown"`
	Total int         `json:"total"`
	Names []nameCount `json:"names"`
}

// viewClean is printed for runs inside the clean intervals only (ADR 0082 point 5). UnderAgent is a lower bound.
type viewClean struct {
	State         string      `json:"state"`
	Reason        string      `json:"reason,omitempty"`
	Seconds       float64     `json:"seconds"`
	Runs          int         `json:"runs"`
	UnderAgent    int         `json:"under_agent_at_least"`
	EndedObserved int         `json:"chain_ended_at_an_observed_process"`
	Broken        int         `json:"chain_broken"`
	Top           []nameCount `json:"top_under_agents"`
	Once          namesShown  `json:"once_under_agents"`
	BrokenRuns    []runRef    `json:"broken_chain_runs"`
	BrokenShown   int         `json:"broken_chain_shown"`
}

type runRef struct {
	Time   string `json:"time"`
	Serial uint64 `json:"serial"`
	Name   string `json:"name"`
}

// owners are the uids whose files view reads: the collector's, whose uid the judge runs as, and the caller's.
func owners() []uint32 {
	list := []uint32{uint32(os.Getuid())} //nolint:gosec // a uid is 32 bits on Linux
	if uid, err := unixsock.LookupUID("balistid-collector"); err == nil && uid >= 0 {
		list = append(list, uint32(uid)) //nolint:gosec // as above
	}
	return list
}

// view reads dir's state.json and exec.jsonl, owned by one of owners, assigns every run and, with manifests,
// checks the probes in them.
func view(dir string, manifests []string, owners []uint32, w io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	sd, err := readState(root, owners)
	if err != nil {
		return err
	}
	runs, err := readRuns(root, owners)
	if err != nil {
		return err
	}
	probes, err := readManifests(manifests)
	if err != nil {
		return err
	}
	where := assign(runs)
	doc := viewDoc{Schema: 1, Covers: coversDoc{Status: sd.Status, Reason: sd.Reason, Period: sd.Period,
		Since: sd.Exec.Since, Runs: len(runs), NotRead: sd.NotRead, Unsealed: sd.Unsealed, Clean: sd.Clean.State}}
	doc.Programs = programs(runs, where)
	doc.Clean = cleanView(sd.Clean, runs, where)
	if len(manifests) > 0 {
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

// failed is what went wrong, with the decoder's error when there is one.
func failed(format string, err error, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if err == nil {
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// ownedFile checks a file of the judge's: a regular file, one link, owned by one of owners, that no one but its
// owner can write.
func ownedFile(root *os.Root, name string, owners []uint32) error {
	fi, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Nlink != 1 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("view: %s is not a regular file only its owner can write", name)
	}
	if !slices.Contains(owners, st.Uid) {
		return fmt.Errorf("view: %s is owned by uid %d, neither the collector's nor the caller's", name, st.Uid)
	}
	return nil
}

func readState(root *os.Root, owners []uint32) (stateDoc, error) {
	var sd stateDoc
	if err := ownedFile(root, stateFile, owners); err != nil {
		return sd, err
	}
	b, err := wholefile.ReadIn(root, stateFile, stateMax)
	if err != nil {
		return sd, fmt.Errorf("view: %s: %w", stateFile, err)
	}
	if err := strictDecode(b, &sd); err != nil || sd.Schema != 1 {
		return sd, failed("view: %s is not the judge's state of schema 1", err, stateFile)
	}
	// inside finds a run's interval by halving, so the intervals must be in order and apart.
	var end time.Time
	for i, iv := range sd.Clean.Intervals {
		from, err1 := time.Parse(time.RFC3339Nano, iv.From)
		to, err2 := time.Parse(time.RFC3339Nano, iv.To)
		if err := errors.Join(err1, err2); err != nil || to.Before(from) || i > 0 && from.Before(end) {
			return sd, fmt.Errorf("view: %s: clean interval %d does not read, or is not after the one before", stateFile, i)
		}
		end = to
	}
	return sd, nil
}

// readRuns reads exec.jsonl line by line, each strictly: a line it cannot read fails the whole view.
func readRuns(root *os.Root, owners []uint32) ([]execRun, error) {
	if err := ownedFile(root, execFile, owners); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(execFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("view: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	return decodeRuns(f)
}

// decodeRuns reads exec.jsonl, every line ended by its newline: the judge appends whole lines, so one without is torn.
func decodeRuns(r io.Reader) ([]execRun, error) {
	br := bufio.NewReaderSize(r, lineMax)
	var runs []execRun
	for n := 1; ; n++ {
		line, err := br.ReadSlice('\n')
		switch {
		case errors.Is(err, io.EOF) && len(line) == 0:
			return runs, nil
		case errors.Is(err, io.EOF):
			return nil, fmt.Errorf("view: %s line %d is torn: no newline", execFile, n)
		case err != nil:
			return nil, fmt.Errorf("view: %s line %d: %w", execFile, n, err)
		case len(runs) >= runsMax:
			return nil, fmt.Errorf("view: %s has more than %d runs", execFile, runsMax)
		}
		var x execRun
		if err := strictDecode(line[:len(line)-1], &x); err != nil || x.Schema != 1 {
			return nil, failed("view: %s line %d is not a run of schema 1", err, execFile, n)
		}
		if _, err := time.Parse(time.RFC3339Nano, x.Time); err != nil {
			return nil, fmt.Errorf("view: %s line %d: %w", execFile, n, err)
		}
		if !nameAlphabet.MatchString(x.Name) {
			return nil, fmt.Errorf("view: %s line %d: a name outside the alphabet", execFile, n)
		}
		runs = append(runs, x)
	}
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

// chainOf follows run i's spawners until one is an agent's or the chain ends, and sets where for every run on it.
// The order of exec.jsonl does not matter: links are looked up by key.
func chainOf(runs []execRun, byEvent map[string]int, where []string, i int) string {
	if where[i] != "" {
		return where[i]
	}
	var chain []int
	seen := map[int]bool{}
	result := broken
	for {
		r := runs[i]
		if where[i] != "" {
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
			result = endedObserved
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

func programs(runs []execRun, where []string) namesShown {
	counts := map[string]int{}
	for i, r := range runs {
		if where[i] == underAgent {
			counts[r.Name]++
		}
	}
	return capped(sorted(counts))
}

func capped(all []nameCount) namesShown {
	shown := append([]nameCount{}, all[:min(listMax, len(all))]...)
	return namesShown{Shown: len(shown), Total: len(all), Names: shown}
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
	v := viewClean{State: c.State, Reason: c.Reason, Seconds: c.Seconds, Top: []nameCount{}, Once: capped(nil),
		BrokenRuns: []runRef{}}
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
	type timedRef struct {
		at time.Time
		runRef
	}
	var brokenRuns []timedRef
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
		case endedObserved:
			v.EndedObserved++
		default:
			v.Broken++
			brokenRuns = append(brokenRuns, timedRef{at, runRef{Time: r.Time, Serial: r.Serial, Name: r.Name}})
		}
	}
	// exec.jsonl holds shards newest first, each oldest first: sorted by the parsed time, as RFC 3339 drops trailing
	// zeros and does not sort as text, the list shown is the oldest runs.
	sort.Slice(brokenRuns, func(i, j int) bool {
		a, b := brokenRuns[i], brokenRuns[j]
		return a.at.Before(b.at) || a.at.Equal(b.at) && a.Serial < b.Serial
	})
	for _, r := range brokenRuns[:min(listMax, len(brokenRuns))] {
		v.BrokenRuns = append(v.BrokenRuns, r.runRef)
	}
	v.BrokenShown = len(v.BrokenRuns)
	all := sorted(counts)
	v.Top = all[:min(topN, len(all))]
	var once []nameCount
	for _, nc := range all {
		if nc.Count == 1 {
			once = append(once, nc)
		}
	}
	sort.Slice(once, func(i, j int) bool { return once[i].Name < once[j].Name })
	v.Once = capped(once)
	return v
}

func inside(ivs [][2]time.Time, at time.Time) bool {
	i := sort.Search(len(ivs), func(i int) bool { return !ivs[i][1].Before(at) })
	return i < len(ivs) && !at.Before(ivs[i][0])
}
