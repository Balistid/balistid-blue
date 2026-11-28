package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sort"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/unixsock"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// Caps on what view reads (T20): state.json holds at most maxEvents changes and maxDays days. A run takes some
// 400 bytes in memory, so maxRuns is about 1.6 GiB, and a line of exec.jsonl is under 512 bytes. view is the user's
// own program, so a host that runs more needs only a new view, not a new install.
const (
	stateMax    = 64 << 20
	lineMax     = 4 << 10
	execMax     = maxRuns * 512
	manifestMax = 1 << 20
	topN        = 20
	listMax     = 1000
)

// Where a run's chain of spawners ended. Only agent is a claim: an ancestor is Claude Code's binary. Every other
// run may still be an agent's (ADR 0082 point 5): observed is a process Laurel named by its start time only, read
// from /proc or forked without an exec (a subshell); broken is a link exec.jsonl lacks (lost, filtered or older),
// one whose event id two runs of other pids carry, or one whose pid is not its spawner's.
const (
	underAgent    = "agent"
	endedObserved = "ended-observed"
	broken        = "broken"
)

const agentIs = "a run is under an agent when one of its spawners is Claude Code's binary, known only by its path " +
	"/home/<user>/.local/share/claude/versions/<version>: one installed elsewhere is not known as an agent"

const countsAre = "the day sums count what the records show, so a zero is not \"no loss\"; the counts of runs " +
	"are of exec.jsonl and bound nothing; a shard not read can hold records of a day shown"

type viewDoc struct {
	Schema int         `json:"schema_version"`
	Covers coversDoc   `json:"covers"`
	Days   []dayView   `json:"days"`
	Top    namesShown  `json:"top_under_agents"`
	Once   namesShown  `json:"once_under_agents"`
	Broken brokenShown `json:"broken_chain_runs"`
	Probes *probesDoc  `json:"probes,omitempty"`
}

// coversDoc is what the days cover: the judge's status and what it did not read.
type coversDoc struct {
	Status   string       `json:"status"`
	Reason   string       `json:"reason,omitempty"`
	Agent    string       `json:"agent"`
	Counts   string       `json:"counts"`
	Partial  string       `json:"partial,omitempty"`
	NotRead  []notReadDoc `json:"shards_not_read"`
	Unsealed []string     `json:"unsealed_not_read"`
	Torn     bool         `json:"torn_index_line"`
	Owner    uint32       `json:"owner_uid"`
	Listed   string       `json:"listed_from,omitempty"`
}

// dayView is one UTC day; a day not read has no count at all, never a zero, and one before the window no count of
// runs.
type dayView struct {
	Day  string `json:"day"`
	Read bool   `json:"has_read_records"`
	*DayCounts
}

// DayCounts is a day read: its sums, and from the window's first day on the runs exec.jsonl holds of it.
type DayCounts struct {
	*RunCounts
	SealedHere int        `json:"shards_not_read_sealed_this_day,omitempty"`
	Execs      execCounts `json:"execs"`
	Evidence   evidence   `json:"evidence"`
}

// RunCounts is where the chains of a day's runs in exec.jsonl ended.
type RunCounts struct {
	Runs          uint64 `json:"runs"`
	UnderAgent    uint64 `json:"under_agent"`
	EndedObserved uint64 `json:"chain_ended_at_an_observed_process"`
	Broken        uint64 `json:"chain_broken"`
}

type nameCount struct {
	Name  string `json:"name"`
	Count uint64 `json:"runs"`
}

// namesShown is a list cut at listMax, with how many there are and what it counts.
type namesShown struct {
	Of    string      `json:"of"`
	Shown int         `json:"shown"`
	Total int         `json:"total"`
	Names []nameCount `json:"names"`
}

type brokenShown struct {
	Shown int      `json:"shown"`
	Total int      `json:"total"`
	Runs  []runRef `json:"runs"`
}

type runRef struct {
	Received  string `json:"received"`
	EventTime string `json:"event_time"`
	Serial    uint64 `json:"serial"`
	Name      string `json:"name"`
}

// collector is the one uid whose files view reads: the judge runs as the collector's. The caller's is not one: an
// agent runs as the caller and could write both files anywhere it can write.
func collector() ([]uint32, error) {
	uid, err := unixsock.LookupUID("balistid-collector")
	if err != nil || uid < 0 {
		return nil, fmt.Errorf("view: no account balistid-collector, whose files these would be: %w", err)
	}
	return []uint32{uint32(uid)}, nil //nolint:gosec // a uid is 32 bits on Linux
}

// view reads dir's state.json and exec.jsonl, owned by one of owners, assigns every run and, with manifests,
// checks the probes in them.
func view(dir string, manifests []string, owners []uint32, w io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	defer root.Close()                      //nolint:errcheck // read-only
	probes, err := readManifests(manifests) // small: a bad one fails before exec.jsonl is read
	if err != nil {
		return err
	}
	sd, stateInfo, err := readState(root, owners)
	if err != nil {
		return err
	}
	if sd.Status == statusReading {
		return errors.New("view: the judge is still writing, or was killed before it wrote its end: run view when " +
			"it has ended, or start its unit again")
	}
	runs, err := readRuns(root, owners)
	if err != nil {
		return err
	}
	if err := unchanged(root, stateInfo); err != nil {
		return err
	}
	where := assign(runs)
	doc := viewDoc{Schema: 1, Covers: coversDoc{Status: sd.Status, Reason: sd.Reason, Agent: agentIs, Counts: countsAre, NotRead: sd.NotRead,
		Unsealed: sd.Unsealed, Torn: sd.TornIndex, Owner: ownerOf(stateInfo), Listed: sd.ListedFrom}}
	if doc.Days, err = days(sd, runs, where); err != nil {
		return err
	}
	switch {
	case sd.Status == statusComplete:
	case sd.Store == nil:
		doc.Covers.Partial = "the judge's status is " + sd.Status + ": it read no sealed shard"
	case len(sd.NotRead) == 0:
		doc.Covers.Partial = "the judge's status is " + sd.Status + ": no sealed shard it lists is unread"
	default:
		doc.Covers.Partial = "the judge's status is " + sd.Status + ": what it did not read is not in any day"
	}
	doc.Top, doc.Once, doc.Broken = overAll(runs, where)
	of := "runs in exec.jsonl: none listed"
	if i := slices.IndexFunc(doc.Days, func(v dayView) bool { return v.DayCounts != nil && v.RunCounts != nil }); i >= 0 && len(runs) > 0 {
		of = "runs in exec.jsonl, received from " + doc.Days[i].Day + " to " + sd.Days[len(sd.Days)-1].Day
	}
	doc.Top.Of, doc.Once.Of = of, of
	if len(manifests) > 0 {
		p := checkProbes(probes, runs, where, sd.Status == statusComplete)
		doc.Probes = &p
	}
	b, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return fmt.Errorf("view: %w", err)
	}
	_, err = w.Write(append(b, '\n'))
	return err //nolint:wrapcheck // stdout
}

// days is one entry for every day of the state and every day of a shard it did not read, oldest first. The state is
// written after each append, so in every status view prints each day's runs are those it counts as listed.
func days(sd stateDoc, runs []execRun, where []string) ([]dayView, error) {
	byDay := map[string]*dayView{}
	for i := range sd.Days {
		r := &sd.Days[i]
		byDay[r.Day] = &dayView{Day: r.Day, Read: true, DayCounts: &DayCounts{Execs: r.Exec, Evidence: r.evidence}}
		if r.Day >= sd.ListedFrom { // both are dates as text, which sorts as time
			byDay[r.Day].RunCounts = &RunCounts{}
		}
	}
	noDay := 0
	for i, r := range runs {
		v := byDay[r.receivedAt.UTC().Format(time.DateOnly)]
		if v == nil || v.RunCounts == nil {
			noDay++
			continue
		}
		v.Runs++
		switch where[i] {
		case underAgent:
			v.UnderAgent++
		case endedObserved:
			v.EndedObserved++
		default:
			v.Broken++
		}
	}
	if noDay > 0 {
		return nil, fmt.Errorf("view: exec.jsonl holds %d runs of days state.json lists none of: the files are not one run's", noDay)
	}
	for _, v := range byDay {
		if v.DayCounts != nil && v.RunCounts != nil && v.Runs != v.Execs.Listed {
			return nil, fmt.Errorf("view: exec.jsonl holds %d runs of %s, state.json %d: the files are not one run's", v.Runs, v.Day, v.Execs.Listed)
		}
	}
	for _, s := range sd.NotRead {
		sealed, _ := time.Parse(time.RFC3339, s.Sealed) // readState parsed it
		switch day := sealed.UTC().Format(time.DateOnly); {
		case byDay[day] == nil:
			byDay[day] = &dayView{Day: day}
		case byDay[day].DayCounts != nil:
			byDay[day].SealedHere++
		}
	}
	out := make([]dayView, 0, len(byDay))
	for _, day := range slices.Sorted(maps.Keys(byDay)) {
		out = append(out, *byDay[day])
	}
	return out, nil
}

// overAll is, over every day listed, the topN names most often under an agent, the names under one once, and the
// runs whose chain broke, oldest first.
func overAll(runs []execRun, where []string) (namesShown, namesShown, brokenShown) {
	counts := map[string]uint64{}
	var brokenRuns []execRun
	for i, r := range runs {
		switch where[i] {
		case underAgent:
			counts[r.Name]++
		case broken:
			brokenRuns = append(brokenRuns, r)
		}
	}
	all := sorted(counts)
	var once []nameCount
	for _, nc := range all {
		if nc.Count == 1 {
			once = append(once, nc)
		}
	}
	sort.Slice(once, func(i, j int) bool { return once[i].Name < once[j].Name })
	// RFC 3339 drops trailing zeros and does not sort as text: by the parsed time.
	sort.Slice(brokenRuns, func(i, j int) bool {
		a, b := brokenRuns[i], brokenRuns[j]
		return a.receivedAt.Before(b.receivedAt) || a.receivedAt.Equal(b.receivedAt) && a.Serial < b.Serial
	})
	b := brokenShown{Total: len(brokenRuns), Runs: []runRef{}}
	for _, r := range brokenRuns[:min(listMax, len(brokenRuns))] {
		b.Runs = append(b.Runs, runRef{Received: r.Received, EventTime: r.EventTime, Serial: r.Serial, Name: r.Name})
	}
	b.Shown = len(b.Runs)
	top := append([]nameCount{}, all[:min(topN, len(all))]...)
	return namesShown{Shown: len(top), Total: len(all), Names: top}, capped(once), b
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
func ownedFile(root *os.Root, name string, owners []uint32) (fs.FileInfo, error) {
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("view: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Nlink != 1 || fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("view: %s is not a regular file only its owner can write", name)
	}
	if !slices.Contains(owners, st.Uid) {
		return nil, fmt.Errorf("view: %s is owned by uid %d, which is not the collector's", name, st.Uid)
	}
	return fi, nil
}

// ownerOf is the uid of a file ownedFile passed, which checked it has one.
func ownerOf(fi fs.FileInfo) uint32 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid
	}
	return 0
}

// unchanged fails when state.json is no longer the file read before exec.jsonl: a run of the judge began meanwhile.
func unchanged(root *os.Root, before fs.FileInfo) error {
	after, err := root.Lstat(stateFile)
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return fmt.Errorf("view: %s changed while exec.jsonl was read", stateFile)
	}
	return nil
}

func readState(root *os.Root, owners []uint32) (stateDoc, fs.FileInfo, error) {
	fi, err := ownedFile(root, stateFile, owners)
	if err != nil {
		return stateDoc{}, nil, err
	}
	b, err := wholefile.ReadIn(root, stateFile, stateMax)
	if err != nil {
		return stateDoc{}, nil, fmt.Errorf("view: %s: %w", stateFile, err)
	}
	sd, err := decodeState(b)
	if err != nil {
		return sd, nil, err
	}
	return sd, fi, nil
}

// decodeState decodes state.json strictly and checks what view relies on: a status the judge writes, days in order
// and a seal time for every shard not read.
func decodeState(b []byte) (stateDoc, error) {
	var sd stateDoc
	if err := strictDecode(b, &sd); err != nil || sd.Schema != 1 {
		return sd, failed("view: %s is not the judge's state of schema 1", err, stateFile)
	}
	switch sd.Status {
	case statusReading, statusComplete, statusPartial, statusUnknown:
	default:
		return sd, fmt.Errorf("view: %s has the status %q, none the judge writes", stateFile, sd.Status)
	}
	for i, r := range sd.Days {
		if _, err := time.Parse(time.DateOnly, r.Day); err != nil || i > 0 && r.Day <= sd.Days[i-1].Day {
			return sd, fmt.Errorf("view: %s: day %d does not read, or is not after the one before", stateFile, i)
		}
	}
	for _, s := range sd.NotRead {
		if _, err := time.Parse(time.RFC3339, s.Sealed); err != nil {
			return sd, fmt.Errorf("view: %s: shard %s has no seal time", stateFile, s.Name)
		}
	}
	return sd, nil
}

// readRuns reads exec.jsonl line by line, each strictly: a line it cannot read fails the whole view.
func readRuns(root *os.Root, owners []uint32) ([]execRun, error) {
	before, err := ownedFile(root, execFile, owners)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(execFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("view: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	opened, err := f.Stat()
	switch {
	case err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened):
		return nil, fmt.Errorf("view: %s changed while it was opened", execFile)
	case opened.Size() > execMax:
		return nil, fmt.Errorf("view: %s holds %d bytes, over the %d this view reads", execFile, opened.Size(), execMax)
	}
	return decodeRuns(io.LimitReader(f, execMax))
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
		case len(runs) >= maxRuns:
			return nil, fmt.Errorf("view: %s has more than %d runs", execFile, maxRuns)
		}
		var x execRun
		if err := strictDecode(line[:len(line)-1], &x); err != nil || x.Schema != 1 {
			return nil, failed("view: %s line %d is not a run of schema 1", err, execFile, n)
		}
		event, err1 := time.Parse(time.RFC3339Nano, x.EventTime)
		received, err2 := time.Parse(time.RFC3339Nano, x.Received)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("view: %s line %d: %w", execFile, n, err)
		}
		if !nameAlphabet.MatchString(x.Name) {
			return nil, fmt.Errorf("view: %s line %d: a name outside the alphabet", execFile, n)
		}
		x.eventAt, x.receivedAt = event, received
		runs = append(runs, x)
	}
}

// ambiguous is an event id two runs carry that differ for a chain: which of them spawned a run is not known.
const ambiguous = -1

// sameForChain reports two runs a chain cannot tell apart: either may stand for the other, in any order.
func sameForChain(a, b execRun) bool {
	return a.PID == b.PID && a.Agent == b.Agent && a.SpawnerAgent == b.SpawnerAgent &&
		(a.SpawnedBy == nil) == (b.SpawnedBy == nil) && (a.SpawnedBy == nil || *a.SpawnedBy == *b.SpawnedBy)
}

// assign says where every run is, walking SPAWNED_BY through the exec events' own keys: a pid alone is reused.
func assign(runs []execRun) []string {
	byEvent := make(map[string]int, len(runs))
	for i, r := range runs {
		id := r.Process.EventID
		if id == "" {
			continue
		}
		if j, ok := byEvent[id]; !ok {
			byEvent[id] = i
		} else if j == ambiguous || !sameForChain(runs[j], r) {
			byEvent[id] = ambiguous
		}
	}
	where := make([]string, len(runs))
	for i := range runs {
		where[i] = chainOf(runs, byEvent, where, i)
	}
	return where
}

// chainOf follows run i's spawners until one is Claude Code's binary or the chain ends, and sets where for every
// run on it. The order of exec.jsonl does not matter: links are looked up by key, and kept only when the run found
// has the spawner's pid.
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
		if !ok || p == ambiguous || seen[p] || runs[p].PID != sp.PID {
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

func capped(all []nameCount) namesShown {
	shown := append([]nameCount{}, all[:min(listMax, len(all))]...)
	return namesShown{Shown: len(shown), Total: len(all), Names: shown}
}

func sorted(counts map[string]uint64) []nameCount {
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
