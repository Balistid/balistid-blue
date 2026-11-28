package main

import (
	"encoding/hex"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/store"
)

// The judge's status in state.json: never OK (R6). COMPLETE says every sealed shard from the start day on was read,
// not that the recorder was healthy or lost nothing; that is in the health changes and the days' evidence.
const (
	statusReading  = "READING"
	statusComplete = "COMPLETE"
	statusPartial  = "PARTIAL"
	statusUnknown  = "UNKNOWN"
)

// stateDoc is state.json (ADR 0082 points 2 and 3). view decodes it strictly, so a field added here is added there.
type stateDoc struct {
	Schema       int                  `json:"schema_version"`
	Judge        string               `json:"judge"`
	Version      string               `json:"version"`
	Written      string               `json:"written"`
	Status       string               `json:"status"`
	Reason       string               `json:"reason,omitempty"`
	Store        storeDoc             `json:"store"`
	Read         []shardDoc           `json:"shards_read"`
	NotRead      []notReadDoc         `json:"shards_not_read"`
	Unsealed     []string             `json:"unsealed_not_read"`
	TornIndex    bool                 `json:"torn_index_line"`
	ReadLimitMin int                  `json:"read_limit_min"`
	BudgetMiB    int64                `json:"byte_budget_mib"`
	MaxRuns      int                  `json:"max_runs"`
	Health       []transition         `json:"health_changes"`
	HealthHeld   string               `json:"health_changes_withheld,omitempty"`
	Keys         map[string]*keyCount `json:"by_rule_key"`
	KeysOver     uint64               `json:"rule_keys_over_cap"`
	Serials      serialDoc            `json:"serials"`
	Days         []dayRow             `json:"days"`
}

type storeDoc struct {
	Seals    int     `json:"seals"`
	Bytes    int64   `json:"bytes"`
	LastSeal *sealOf `json:"last_seal"`
}

type sealOf struct {
	Name   string `json:"name"`
	First  uint64 `json:"first_seq"`
	Last   uint64 `json:"last_seq"`
	SHA256 string `json:"sha256"`
	Sealed string `json:"sealed"`
}

type shardDoc struct {
	Name    string `json:"name"`
	First   uint64 `json:"first_seq"`
	Last    uint64 `json:"last_seq"`
	Records uint64 `json:"records"`
}

type notReadDoc struct {
	Name   string `json:"name"`
	Sealed string `json:"sealed"`
	Reason string `json:"reason"`
}

// serialDoc is what the serials' runs share; their gaps are in the days.
type serialDoc struct {
	Segments  int    `json:"segments"`
	Duplicate uint64 `json:"duplicate"`
	OverCap   uint64 `json:"gaps_counted_at_the_cap"`
}

// state is one run of the judge: the seals, the shards read from the start, and why the read stopped.
type state struct {
	doc   stateDoc
	seals []store.Seal
	from  int    // the first shard read: those before it are outside the byte budget
	next  int    // the next shard to read
	stop  string // why the read stopped at next
	read  []shardDoc
	last  stateDoc // state.json as written after the last shard read whole
}

func newState(seals []store.Seal, sizes int64, from int, limitMin int) *state {
	st := &state{seals: seals, from: from, next: from}
	d := &st.doc
	d.Schema, d.Judge, d.Version, d.Status = 1, "ADR 0082", buildinfo.Version, statusReading
	d.Store = storeDoc{Seals: len(seals), Bytes: sizes}
	if n := len(seals); n > 0 {
		l := seals[n-1]
		d.Store.LastSeal = &sealOf{Name: l.Name, First: l.First, Last: l.Last, SHA256: hex.EncodeToString(l.SHA256[:]),
			Sealed: sealText(l)}
	}
	d.Unsealed, d.ReadLimitMin, d.BudgetMiB, d.MaxRuns = []string{}, limitMin, budgetBytes>>20, maxRuns
	return st
}

func sealText(l store.Seal) string { return time.Unix(l.Sealed, 0).UTC().Format(time.RFC3339) }

// notRead is every sealed shard not read, oldest first, with why.
func (st *state) notRead() []notReadDoc {
	out := []notReadDoc{}
	for i, l := range st.seals {
		reason := "not read yet"
		switch {
		case i < st.from:
			reason = "before the first UTC day whose shards to the newest fit the byte budget"
		case i < st.next:
			continue
		case i == st.next && st.stop != "":
			reason = st.stop
		case st.stop != "":
			reason = "not read: " + st.doc.Reason
		}
		out = append(out, notReadDoc{Name: l.Name, Sealed: sealText(l), Reason: reason})
	}
	return out
}

// render is state.json after the shards read so far. The run of serials being read has its holes counted as they
// stand; a later serial may still fill one.
func (st *state) render(rd *reader, written int64) stateDoc {
	d := st.doc
	d.Written = timeText(written)
	d.Read, d.NotRead = append([]shardDoc{}, st.read...), st.notRead()
	d.Keys = make(map[string]*keyCount, len(rd.keys))
	for k, c := range rd.keys {
		d.Keys[k] = &keyCount{Records: c.Records, Bytes: c.Bytes}
	}
	d.KeysOver = rd.keysOver
	d.Health = []transition{}
	if rd.over {
		d.HealthHeld = "more than " + strconv.Itoa(maxEvents) + " health changes: the list is not kept"
	} else {
		d.Health = append(d.Health, rd.trans...)
	}
	d.Serials = serialDoc{Segments: rd.ser.segments, Duplicate: rd.ser.duplicate, OverCap: rd.ser.overCap}
	rows := make(map[int64]*dayRow, len(rd.rows))
	for day, row := range rd.rows {
		r := *row
		r.Records, r.Loss, r.Undecoded = maps.Clone(r.Records), maps.Clone(r.Loss), maps.Clone(r.Undecoded)
		r.NotOK, r.NotKnown = float64(r.notOK)/1e9, float64(r.notKnown)/1e9
		rows[day] = &r
	}
	if rd.ser.cur != nil {
		rd.ser.cur.holes(func(missing uint64, at int64) {
			if r := rows[dayOf(at)]; r != nil {
				r.Gaps++
				r.Missing = satAdd(r.Missing, missing)
			}
		})
	}
	d.Days = []dayRow{}
	for _, day := range slices.Sorted(maps.Keys(rows)) {
		d.Days = append(d.Days, *rows[day])
	}
	if n := len(d.Days); n > 0 {
		d.Days[0].Earlier = st.from > 0
		d.Days[n-1].Later = st.next < len(st.seals) || len(d.Unsealed) > 0
	}
	return d
}
