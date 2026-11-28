package main

import (
	"encoding/hex"
	"math"
	"sort"
	"strconv"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/store"
)

// The judge's status in state.json: never OK (R6). COMPLETE says every sealed shard was read, not that the
// recorder was healthy; that is in the health changes and clean intervals.
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
	Period       *periodDoc           `json:"period"`
	Records      map[string]uint64    `json:"records"`
	Bytes        uint64               `json:"bytes"`
	Health       []transition         `json:"health_changes"`
	HealthLost   uint64               `json:"health_records_lost"`
	HealthHeld   string               `json:"health_changes_withheld,omitempty"`
	Loss         map[string]uint64    `json:"loss_by_stage"`
	LossErrors   uint64               `json:"loss_records_not_decoded"`
	OwnUnknown   uint64               `json:"own_records_unknown"`
	Lag          *lag                 `json:"largest_lag"`
	Serials      serialDoc            `json:"serials"`
	Keys         map[string]*keyCount `json:"by_rule_key"`
	KeysOver     uint64               `json:"rule_keys_over_cap"`
	Undecoded    map[string]uint64    `json:"undecoded"`
	Silences     uint64               `json:"silences_over_90s"`
	ClockBack    uint64               `json:"clock_went_back"`
	Clean        cleanDoc             `json:"clean"`
	Exec         execDoc              `json:"exec"`
	Unsealed     []string             `json:"unsealed_not_read"`
	TornIndex    bool                 `json:"torn_index_line"`
	ReadLimitMin int                  `json:"read_limit_min"`
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
	Reason string `json:"reason"`
}

type periodDoc struct {
	From     string `json:"from"`
	To       string `json:"to"`
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
}

// serialDoc is the gaps in the kernel's serials: serials no record of their boot's run holds. Those missing in the
// last HoldS of the newest shard are held, not counted: the unsealed shard may hold them.
type serialDoc struct {
	Gaps      uint64 `json:"gaps"`
	Missing   uint64 `json:"serials_missing"`
	Duplicate uint64 `json:"duplicate"`
	HeldAtEnd uint64 `json:"held_at_the_end"`
	HoldS     int    `json:"hold_s"`
	OverCap   uint64 `json:"gaps_counted_at_the_cap"`
	Segments  int    `json:"segments"`
}

// cleanDoc is the intervals with health OK, no loss and no gap (ADR 0082 point 3); UNKNOWN with its reason when
// the judge cannot tell, never an empty list that reads as none.
type cleanDoc struct {
	State     string     `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	Seconds   float64    `json:"seconds"`
	Intervals []interval `json:"intervals"`
}

type interval struct {
	From string `json:"from"`
	To   string `json:"to"`
	from int64
	to   int64
}

type execDoc struct {
	Since string `json:"since"`
	execCounts
}

// state is what the judge knows after the shards it read, newest first.
type state struct {
	doc      stateDoc
	merged   int   // shards read; their exec lines are already in exec.jsonl
	newestAt int64 // the newest record read: nothing after it is known
	older    struct {
		firstAt int64 // the first record of the oldest shard merged
		n       uint64
	}
	segs       []*segment // the serials' segments that may still change: the oldest and the newest
	closed     gapCount   // the segments between them
	closedSegs int
	open       []span // spans that start in a shard not read yet
	spans      []span
	trans      []transition
	over       bool
}

func newState(seals []store.Seal, sizes int64, cutoff int64, limitMin int) *state {
	st := &state{}
	d := &st.doc
	d.Schema, d.Judge, d.Version, d.Status = 1, "ADR 0082", buildinfo.Version, statusReading
	d.Store = storeDoc{Seals: len(seals), Bytes: sizes}
	if n := len(seals); n > 0 {
		l := seals[n-1]
		d.Store.LastSeal = &sealOf{Name: l.Name, First: l.First, Last: l.Last, SHA256: hex.EncodeToString(l.SHA256[:]),
			Sealed: timeText(l.Sealed * 1e9)}
	}
	d.Read, d.Records, d.Loss, d.Keys, d.Undecoded = []shardDoc{}, map[string]uint64{}, map[string]uint64{},
		map[string]*keyCount{}, map[string]uint64{}
	d.Health, d.Unsealed = []transition{}, []string{}
	d.Serials.HoldS = int(gapHold / 1e9)
	d.ReadLimitMin = limitMin
	d.Exec.Since = timeText(cutoff)
	for i := len(seals) - 1; i >= 0; i-- {
		d.NotRead = append(d.NotRead, notReadDoc{Name: seals[i].Name, Reason: "not read yet"})
	}
	if d.NotRead == nil {
		d.NotRead = []notReadDoc{}
	}
	return st
}

// merge adds a shard that was read whole, the one just older than every shard merged before.
func (st *state) merge(name string, a *shardAcc) {
	d := &st.doc
	d.Read = append(d.Read, shardDoc{Name: name, First: a.firstSeq, Last: a.lastSeq, Records: a.n})
	d.NotRead = d.NotRead[1:]
	for k, v := range a.records {
		d.Records[k] += v
	}
	d.Bytes += a.bytes
	for k, v := range a.loss {
		d.Loss[k] = satAdd(d.Loss[k], v)
	}
	for k, v := range a.undecoded {
		d.Undecoded[k] += v
	}
	for k, c := range a.keys {
		if t, ok := d.Keys[k]; ok {
			t.Records, t.Bytes = t.Records+c.Records, t.Bytes+c.Bytes
		} else if len(d.Keys) < maxKeys {
			d.Keys[k] = &keyCount{Records: c.Records, Bytes: c.Bytes}
		} else {
			d.KeysOver += c.Records
		}
	}
	d.KeysOver += a.keysOver
	d.LossErrors += a.lossErrors
	d.HealthLost = satAdd(d.HealthLost, a.healthLost)
	d.OwnUnknown += a.ownUnknown
	d.Silences += a.silences
	d.ClockBack += a.clockBack
	if a.lagNS >= 0 && (d.Lag == nil || a.lagNS > d.Lag.MS) {
		l := a.lag
		d.Lag = &l
	}
	addExecs(&d.Exec.execCounts, a.execs)
	st.joinTimes(a)
	st.joinSerials(a)
	st.over = st.over || a.over || len(st.trans)+len(a.transitions) > maxEvents || len(st.spans)+len(a.spans) > maxEvents
	if !st.over {
		st.trans = append(a.transitions, st.trans...)
	}
	if a.n > 0 {
		if d.Period != nil {
			d.Period.From, d.Period.FirstSeq = timeText(a.firstAt), a.firstSeq
		} else {
			st.newestAt = a.lastAt
			d.Period = &periodDoc{From: timeText(a.firstAt), To: timeText(a.lastAt), FirstSeq: a.firstSeq, LastSeq: a.lastSeq}
		}
	}
	st.merged++
	if a.n > 0 { // an empty shard is no neighbour: the silence is between the shards around it
		st.older.firstAt, st.older.n = a.firstAt, a.n
	}
}

func addExecs(t *execCounts, a execCounts) {
	t.Successful += a.Successful
	t.Exported += a.Exported
	t.System += a.System
	t.Older += a.Older
	t.Partial += a.Partial
	t.Execveat += a.Execveat
	t.OtherArch += a.OtherArch
}

// joinTimes keeps a's spans, ends the spans of newer shards that start before them, and adds the silence or
// clock step between a and the newer shard.
func (st *state) joinTimes(a *shardAcc) {
	var open []span
	for _, s := range a.spans {
		if s.fromOwn {
			open = append(open, s)
		} else {
			st.addSpan(s)
		}
	}
	if a.ownSeen {
		for _, s := range st.open {
			s.From = a.lastOwnAt
			if s.first > 0 && s.first < s.From {
				s.From = s.first
			}
			s.fromOwn = false
			st.addSpan(s)
		}
		st.open = nil
	}
	st.open = append(st.open, open...)
	if st.merged > 0 && st.older.n > 0 && a.n > 0 {
		switch newer := st.older.firstAt; {
		case newer < a.lastAt:
			st.doc.ClockBack++
			st.addSpan(span{From: newer, To: a.lastAt})
		case newer-a.lastAt > silence:
			st.doc.Silences++
			st.addSpan(span{From: a.lastAt, To: newer})
		}
	}
}

func (st *state) addSpan(s span) {
	if len(st.spans) >= maxEvents {
		st.over = true
		return
	}
	st.spans = append(st.spans, s)
}

// joinSerials puts a's segments before the ones read so far, its last into the oldest of those when that one goes
// on from it, and counts every segment that can no longer change: all but the oldest and the newest.
func (st *state) joinSerials(a *shardAcc) {
	segs := a.ser.segs
	if a.ser.startNext && len(st.segs) > 0 && !st.segs[0].started { // a started record after a's last serial
		st.segs[0].started, st.segs[0].boot = true, a.ser.startBoot
	}
	if n := len(segs); n > 0 && len(st.segs) > 0 && continues(segs[n-1], st.segs[0]) {
		merge(segs[n-1], st.segs[0])
		segs = segs[:n-1]
	}
	st.segs = append(append([]*segment(nil), segs...), st.segs...)
	for len(st.segs) > 2 {
		st.closed.add(st.segs[1], math.MaxInt64)
		st.segs = append(st.segs[:1], st.segs[2:]...)
		st.closedSegs++
	}
	st.over = st.over || len(st.closed.spans) > maxEvents
}

// render fills in what depends on every shard read: the serials' gaps, holding those at the end of the newest
// shard that the unsealed one may still fill, and the clean intervals.
func (st *state) render(written int64) stateDoc {
	d := st.doc
	d.Written = timeText(written)
	c := st.closed
	c.spans = append([]span(nil), c.spans...)
	for i, g := range st.segs {
		held := int64(math.MaxInt64)
		if i == len(st.segs)-1 {
			held = st.newestAt - gapHold
		}
		c.add(g, held)
	}
	d.Serials.Gaps, d.Serials.Missing, d.Serials.Duplicate = c.gaps, c.missing, c.duplicate
	d.Serials.HeldAtEnd, d.Serials.OverCap, d.Serials.Segments = c.held, c.overCap, len(st.segs)+st.closedSegs
	d.Health = []transition{}
	if st.over {
		d.HealthHeld = "more than " + strconv.Itoa(maxEvents) + " health changes or spans: the list is not kept"
	} else {
		d.Health = append(d.Health, st.trans...)
	}
	d.Clean = st.clean(c.spans)
	return d
}

// clean is the intervals where the health state is OK, cut by every span. Before the oldest shard's first health
// change the state is not known, and after the newest record nothing is.
func (st *state) clean(extra []span) cleanDoc {
	switch {
	case st.over:
		return cleanDoc{State: statusUnknown, Reason: "more than " + strconv.Itoa(maxEvents) + " health changes or spans", Intervals: []interval{}}
	case st.doc.Period == nil:
		return cleanDoc{State: statusUnknown, Reason: "no record read", Intervals: []interval{}}
	case len(st.doc.NotRead) > 0: // a gap or a loss at the boundary to an older shard is not known
		return cleanDoc{State: statusUnknown, Reason: "not every sealed shard was read", Intervals: []interval{}}
	}
	end := st.newestAt
	var ok []interval
	for i, t := range st.trans {
		if t.State != "OK" {
			continue
		}
		to := end
		if i+1 < len(st.trans) {
			to = st.trans[i+1].at
		}
		ok = append(ok, interval{from: t.at, to: to})
	}
	spans := append(append([]span(nil), st.spans...), extra...)
	for _, s := range st.open { // their start is in a shard not read
		spans = append(spans, span{From: math.MinInt64, To: s.To})
	}
	sortSpans(spans)
	out := cleanDoc{State: "KNOWN", Intervals: []interval{}}
	for _, iv := range ok {
		for _, piece := range cut(iv, spans) {
			piece.From, piece.To = timeText(piece.from), timeText(piece.to)
			out.Intervals = append(out.Intervals, piece)
			out.Seconds += float64(piece.to-piece.from) / 1e9
		}
	}
	return out
}

// cut is iv without the spans, sorted by start; a span of no length still splits it.
func cut(iv interval, spans []span) []interval {
	var out []interval
	from := iv.from
	i := sort.Search(len(spans), func(i int) bool { return spans[i].From > iv.to })
	for _, s := range spans[:i] {
		if s.To < from {
			continue
		}
		if s.From > from {
			out = append(out, interval{from: from, to: s.From})
		}
		from = max(from, s.To)
	}
	if from < iv.to {
		out = append(out, interval{from: from, to: iv.to})
	}
	return out
}
