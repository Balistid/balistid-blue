package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"math"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const (
	// silence is the longest time between two records that a clean interval spans: the collector writes stats
	// every 60 s, so a longer silence is a suspend, a stop or records the judge cannot account for.
	silence = int64(90 * time.Second)
	// gapHold is how long a missing serial may arrive late before it is a gap. ADR 0062 sets gap_hold_s by a
	// range measurement that has not run; 60 s is far above the lateness a Laurel line has in the range.
	gapHold = int64(60 * time.Second)
	// minUID is the first uid exec.jsonl holds: the users', not the system's (ADR 0082 point 4).
	minUID = 1000
	// Caps on what one shard keeps in memory (R5, T20); past them the judge says so and reports no clean interval.
	maxEvents  = 1 << 16
	maxHeld    = 4096
	maxKeys    = 256
	ownCapture = 4 << 10
)

// span is a time no clean interval covers. fromOwn marks a span that starts at the collector's previous own
// record, which is in an older shard: the merge sets From to that record's time, or to first, the loss's own first
// time, when that is earlier.
type span struct {
	From, To int64
	fromOwn  bool
	first    int64
}

// transition is a change of the collector's health: a health record, or a start or stop of the collector.
type transition struct {
	Seq   uint64 `json:"seq"`
	At    string `json:"time"`
	Kind  string `json:"kind"`
	State string `json:"state"`
	at    int64
}

// keyCount is what one audit rule key stored.
type keyCount struct {
	Records uint64 `json:"records"`
	Bytes   uint64 `json:"bytes"`
}

// execCounts counts the successful execs of a shard by what became of them.
type execCounts struct {
	Successful uint64 `json:"successful"`
	Exported   uint64 `json:"exported"`
	System     uint64 `json:"system_uid"`
	Older      uint64 `json:"older_than_7_days"`
	Partial    uint64 `json:"fields_not_decoded"`
	Execveat   uint64 `json:"execveat_not_listed"`
	OtherArch  uint64 `json:"other_arch_not_listed"`
}

// lag is the largest lag the collector reported and when.
type lag struct {
	MS int64  `json:"ms"`
	At string `json:"time"`
}

// shardAcc is what the judge learns from one shard, read in seq order. It knows nothing of the shards around
// it; the merge joins it to the newer one it read before.
type shardAcc struct {
	cutoff                 int64 // runs received before it are older than the 7 days
	out                    *bufio.Writer
	records                map[string]uint64
	bytes                  uint64
	firstSeq, lastSeq      uint64
	firstAt, lastAt        int64
	n                      uint64
	ownSeen                bool
	lastOwnAt              int64
	keys                   map[string]*keyCount
	keysOver               uint64
	transitions            []transition
	spans                  []span
	over                   bool // transitions or spans past maxEvents
	loss                   map[string]uint64
	lossErrors, ownUnknown uint64
	silences, clockBack    uint64
	lag                    lag
	lagNS                  int64
	undecoded              map[string]uint64
	execs                  execCounts
	ser                    serials
}

func newShardAcc(cutoff int64, out *bufio.Writer) *shardAcc {
	return &shardAcc{cutoff: cutoff, out: out, records: map[string]uint64{}, keys: map[string]*keyCount{},
		loss: map[string]uint64{}, undecoded: map[string]uint64{}, lagNS: -1}
}

// add takes the next record of the shard.
func (a *shardAcc) add(r rawrecord.Record) error {
	if a.n == 0 {
		a.firstSeq, a.firstAt = r.Seq, r.Received
	} else {
		a.between(a.lastAt, r.Received)
	}
	prev := a.lastAt
	a.n++
	a.lastSeq, a.lastAt = r.Seq, r.Received
	a.bytes += r.OrigLen
	switch r.Provider {
	case store.SensorProvider:
		a.records[r.Provider]++
		return a.sensor(r, prev)
	case store.HealthProvider:
		a.records[r.Provider]++
		a.health(r)
	case store.LossProvider:
		a.records[r.Provider]++
		a.storeLoss(r)
	default: // lossOf refuses it: what it held is not known
		a.records["other"]++
		a.lossErrors++
		a.addSpan(span{From: prev, To: r.Received, fromOwn: a.n == 1})
	}
	return nil
}

// between keeps a clean interval from spanning a silence or a clock that went back between two records.
func (a *shardAcc) between(prev, at int64) {
	switch {
	case at < prev:
		a.clockBack++
		a.addSpan(span{From: at, To: prev})
	case at-prev > silence:
		a.silences++
		a.addSpan(span{From: prev, To: at})
	}
}

func (a *shardAcc) addSpan(s span) {
	if len(a.spans) >= maxEvents {
		a.over = true
		return
	}
	a.spans = append(a.spans, s)
}

// ownSpan is a loss or an unknown record of the collector's: it may have happened any time since its previous
// own record, so that is where the span starts.
func (a *shardAcc) ownSpan(at int64, first int64) {
	s := span{From: a.lastOwnAt, To: at, fromOwn: !a.ownSeen, first: first}
	if a.ownSeen && first > 0 && first < s.From {
		s.From = first
	}
	a.addSpan(s)
}

func (a *shardAcc) sensor(r rawrecord.Record, prev int64) error {
	if r.ProviderSeq == 0 {
		a.undecoded["no serial"]++
	} else if !auditdOwn(r.Data) {
		a.ser.add(r.ProviderSeq, r.Received)
	}
	if r.Truncated() { // lossOf counts it; its line is cut in two and not read
		a.loss["truncated"]++
		a.undecoded["truncated"]++
		a.addSpan(span{From: prev, To: r.Received, fromOwn: a.n == 1})
		return nil
	}
	rec, err := decodeLine(r.Data)
	if err != nil {
		a.undecoded["not a Laurel line"]++
		return nil
	}
	a.key(rec.Key, r.OrigLen)
	switch {
	case rec.Refused != "":
		a.undecoded[rec.Refused]++
	case rec.Unlisted == unlistedExecveat:
		a.execs.Execveat++
	case rec.Unlisted == unlistedOtherArch:
		a.execs.OtherArch++
	}
	if !rec.Exec {
		return nil
	}
	a.execs.Successful++
	switch {
	case !rec.Whole:
		a.execs.Partial++
		return nil
	case rec.Run.UID < minUID:
		a.execs.System++
		return nil
	case r.Received < a.cutoff:
		a.execs.Older++
		return nil
	}
	line := rec.Run
	line.Time, line.Serial = timeText(r.Received), r.ProviderSeq
	b, err := json.Marshal(line)
	if err != nil {
		return err //nolint:wrapcheck // a run of fixed types always encodes
	}
	if _, err := a.out.Write(append(b, '\n')); err != nil {
		return err //nolint:wrapcheck // the caller names the file
	}
	a.execs.Exported++
	return nil
}

// auditdOwn reports a line of auditd's own (DAEMON_*): its number is auditd's, not the kernel's (ADR 0062 point 1).
// Laurel writes the ID first and the record type right after it.
func auditdOwn(data []byte) bool {
	end := bytes.IndexByte(data[min(len(data), len(`{"ID":"`)):], '"')
	if end < 0 {
		return false
	}
	return bytes.HasPrefix(data[len(`{"ID":"`)+end+1:], []byte(`,"DAEMON_`))
}

func (a *shardAcc) key(k string, size uint64) {
	c, ok := a.keys[k]
	if !ok {
		if len(a.keys) >= maxKeys {
			a.keysOver++
			return
		}
		c = &keyCount{}
		a.keys[k] = c
	}
	c.Records++
	c.Bytes += size
}

func (a *shardAcc) transition(seq uint64, at int64, kind, state string) {
	if len(a.transitions) >= maxEvents {
		a.over = true
		return
	}
	a.transitions = append(a.transitions, transition{Seq: seq, At: timeText(at), Kind: kind, State: state, at: at})
}

// health reads one of the collector's own records (internal/collector/writer.go). A kind it does not know, or a
// record that does not decode, is not healthy: a span, counted.
func (a *shardAcc) health(r rawrecord.Record) {
	defer func() { a.ownSeen, a.lastOwnAt = true, r.Received }()
	var head struct {
		SchemaVersion int    `json:"schema_version"`
		Kind          string `json:"kind"`
	}
	if len(r.Data) > ownCapture || json.Unmarshal(r.Data, &head) != nil || head.SchemaVersion != 1 {
		a.ownUnknown++
		a.ownSpan(r.Received, 0)
		return
	}
	switch head.Kind {
	case "health":
		var h struct {
			State string `json:"state"`
		}
		if json.Unmarshal(r.Data, &h) != nil || h.State == "" {
			a.ownUnknown++
			a.ownSpan(r.Received, 0)
			return
		}
		a.transition(r.Seq, r.Received, "health", h.State)
	case "started":
		var s struct {
			Info struct {
				BootID string `json:"boot_id"`
			} `json:"info"`
		}
		_ = json.Unmarshal(r.Data, &s) // a started record without a boot id goes on in the same boot
		a.ser.started(s.Info.BootID)
		a.transition(r.Seq, r.Received, "started", "UNKNOWN starting")
	case "stopping":
		a.transition(r.Seq, r.Received, "stopping", "UNKNOWN stopped")
	case "stats", "lag":
		var l struct {
			MaxLag *int64 `json:"max_lag_ms"`
			Lag    *int64 `json:"lag_ms"`
		}
		_ = json.Unmarshal(r.Data, &l) // a lag that does not decode is no lag
		for _, ms := range []*int64{l.MaxLag, l.Lag} {
			if ms != nil && *ms > a.lagNS {
				a.lagNS, a.lag = *ms, lag{MS: *ms, At: timeText(r.Received)}
			}
		}
	case "lost":
		a.lost(r)
	case "connection", "refused":
	default:
		a.ownUnknown++
		a.ownSpan(r.Received, 0)
	}
}

// lossStages are internal/collector's stages, as lossOf knows them.
var lossStages = map[string]bool{"cap": true, "queue": true, "framing": true, "store": true, "shutdown": true,
	"kernel": true, "dispatcher": true}

// lost is lossOf on a lost record: decoded strictly, its stage known, its count at least 1, the dispatcher's
// counted once (flips merged while the store was down, ADR 0038).
func (a *shardAcc) lost(r rawrecord.Record) {
	var l struct {
		SchemaVersion int    `json:"schema_version"`
		At            int64  `json:"at"`
		NoteSeq       uint64 `json:"note_seq"`
		Kind          string `json:"kind"`
		Stage         string `json:"stage"`
		Count         uint64 `json:"count"`
		Bytes         uint64 `json:"bytes"`
		FirstSeq      uint64 `json:"first_seq"`
		LastSeq       uint64 `json:"last_seq"`
		FirstAt       int64  `json:"first_at"`
		LastAt        int64  `json:"last_at"`
	}
	if strictDecode(r.Data, &l) != nil || !lossStages[l.Stage] || l.SchemaVersion != 1 || l.Count == 0 {
		a.lossErrors++
		a.ownSpan(r.Received, 0)
		return
	}
	n := l.Count
	if l.Stage == "dispatcher" {
		n = 1
	}
	a.loss[l.Stage] = satAdd(a.loss[l.Stage], n)
	a.ownSpan(r.Received, l.FirstAt)
}

// storeLoss is lossOf on the store's own loss record: records dropped at the cap, with their receive times.
func (a *shardAcc) storeLoss(r rawrecord.Record) {
	var l struct {
		SchemaVersion int    `json:"schema_version"`
		Dropped       uint64 `json:"dropped"`
		FirstReceived int64  `json:"first_received"`
		LastReceived  int64  `json:"last_received"`
	}
	if strictDecode(r.Data, &l) != nil || l.SchemaVersion != 1 || l.Dropped == 0 {
		a.lossErrors++
		a.ownSpan(r.Received, 0)
		return
	}
	a.loss["cap"] = satAdd(a.loss["cap"], l.Dropped)
	a.ownSpan(r.Received, l.FirstReceived)
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func timeText(ns int64) string { return time.Unix(0, ns).UTC().Format(time.RFC3339Nano) }
