package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const (
	// silence is the longest time between two records that is not counted: the collector writes stats every 60 s,
	// so a longer one is a suspend, a stop or records the judge cannot account for.
	silence = int64(90 * time.Second)
	// minUID is the first uid exec.jsonl holds (ADR 0082 point 4: 1000 or more). Above it are users, and also
	// nobody (65534), systemd's dynamic uids and subordinate uids: they are listed too.
	minUID = 1000
	// Caps on what the read keeps in memory (R5, T20): past maxDays the read stops as UNKNOWN, past the others it
	// says so.
	maxEvents  = 1 << 16
	maxHeld    = 4096
	maxKeys    = 256
	maxDays    = 1 << 12
	ownCapture = 4 << 10
	dayNS      = int64(24 * time.Hour)
)

var errTooManyDays = errors.New("records on more than 4096 UTC days")

// transition is a change of the collector's health: a health record, or a start or stop of the collector, at its
// own time when that is earlier than when the store took it.
type transition struct {
	Seq   uint64 `json:"seq"`
	At    string `json:"time"`
	Kind  string `json:"kind"`
	State string `json:"state"`
}

// keyCount is what one audit rule key stored.
type keyCount struct {
	Records uint64 `json:"records"`
	Bytes   uint64 `json:"bytes"`
}

// execCounts counts a day's execs by what became of them. Successful is the next five together; the last three
// are execs the judge counts and never lists: execveat, a 32-bit execve, a line the strict reading refused.
type execCounts struct {
	Successful uint64 `json:"successful"`
	Listed     uint64 `json:"listed"`
	OverCap    uint64 `json:"not_listed_over_max_runs"`
	Outside    uint64 `json:"not_listed_before_the_window"`
	Partial    uint64 `json:"fields_not_decoded"`
	System     uint64 `json:"system_uid"`
	Execveat   uint64 `json:"execveat_not_listed"`
	OtherArch  uint64 `json:"other_arch_not_listed"`
	Refused    uint64 `json:"refused_by_strict_reading"`
}

// evidence is what a day's records say about what the store may lack: no count of it says that nothing was lost.
type evidence struct {
	Loss       map[string]uint64 `json:"loss_by_stage"`
	LossErrors uint64            `json:"loss_records_not_decoded"`
	OwnUnknown uint64            `json:"own_records_unknown"`
	HealthLost uint64            `json:"health_records_lost"`
	Gaps       uint64            `json:"serial_gaps"`
	Missing    uint64            `json:"serials_missing"`
	NotOK      float64           `json:"seconds_not_ok"`
	NotKnown   float64           `json:"seconds_not_known"`
	StoreLag   *int64            `json:"max_store_lag_ms"`
	ArrivalLag *int64            `json:"max_arrival_lag_ms"`
	Silences   uint64            `json:"silences_over_90s"`
	ClockBack  uint64            `json:"clock_went_back"`
	Undecoded  map[string]uint64 `json:"undecoded"`
}

// dayRow is one UTC day of records by their receive time: sums, and the health state carried into it.
type dayRow struct {
	Day     string            `json:"day"`
	Earlier bool              `json:"earlier_shards_not_read,omitempty"`
	Later   bool              `json:"later_shards_not_read,omitempty"`
	Records map[string]uint64 `json:"records"`
	Bytes   uint64            `json:"bytes"`
	Exec    execCounts        `json:"exec"`
	evidence
	day             int64
	notOK, notKnown int64
}

// Health as the read carries it from record to record; before the first health or started record it is not known.
const (
	healthNotKnown = iota
	healthOK
	healthNotOK
)

// reader is the judge's one pass over the shards, oldest first: sums by UTC day and what is carried from one
// record to the next, across shards.
type reader struct {
	rows       map[int64]*dayRow
	listFrom   int64 // the first day whose runs are listed, known from the seals before the read
	keys       map[string]*keyCount
	keysOver   uint64
	trans      []transition
	over       bool
	tooMany    bool
	ser        serials
	n          uint64
	lastAt     int64
	health     int
	cursor     int64  // health is counted up to here
	okSince    int64  // where the health became OK: a change away from it counts back no further
	lostHealth uint64 // the collector run's lost_health so far
	listed     uint64 // lines in exec.jsonl and the shard's part
	out        *bufio.Writer
}

func newReader(listFrom int64) *reader {
	return &reader{rows: map[int64]*dayRow{}, keys: map[string]*keyCount{}, listFrom: listFrom}
}

func dayText(day int64) string { return time.Unix(day*86400, 0).UTC().Format(time.DateOnly) }

// dayOf is the UTC day of a time, counted from 1970, rounded down.
func dayOf(ns int64) int64 {
	if ns < 0 && ns%dayNS != 0 {
		return ns/dayNS - 1
	}
	return ns / dayNS
}

// row is the day's row, made on first use; past maxDays the read cannot go on.
func (rd *reader) row(day int64) *dayRow {
	if r, ok := rd.rows[day]; ok {
		return r
	}
	r := &dayRow{Day: dayText(day), day: day, Records: map[string]uint64{},
		evidence: evidence{Loss: map[string]uint64{}, Undecoded: map[string]uint64{}}}
	if len(rd.rows) >= maxDays {
		rd.tooMany = true
		return r
	}
	rd.rows[day] = r
	return r
}

// add takes the next record.
func (rd *reader) add(r rawrecord.Record) error {
	at := r.Received
	row := rd.row(dayOf(at))
	if rd.n == 0 {
		rd.cursor = at
	} else {
		switch {
		case at < rd.lastAt:
			row.ClockBack++
		case at-rd.lastAt > silence:
			row.Silences++
		}
	}
	rd.count(at)
	rd.n++
	rd.lastAt = at
	row.Bytes += r.OrigLen
	var err error
	switch r.Provider {
	case store.SensorProvider:
		row.Records[r.Provider]++
		err = rd.sensor(row, r)
	case store.HealthProvider:
		row.Records[r.Provider]++
		rd.own(row, r)
	case store.LossProvider:
		row.Records[r.Provider]++
		storeLoss(row, r)
	default: // lossOf refuses it: what it held is not known
		row.Records["other"]++
		row.LossErrors++
	}
	if rd.tooMany {
		return errTooManyDays
	}
	return err
}

// count carries the health up to at: seconds not OK and not known, split at midnight. The clock going back
// counts nothing.
func (rd *reader) count(at int64) {
	rd.addHealth(rd.cursor, at, rd.health)
	rd.cursor = max(rd.cursor, at)
}

func (rd *reader) addHealth(from, to int64, health int) {
	for from < to && health != healthOK {
		end := min(to, (dayOf(from)+1)*dayNS)
		row := rd.row(dayOf(from))
		if health == healthNotOK {
			row.notOK += end - from
		} else {
			row.notKnown += end - from
		}
		from = end
	}
}

func (rd *reader) sensor(row *dayRow, r rawrecord.Record) error {
	if r.ProviderSeq == 0 {
		row.Undecoded["no serial"]++
	} else if !auditdOwn(r.Data) {
		rd.ser.add(r.ProviderSeq, r.Received, rd.gap)
	}
	if r.Truncated() { // lossOf counts it; its line is cut in two and not read
		row.Loss["truncated"]++
		row.Undecoded["truncated"]++
		return nil
	}
	rec, err := decodeLine(r.Data)
	if err != nil {
		row.Undecoded["not a Laurel line"]++
		return nil
	}
	if rec.Event {
		maxOf(&row.ArrivalLag, (r.Received-rec.EventNS)/int64(time.Millisecond))
	}
	rd.key(rec.Key, r.OrigLen)
	switch {
	case rec.Refused != "":
		row.Exec.Refused++
	case rec.Unlisted == unlistedExecveat:
		row.Exec.Execveat++
	case rec.Unlisted == unlistedOtherArch:
		row.Exec.OtherArch++
	}
	if !rec.Exec {
		return nil
	}
	row.Exec.Successful++
	switch {
	case !rec.Whole:
		row.Exec.Partial++
		return nil
	case rec.Run.UID < minUID:
		row.Exec.System++
		return nil
	case row.day < rd.listFrom:
		row.Exec.Outside++
		return nil
	case rd.listed >= maxRuns:
		row.Exec.OverCap++
		return nil
	}
	line := rec.Run
	line.EventTime, line.Received, line.Serial = timeText(rec.EventNS), timeText(r.Received), r.ProviderSeq
	b, err := json.Marshal(line)
	if err != nil {
		return err //nolint:wrapcheck // a run of fixed types always encodes
	}
	if _, err := rd.out.Write(append(b, '\n')); err != nil {
		return err //nolint:wrapcheck // the caller names the file
	}
	row.Exec.Listed++
	rd.listed++
	return nil
}

// gap counts a hole in the serials on the day its later end was received.
func (rd *reader) gap(missing uint64, at int64) {
	row := rd.row(dayOf(at))
	row.Gaps++
	row.Missing = satAdd(row.Missing, missing)
}

func maxOf(p **int64, v int64) {
	if *p == nil || v > **p {
		*p = &v
	}
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

func (rd *reader) key(k string, size uint64) {
	c, ok := rd.keys[k]
	if !ok {
		if len(rd.keys) >= maxKeys {
			rd.keysOver++
			return
		}
		c = &keyCount{}
		rd.keys[k] = c
	}
	c.Records++
	c.Bytes += size
}

// change is a health change at the record's own time when that is earlier than when the store took it. A change
// away from OK counts as not OK back to that time; one to OK counts nothing back.
func (rd *reader) change(r rawrecord.Record, at int64, kind, state string) {
	t := r.Received
	if at > 0 && at < t {
		t = at
	}
	next := healthNotOK
	if state == "OK" {
		next = healthOK
	}
	switch {
	case next == healthNotOK && rd.health == healthOK:
		rd.addHealth(max(t, rd.okSince), rd.cursor, healthNotOK)
	case next == healthOK && rd.health != healthOK:
		rd.okSince = rd.cursor
	}
	rd.health = next
	if len(rd.trans) >= maxEvents {
		rd.over = true
		return
	}
	rd.trans = append(rd.trans, transition{Seq: r.Seq, At: timeText(t), Kind: kind, State: state})
}

// own reads one of the collector's own records (internal/collector/writer.go). One that does not decode may have
// been a health change: the health is not known from it on.
func (rd *reader) own(row *dayRow, r rawrecord.Record) {
	var head struct {
		SchemaVersion int    `json:"schema_version"`
		Kind          string `json:"kind"`
		At            int64  `json:"at"`
	}
	if len(r.Data) > ownCapture || json.Unmarshal(r.Data, &head) != nil || head.SchemaVersion != 1 {
		row.OwnUnknown++
		rd.health = healthNotKnown
		return
	}
	switch head.Kind {
	case "health":
		var h struct {
			State string `json:"state"`
		}
		if json.Unmarshal(r.Data, &h) != nil || h.State == "" {
			row.OwnUnknown++
			rd.health = healthNotKnown
			return
		}
		rd.change(r, head.At, "health", h.State)
	case "started":
		var s struct {
			Info struct {
				BootID string `json:"boot_id"`
			} `json:"info"`
		}
		_ = json.Unmarshal(r.Data, &s) // a started record without a boot id begins a new run of the serials
		rd.ser.started(s.Info.BootID)
		rd.lostHealth = 0
		rd.change(r, head.At, "started", "UNKNOWN starting")
	case "stopping":
		rd.change(r, head.At, "stopping", "UNKNOWN stopped")
	case "stats", "lag":
		rd.stats(row, r)
	case "lost":
		lost(row, r)
	case "connection", "refused":
	default: // a kind the judge does not know may have been a health change
		row.OwnUnknown++
		rd.health = healthNotKnown
	}
}

// stats reads the store's lag and the health records that gave way: lost_health is the collector run's running
// total, so its rise is what gave way since the last stats; one that falls began a run whose start was not read.
func (rd *reader) stats(row *dayRow, r rawrecord.Record) {
	var l struct {
		MaxLag     *int64  `json:"max_lag_ms"`
		Lag        *int64  `json:"lag_ms"`
		LostHealth *uint64 `json:"lost_health"`
	}
	_ = json.Unmarshal(r.Data, &l) // a lag that does not decode is no lag
	for _, ms := range []*int64{l.MaxLag, l.Lag} {
		if ms != nil {
			maxOf(&row.StoreLag, *ms)
		}
	}
	if l.LostHealth == nil {
		return
	}
	n := *l.LostHealth
	if n >= rd.lostHealth {
		row.HealthLost = satAdd(row.HealthLost, n-rd.lostHealth)
	} else {
		row.HealthLost = satAdd(row.HealthLost, n)
	}
	rd.lostHealth = n
}

// lossStages are internal/collector's stages, as lossOf knows them.
var lossStages = map[string]bool{"cap": true, "queue": true, "framing": true, "store": true, "shutdown": true,
	"kernel": true, "dispatcher": true}

// lost is lossOf on a lost record: decoded strictly, its stage known, its count at least 1, the dispatcher's
// counted once (flips merged while the store was down, ADR 0038).
func lost(row *dayRow, r rawrecord.Record) {
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
		row.LossErrors++
		return
	}
	n := l.Count
	if l.Stage == "dispatcher" {
		n = 1
	}
	row.Loss[l.Stage] = satAdd(row.Loss[l.Stage], n)
}

// storeLoss is lossOf on the store's own loss record: records dropped at the cap.
func storeLoss(row *dayRow, r rawrecord.Record) {
	var l struct {
		SchemaVersion int    `json:"schema_version"`
		Dropped       uint64 `json:"dropped"`
		FirstReceived int64  `json:"first_received"`
		LastReceived  int64  `json:"last_received"`
	}
	if strictDecode(r.Data, &l) != nil || l.SchemaVersion != 1 || l.Dropped == 0 {
		row.LossErrors++
		return
	}
	row.Loss["cap"] = satAdd(row.Loss["cap"], l.Dropped)
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func timeText(ns int64) string { return time.Unix(0, ns).UTC().Format(time.RFC3339Nano) }
