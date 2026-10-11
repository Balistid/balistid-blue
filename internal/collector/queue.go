package collector

import (
	"sync"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// Stage names where a line can be lost (ADR 0016, point 3).
type Stage string

// StageQueue counts records dropped because the queue was full.
const StageQueue Stage = "queue"

// Loss sums what one stage lost: how many records and delivered bytes, and the provider seq and receive
// time of the first and the last, which find them again in auditd's own log.
type Loss struct {
	Count, Bytes      uint64
	FirstSeq, LastSeq uint64
	FirstAt, LastAt   int64
}

// Losses counts lost records per stage outside the queue, so counting never waits for the store and
// never competes with records for room (ADR 0016, point 3).
type Losses struct {
	mu sync.Mutex
	by map[Stage]Loss
}

// Add counts r as lost at stage.
func (l *Losses) Add(stage Stage, r rawrecord.Record) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.by == nil {
		l.by = map[Stage]Loss{}
	}
	c := l.by[stage]
	if c.Count == 0 {
		c.FirstSeq, c.FirstAt = r.ProviderSeq, r.Received
	}
	c.Count++
	c.Bytes += r.OrigLen
	c.LastSeq, c.LastAt = r.ProviderSeq, r.Received
	l.by[stage] = c
}

// Take returns the losses counted since the last Take and starts counting afresh.
func (l *Losses) Take() map[Stage]Loss {
	l.mu.Lock()
	defer l.mu.Unlock()
	by := l.by
	l.by = nil
	return by
}

// Queue hands records from the reader to the writer. It is bounded in bytes and never blocks: a record
// that does not fit is dropped at once and counted, so Laurel never waits on the store (ADR 0016,
// point 3).
type Queue struct {
	mu        sync.Mutex
	recs      []rawrecord.Record
	bytes     int
	max       int
	highWater int
	ready     chan struct{}
	loss      *Losses
}

// NewQueue returns a queue holding at most maxBytes of encoded records, counting drops in loss.
func NewQueue(maxBytes int, loss *Losses) *Queue {
	return &Queue{max: maxBytes, ready: make(chan struct{}, 1), loss: loss}
}

// Push queues r, or drops and counts it when it does not fit.
func (q *Queue) Push(r rawrecord.Record) {
	size := r.EncodedLen()
	q.mu.Lock()
	if q.bytes+size > q.max {
		q.mu.Unlock()
		q.loss.Add(StageQueue, r)
		return
	}
	q.recs = append(q.recs, r)
	q.bytes += size
	q.highWater = max(q.highWater, q.bytes)
	q.mu.Unlock()
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// Ready is signalled after a Push that queued a record; the writer then drains.
func (q *Queue) Ready() <-chan struct{} { return q.ready }

// Drain returns every queued record, oldest first, and empties the queue.
func (q *Queue) Drain() []rawrecord.Record {
	q.mu.Lock()
	defer q.mu.Unlock()
	recs := q.recs
	q.recs, q.bytes = nil, 0
	return recs
}

// HighWater returns the most bytes the queue held since the last call, and resets it.
func (q *Queue) HighWater() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	hw := q.highWater
	q.highWater = q.bytes
	return hw
}
