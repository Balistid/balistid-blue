// Package collector takes Laurel's lines over its socket and hands them to the store as evidence
// without ever blocking Laurel (ADR 0016, 0017).
package collector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// readBufBytes is the read size; a line up to rawrecord.MaxBytes is gathered whole, a longer one streamed.
const readBufBytes = 64 << 10

// idPrefix opens every line of Laurel's: it serializes ID first (laurel src/types.rs).
const idPrefix = `{"ID":"`

// Counts are what the reader saw on its connections; the writer reports them in stats (ADR 0017).
type Counts struct {
	Records, Bytes, Truncated, Malformed uint64
}

// Reader turns Laurel's lines into records and queues them. A line is evidence, not our protocol: one
// that is not Laurel's JSON with its ID first is still stored, with provider seq 0, and counted
// malformed (ADR 0016, point 2).
type Reader struct {
	q      *Queue
	now    func() time.Time
	mu     sync.Mutex
	counts Counts
}

// NewReader returns a reader that queues into q and stamps records with now.
func NewReader(q *Queue, now func() time.Time) *Reader { return &Reader{q: q, now: now} }

// Counts returns what the reader has seen so far.
func (r *Reader) Counts() Counts {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts
}

// ReadConn reads one connection to EOF. A head cut by EOF is stored as malformed, as is a tail that
// opens a connection, because neither parses as a line of its own. It returns nil at EOF, ctx's error
// once ctx is done between lines, or the read error that ended the connection.
func (r *Reader) ReadConn(ctx context.Context, conn io.Reader) error {
	br := bufio.NewReaderSize(conn, readBufBytes)
	var l line
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("collector: read: %w", err)
		}
		chunk, err := br.ReadSlice('\n')
		end := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'
		if end {
			chunk = chunk[:len(chunk)-1]
		}
		l.add(chunk)
		switch {
		case end:
			r.emit(&l, true)
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if l.n > 0 {
				r.emit(&l, false)
			}
			return nil
		case err != nil:
			if l.n > 0 {
				r.emit(&l, false)
			}
			return fmt.Errorf("collector: read: %w", err)
		}
	}
}

// emit queues the line gathered in l and resets l; whole says the line ended in its newline.
func (r *Reader) emit(l *line, whole bool) {
	rec, ok := l.record(r.now().UnixNano())
	l.reset()
	r.mu.Lock()
	r.counts.Records++
	r.counts.Bytes += rec.OrigLen
	if !ok || !whole {
		r.counts.Malformed++
		rec.ProviderSeq = 0
	}
	if rec.Truncated() {
		r.counts.Truncated++
	}
	r.mu.Unlock()
	r.q.Push(rec)
}

// line gathers one line: whole while it fits rawrecord.MaxBytes, then its first half, a running hash
// and a window holding at least its last half.
type line struct {
	buf  []byte // the whole line, or its first MaxBytes/2 bytes once streaming
	tail []byte // streaming only: the latest bytes, at least MaxBytes/2 of them once that many arrived
	sum  hash.Hash
	n    uint64
}

func (l *line) add(b []byte) {
	l.n += uint64(len(b))
	if l.sum == nil && len(l.buf)+len(b) <= rawrecord.MaxBytes {
		l.buf = append(l.buf, b...)
		return
	}
	half := rawrecord.MaxBytes / 2
	if l.sum == nil {
		l.sum = sha256.New()
		l.sum.Write(l.buf)
		l.tail = append(make([]byte, 0, 2*half), l.buf[half:]...)
		l.buf = l.buf[:half]
	}
	l.sum.Write(b)
	l.tail = append(l.tail, b...)
	if len(l.tail) > 2*half {
		l.tail = append(l.tail[:0], l.tail[len(l.tail)-half:]...)
	}
}

func (l *line) reset() {
	l.buf, l.tail, l.sum, l.n = l.buf[:0], nil, nil, 0
}

// record returns l as a record and whether its head is a line of Laurel's: JSON whose first key is
// "ID". A streamed line is too long to validate; only its head's ID is read (ADR 0016, point 2).
func (l *line) record(received int64) (rawrecord.Record, bool) {
	seq, ok := providerSeq(l.buf)
	if l.sum == nil {
		if ok {
			ok = idMatches(l.buf)
		}
		return rawrecord.New(0, store.SensorProvider, seq, received, l.buf), ok
	}
	half := rawrecord.MaxBytes / 2
	r, err := rawrecord.FromParts(0, store.SensorProvider, seq, received, l.buf,
		l.tail[len(l.tail)-half:], l.n, [32]byte(l.sum.Sum(nil)))
	return r, ok && err == nil
}

// providerSeq reads the serial after ':' in the ID that opens b ({"ID":"<sec>.<msec>:<serial>",...).
func providerSeq(b []byte) (uint64, bool) {
	rest, ok := bytes.CutPrefix(b, []byte(idPrefix))
	if !ok {
		return 0, false
	}
	id, _, ok := bytes.Cut(rest, []byte(`"`))
	if !ok {
		return 0, false
	}
	_, serial, ok := bytes.Cut(id, []byte(":"))
	if !ok {
		return 0, false
	}
	seq, err := strconv.ParseUint(string(serial), 10, 63)
	return seq, err == nil
}

// idMatches reports whether b is valid JSON whose ID, as the decoder reads it, is the one that opens b:
// a second or case-variant ID key that the decoder would take instead makes the line malformed.
func idMatches(b []byte) bool {
	var v struct{ ID string }
	if err := json.Unmarshal(b, &v); err != nil {
		return false
	}
	rest, _ := bytes.CutPrefix(b, []byte(idPrefix))
	id, _, _ := bytes.Cut(rest, []byte(`"`))
	return v.ID == string(id)
}
