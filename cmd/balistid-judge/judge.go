package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/shard"
	"github.com/Balistid/balistid-blue/internal/store"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

const (
	stateFile = "state.json"
	execFile  = "exec.jsonl"
	// readLimit is acceptance read_limit_min: the judge stops reading after it and says what it left.
	readLimit = 90 * time.Minute
	execDays  = 7
	// maxRuns is the most lines exec.jsonl holds, for the judge that writes it and the view that reads it.
	maxRuns = 1 << 22
	// maxSealed is the last Unix second whose nanoseconds fit an int64; the seal index takes any int64.
	maxSealed = math.MaxInt64 / int64(time.Second)
	// checkEvery is how many records are read between looks at the clock.
	checkEvery = 1024
	// resultMode is world-readable: every local user reads what the recorder saw (ADR 0082 consequences).
	resultMode = 0o644
)

// budgetRate is half the rate the judge read at under the unit's CPU policy (ADR 0082 point 2): on 2026-11-28
// TestBigStore under `chrt -i 0 nice -n 19`, at a load of about 4 on 16 cores, read 1336 MiB at 37.5 MiB/s (about
// 36 s).
const budgetRate = 18 << 20

// budgetBytes is what the judge reads at most: the read limit at budgetRate, about 95 GiB.
const budgetBytes = int64(readLimit/time.Second) * budgetRate

var errReadLimit = errors.New("the read limit passed")

// config is one run of the judge: the store it reads, where its two files go and the clock of its read limit.
type config struct {
	Store   string
	Out     string
	Scratch shard.Scratch
	Now     func() time.Time
	Limit   time.Duration
}

// judge reads the sealed store into state.json and exec.jsonl in cfg.Out and returns the status it wrote. The
// store is only read: ReadSeals and shard.Read open nothing for writing.
func judge(ctx context.Context, cfg config) (string, error) {
	start := cfg.Now()
	out, err := os.OpenRoot(cfg.Out)
	if err != nil {
		return statusUnknown, fmt.Errorf("judge: %w", err)
	}
	defer out.Close() //nolint:errcheck // every write is synced by its own file
	if err := removeLeftovers(out); err != nil {
		return statusUnknown, err
	}
	limitMin := int(cfg.Limit / time.Minute)
	seals, unsealed, torn, err := sealsOf(ctx, cfg.Store)
	var sizes []int64
	if err == nil {
		sizes, err = shardSizes(cfg.Store, seals)
	}
	if err != nil {
		st := newState(nil, 0, 0, limitMin)
		st.doc.Status, st.doc.Reason = statusUnknown, err.Error()
		return statusUnknown, errors.Join(err, writeBoth(out, st.render(newReader(math.MinInt64), start.UnixNano())))
	}
	rd := newReader(listFrom(seals))
	st := newState(seals, sum(sizes), startOf(seals, sizes), limitMin)
	st.doc.Unsealed, st.doc.TornIndex = unsealed, torn
	// State first, from the seals alone, and no exec line of an earlier run left beside it.
	st.last = st.render(rd, cfg.Now().UnixNano())
	if err := writeBoth(out, st.last); err != nil {
		return statusUnknown, err
	}
	if len(seals) == 0 { // nothing read is not a read of everything (R6)
		return st.fail(out, cfg, statusUnknown, "the store holds no sealed shard", errors.New("no sealed shard"))
	}
	deadline := start.Add(cfg.Limit)
	for st.next < len(seals) {
		l := seals[st.next]
		doc, err := readShard(ctx, cfg, out, rd, l, deadline)
		switch {
		case errors.Is(err, errReadLimit):
			return st.fail(out, cfg, statusPartial, "the read limit of "+strconv.Itoa(limitMin)+" min passed", err)
		case err != nil && ctx.Err() != nil:
			return st.fail(out, cfg, statusPartial, "stopped: "+ctx.Err().Error(), err)
		case err != nil:
			return st.fail(out, cfg, statusUnknown, l.Name+": "+err.Error(), err)
		}
		// exec.jsonl holds the shard's runs before state.json names the shard read: a crash in between leaves
		// runs whose shard state.json lists as not read, and the next run starts both files anew.
		st.read = append(st.read, doc)
		st.next++
		st.last = st.render(rd, cfg.Now().UnixNano())
		if err := writeState(out, st.last); err != nil {
			return statusUnknown, err
		}
	}
	// One sample ends the read: the limit bounds the read, not the write of the last file. COMPLETE says the read
	// ended before the limit, and written is this sample.
	end := cfg.Now()
	switch {
	case !end.Before(deadline): // the limit is a hard stop, even when the last shard was read whole
		return st.fail(out, cfg, statusPartial, "the read limit of "+strconv.Itoa(limitMin)+
			" min passed while the last shard was read; no sealed shard is unread", errReadLimit)
	case torn:
		return st.fail(out, cfg, statusPartial, "the seal index ends in a torn line", errors.New("a torn seal index"))
	}
	d := st.last
	d.Status, d.Written = statusComplete, timeText(end.UnixNano())
	if err := writeState(out, d); err != nil {
		return statusUnknown, err // state.json on disk still says READING
	}
	return statusComplete, nil
}

// fail writes state.json as it was after the last shard read whole, with the status and why the read stopped.
func (st *state) fail(out *os.Root, cfg config, status, reason string, err error) (string, error) {
	st.doc.Status, st.doc.Reason, st.stop = status, reason, err.Error()
	d := st.last
	d.Status, d.Reason, d.Written, d.NotRead = status, reason, timeText(cfg.Now().UnixNano()), st.notRead()
	return status, errors.Join(err, writeState(out, d))
}

// sealsOf is the seal index; ReadSeals refuses one whose seqs do not run on. A shard the index does not list is
// accepted only above the last seal, as the collector's open one (ADR 0074 point 2); it is named, not read.
func sealsOf(ctx context.Context, dir string) ([]store.Seal, []string, bool, error) {
	seals, err := store.ReadSeals(ctx, dir)
	var u *store.UnindexedError
	if err != nil && !errors.As(err, &u) {
		return nil, nil, false, fmt.Errorf("read the seals: %w", err)
	}
	for _, l := range seals {
		if l.Sealed > maxSealed {
			return nil, nil, false, fmt.Errorf("the time of seal %s, %d s, is past what the judge can count", l.Name, l.Sealed)
		}
	}
	if u == nil {
		return seals, []string{}, false, nil
	}
	if len(u.Beside) > 0 {
		return nil, nil, false, fmt.Errorf("sidecars beside sealed shards: %v", u.Beside)
	}
	var last uint64
	if len(seals) > 0 {
		last = seals[len(seals)-1].Last
	}
	for _, name := range u.Pending {
		first, err := strconv.ParseUint(strings.TrimSuffix(name, ".db"), 10, 64)
		if err != nil || first <= last {
			return nil, nil, false, fmt.Errorf("unindexed shard %s is not above the last seal (%d)", name, last)
		}
	}
	for _, name := range u.Sidecars {
		if !slices.Contains(u.Pending, name[:strings.LastIndexByte(name, '-')]) {
			return nil, nil, false, fmt.Errorf("sidecar %s of no unindexed shard", name)
		}
	}
	return seals, append(append([]string{}, u.Pending...), u.Sidecars...), u.Torn, nil
}

func shardSizes(dir string, seals []store.Seal) ([]int64, error) {
	sizes := make([]int64, len(seals))
	for i, l := range seals {
		fi, err := os.Lstat(filepath.Join(dir, l.Name))
		if err != nil {
			return nil, fmt.Errorf("size of %s: %w", l.Name, err)
		}
		sizes[i] = fi.Size()
	}
	return sizes, nil
}

func sum(sizes []int64) int64 {
	var n int64
	for _, s := range sizes {
		n += s
	}
	return n
}

// listFrom is the first UTC day whose runs exec.jsonl lists: the newest seal's day less execDays (ADR 0082 point 4),
// known before the read, so exec.jsonl is only appended to. The newest is the latest time of any seal: the store's
// clock can step back.
func listFrom(seals []store.Seal) int64 {
	if len(seals) == 0 {
		return math.MinInt64
	}
	newest := seals[0].Sealed
	for _, l := range seals {
		newest = max(newest, l.Sealed)
	}
	return newest/86400 - execDays
}

// startOf is the first shard of the first UTC day, by the seals' times, whose shards to the newest fit budgetBytes;
// when the newest day alone does not, its first shard, as the read limit still stops the read.
func startOf(seals []store.Seal, sizes []int64) int {
	dayAt := func(i int) int64 { return seals[i].Sealed / 86400 }
	start := len(seals)
	var n int64
	for i := len(seals) - 1; i >= 0; i-- {
		if n += sizes[i]; n > budgetBytes && start < len(seals) {
			break
		}
		if i == 0 || dayAt(i-1) != dayAt(i) {
			start = i
		}
	}
	return start
}

// readShard reads one sealed shard into rd, its exec lines into a file of their own, and only once the shard was
// read whole appends them to exec.jsonl. On a read error nothing is appended and rd is not read again.
func readShard(ctx context.Context, cfg config, out *os.Root, rd *reader, l store.Seal, deadline time.Time) (shardDoc, error) {
	doc := shardDoc{Name: l.Name}
	if !cfg.Now().Before(deadline) {
		return doc, errReadLimit
	}
	part, err := newPart(out)
	if err != nil {
		return doc, err
	}
	rd.out = part.w
	listed := rd.listed
	err = shard.Read(ctx, filepath.Join(cfg.Store, l.Name), l.SHA256, cfg.Scratch, func(r rawrecord.Record) error {
		if doc.Records%checkEvery == checkEvery-1 && !cfg.Now().Before(deadline) {
			return errReadLimit
		}
		if doc.Records == 0 {
			doc.First = r.Seq
		}
		doc.Last = r.Seq
		doc.Records++
		return rd.add(r)
	})
	if err != nil {
		return doc, errors.Join(fmt.Errorf("read %s: %w", l.Name, err), part.abort())
	}
	if rd.listed == listed {
		return doc, part.abort()
	}
	return doc, part.commit()
}

// part is one shard's exec lines, held until the shard was read whole.
type part struct {
	root *os.Root
	name string
	f    *os.File
	w    *bufio.Writer
}

func newPart(root *os.Root) (*part, error) {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("write %s: %w", execFile, err)
	}
	name := ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("write %s: %w", execFile, err)
	}
	return &part{root: root, name: name, f: f, w: bufio.NewWriterSize(f, 1<<20)}, nil
}

// commit appends the shard's lines to exec.jsonl and syncs it. A crash in the append leaves a torn last line,
// which view refuses.
func (p *part) commit() error {
	err := p.w.Flush()
	if err == nil {
		_, err = p.f.Seek(0, io.SeekStart)
	}
	if err == nil {
		err = p.appendTo()
	}
	if err != nil {
		return errors.Join(fmt.Errorf("append to %s: %w", execFile, err), p.abort())
	}
	return p.abort()
}

func (p *part) appendTo() error {
	cur, err := p.root.OpenFile(execFile, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err //nolint:wrapcheck // commit names the file
	}
	fi, err := cur.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return errors.Join(err, cur.Close())
	}
	_, err = io.Copy(cur, p.f)
	return errors.Join(err, cur.Sync(), cur.Close())
}

func (p *part) abort() error {
	return errors.Join(p.f.Close(), p.root.Remove(p.name))
}

// removeLeftovers removes the temp files a crashed run left in the results directory (R5): the regular files named
// .tmp-*, each through out and checked by Lstat, so a link or a directory of that name stays and is not followed.
func removeLeftovers(out *os.Root) error {
	d, err := out.Open(".")
	if err != nil {
		return fmt.Errorf("judge: the results directory: %w", err)
	}
	entries, err := d.ReadDir(-1)
	if err = errors.Join(err, d.Close()); err != nil {
		return fmt.Errorf("judge: the results directory: %w", err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".tmp-") || !e.Type().IsRegular() {
			continue
		}
		if fi, err := out.Lstat(e.Name()); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if err := out.Remove(e.Name()); err != nil {
			return fmt.Errorf("judge: remove a leftover: %w", err)
		}
	}
	return nil
}

// writeBoth starts a run: state.json from the seals, then an empty exec.jsonl. In that order an earlier run's
// COMPLETE state.json never stands beside the emptied file, and view reads a READING or UNKNOWN one as partial.
func writeBoth(out *os.Root, d stateDoc) error {
	if err := writeState(out, d); err != nil {
		return err
	}
	if err := wholefile.WriteIn(out, execFile, nil, resultMode); err != nil {
		return fmt.Errorf("judge: %w", err)
	}
	return nil
}

func writeState(out *os.Root, d stateDoc) error {
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return fmt.Errorf("judge: encode %s: %w", stateFile, err)
	}
	if err := wholefile.WriteIn(out, stateFile, append(b, '\n'), resultMode); err != nil {
		return fmt.Errorf("judge: %w", err)
	}
	return nil
}
