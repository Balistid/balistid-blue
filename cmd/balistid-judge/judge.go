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
	// readLimit is acceptance read_limit_min: the judge stops reading shards after it and says what it left.
	readLimit = 90 * time.Minute
	execDays  = 7
	// checkEvery is how many records are read between looks at the clock.
	checkEvery = 1024
	// resultMode is world-readable: every local user reads what the recorder saw (ADR 0082 consequences).
	resultMode = 0o644
)

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
	limitMin := int(cfg.Limit / time.Minute)
	seals, unsealed, torn, err := sealsOf(ctx, cfg.Store)
	if err != nil {
		st := newState(nil, 0, 0, limitMin)
		st.doc.Status, st.doc.Reason = statusUnknown, err.Error()
		return statusUnknown, errors.Join(err, writeBoth(out, st, start.UnixNano()))
	}
	sizes, err := shardBytes(cfg.Store, seals)
	if err != nil {
		st := newState(seals, 0, 0, limitMin)
		st.doc.Status, st.doc.Reason = statusUnknown, err.Error()
		return statusUnknown, errors.Join(err, writeBoth(out, st, start.UnixNano()))
	}
	var cutoff int64
	if n := len(seals); n > 0 {
		cutoff = (seals[n-1].Sealed - execDays*86400) * 1e9
	}
	st := newState(seals, sizes, cutoff, limitMin)
	st.doc.Unsealed, st.doc.TornIndex = unsealed, torn
	// State first, from the seals alone, and no exec line of an earlier run left beside it.
	if err := writeBoth(out, st, cfg.Now().UnixNano()); err != nil {
		return statusUnknown, err
	}
	deadline := start.Add(cfg.Limit)
	for i := len(seals) - 1; i >= 0; i-- {
		l := seals[i]
		a, err := readShard(ctx, cfg, out, l, cutoff, deadline)
		switch {
		case errors.Is(err, errReadLimit):
			st.doc.Status, st.doc.Reason = statusPartial, "the read limit of "+strconv.Itoa(limitMin)+" min passed"
		case err != nil && ctx.Err() != nil:
			st.doc.Status, st.doc.Reason = statusPartial, "stopped: "+ctx.Err().Error()
		case err != nil:
			st.doc.Status, st.doc.Reason = statusUnknown, l.Name+": "+err.Error()
		}
		if err != nil {
			for j := range st.doc.NotRead {
				st.doc.NotRead[j].Reason = "not read: " + st.doc.Reason
			}
			st.doc.NotRead[0].Reason = err.Error()
			return st.doc.Status, errors.Join(err, writeState(out, st, cfg.Now().UnixNano()))
		}
		st.merge(l.Name, a)
		if err := writeState(out, st, cfg.Now().UnixNano()); err != nil {
			return statusUnknown, err
		}
	}
	st.doc.Status = statusComplete
	return statusComplete, writeState(out, st, cfg.Now().UnixNano())
}

// sealsOf is the seal index, contiguous in seq. A shard the index does not list is accepted only above the last
// seal, as the collector's open one (ADR 0074 point 2); it is named, not read.
func sealsOf(ctx context.Context, dir string) ([]store.Seal, []string, bool, error) {
	seals, err := store.ReadSeals(ctx, dir)
	var u *store.UnindexedError
	if err != nil && !errors.As(err, &u) {
		return nil, nil, false, fmt.Errorf("read the seals: %w", err)
	}
	for i := 1; i < len(seals); i++ {
		if seals[i].First != seals[i-1].Last+1 {
			return nil, nil, false, fmt.Errorf("seal %s starts at %d, not %d", seals[i].Name, seals[i].First, seals[i-1].Last+1)
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

func shardBytes(dir string, seals []store.Seal) (int64, error) {
	var n int64
	for _, l := range seals {
		fi, err := os.Lstat(filepath.Join(dir, l.Name))
		if err != nil {
			return 0, fmt.Errorf("size of %s: %w", l.Name, err)
		}
		n += fi.Size()
	}
	return n, nil
}

// readShard reads one sealed shard into its accumulator and its exec lines in front of exec.jsonl's. On any error
// exec.jsonl stays as it was.
func readShard(ctx context.Context, cfg config, out *os.Root, l store.Seal, cutoff int64, deadline time.Time) (*shardAcc, error) {
	if !cfg.Now().Before(deadline) {
		return nil, errReadLimit
	}
	part, err := newPart(out)
	if err != nil {
		return nil, err
	}
	a := newShardAcc(cutoff, part.w)
	err = shard.Read(ctx, filepath.Join(cfg.Store, l.Name), l.SHA256, cfg.Scratch, func(r rawrecord.Record) error {
		if a.n%checkEvery == checkEvery-1 && !cfg.Now().Before(deadline) {
			return errReadLimit
		}
		return a.add(r)
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("read %s: %w", l.Name, err), part.abort())
	}
	if a.execs.Exported == 0 { // older than the 7 days, mostly: no copy of the whole file for nothing
		return a, part.abort()
	}
	return a, part.commit()
}

// part is the next exec.jsonl being written: the lines of the shard being read, then the current file's.
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
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("write %s: %w", execFile, err)
	}
	return &part{root: root, name: name, f: f, w: bufio.NewWriterSize(f, 1<<20)}, nil
}

// commit appends the current exec.jsonl, then renames the whole over it, as wholefile does.
func (p *part) commit() error {
	err := p.w.Flush()
	if err == nil {
		err = p.appendCurrent()
	}
	if err == nil {
		err = errors.Join(p.f.Chmod(resultMode), p.f.Sync())
	}
	if err = errors.Join(err, p.f.Close()); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", execFile, err), p.root.Remove(p.name))
	}
	if err := p.root.Rename(p.name, execFile); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", execFile, err), p.root.Remove(p.name))
	}
	return syncDir(p.root)
}

func (p *part) appendCurrent() error {
	cur, err := p.root.OpenFile(execFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err //nolint:wrapcheck // commit names the file
	}
	defer cur.Close() //nolint:errcheck // read-only
	if fi, err := cur.Stat(); err != nil || !fi.Mode().IsRegular() {
		return errors.Join(err, errors.New("not a regular file"))
	}
	_, err = io.Copy(p.f, cur)
	return err //nolint:wrapcheck // commit names the file
}

func (p *part) abort() error {
	return errors.Join(p.f.Close(), p.root.Remove(p.name))
}

func syncDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("sync the results directory: %w", err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync the results directory: %w", err)
	}
	return nil
}

// writeBoth starts a run: state.json from the seals and an empty exec.jsonl.
func writeBoth(out *os.Root, st *state, now int64) error {
	if err := wholefile.WriteIn(out, execFile, nil, resultMode); err != nil {
		return fmt.Errorf("judge: %w", err)
	}
	return writeState(out, st, now)
}

func writeState(out *os.Root, st *state, now int64) error {
	b, err := json.MarshalIndent(st.render(now), "", " ")
	if err != nil {
		return fmt.Errorf("judge: encode %s: %w", stateFile, err)
	}
	if err := wholefile.WriteIn(out, stateFile, append(b, '\n'), resultMode); err != nil {
		return fmt.Errorf("judge: %w", err)
	}
	return nil
}
