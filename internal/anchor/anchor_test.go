package anchor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
)

const origin = "balistid.test/log"

// clock is a fake clock a test advances while a connection's goroutine reads it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type keys struct {
	signer   note.Signer
	verifier note.Verifier
}

func newKeys(t *testing.T) keys {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return keys{s, v}
}

func config(dir string, k keys, c *clock) Config {
	return Config{Dir: dir, Signer: k.signer, CapBytes: 1 << 30, CheckpointInterval: 100 * time.Millisecond, Now: c.now}
}

func openLog(t *testing.T, cfg Config) *Log {
	t.Helper()
	l, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func closeLog(t *testing.T, l *Log) {
	t.Helper()
	if err := l.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// die stops l as a killed process would: the waiting batch is never logged.
func die(t *testing.T, l *Log) {
	t.Helper()
	l.batch = nil
	closeLog(t, l)
}

func leaf(seq uint64) [32]byte { return sha256.Sum256([]byte(strconv.FormatUint(seq, 10))) }

func records(t *testing.T, l *Log, first, last uint64) {
	t.Helper()
	for s := first; s <= last; s++ {
		if err := l.Record(t.Context(), link.Record{Seq: s, Leaf: leaf(s)}); err != nil {
			t.Fatal(err)
		}
	}
}

func rootOver(t *testing.T, first, last uint64) [32]byte {
	t.Helper()
	r := entry.NewRoot()
	for s := first; s <= last; s++ {
		if err := r.Add(leaf(s)); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := r.Sum()
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

// logged reads every entry of the log in dir and its signed checkpoint.
func logged(t *testing.T, dir string, k keys) ([]entry.Body, log.Checkpoint) {
	t.Helper()
	f := client.FileFetcher{Root: dir}
	cp, _, _, err := client.FetchCheckpoint(t.Context(), f.ReadCheckpoint, k.verifier, origin)
	if err != nil {
		t.Fatal(err)
	}
	var out []entry.Body
	for idx := uint64(0); idx*layout.EntryBundleWidth < cp.Size; idx++ {
		b, err := client.GetEntryBundle(t.Context(), f.ReadEntryBundle, idx, cp.Size)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range b.Entries {
			e, err := entry.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, e.Body)
		}
	}
	return out, *cp
}

func TestBatchesCoverTheStreamInCuts(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	if l.Resume() != (Resume{}) {
		t.Fatalf("empty log resumes at %+v", l.Resume())
	}
	records(t, l, 1, 5)
	c.advance(CutEvery - time.Millisecond)
	if err := l.Tick(t.Context()); err != nil || l.Resume().Last != 0 {
		t.Fatalf("cut before CutEvery: %+v, %v", l.Resume(), err)
	}
	c.advance(time.Millisecond)
	if err := l.Tick(t.Context()); err != nil || l.Resume() != (Resume{Last: 5, First: 1, Root: rootOver(t, 1, 5)}) {
		t.Fatalf("after CutEvery: %+v, %v", l.Resume(), err)
	}
	records(t, l, 6, 7)
	closeLog(t, l)
	got, cp := logged(t, dir, k)
	want := []entry.Body{entry.Batch{First: 1, Last: 5, Root: rootOver(t, 1, 5)}, entry.Batch{First: 6, Last: 7, Root: rootOver(t, 6, 7)}}
	if fmt.Sprint(got) != fmt.Sprint(want) || cp.Size != 2 {
		t.Fatalf("log %v of size %d, want %v", got, cp.Size, want)
	}
}

func TestStreamResumesFromTheLog(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	records(t, l, 1, 3)
	closeLog(t, l)
	l = openLog(t, config(dir, k, c))
	if l.Resume() != (Resume{Last: 3, First: 1, Root: rootOver(t, 1, 3)}) {
		t.Fatalf("resume %+v", l.Resume())
	}
	for _, seq := range []uint64{3, 5, 0, entry.MaxSeq + 1} {
		if err := l.Record(t.Context(), link.Record{Seq: seq, Leaf: leaf(seq)}); !errors.Is(err, ErrStream) {
			t.Fatalf("record %d after 3: %v", seq, err)
		}
	}
	if l.Broken() != nil {
		t.Fatalf("a stream error broke the log: %v", l.Broken())
	}
	records(t, l, 4, 4)
	closeLog(t, l)
}

// A loss entry precedes the batch covering its record; resent after a kill, it is not logged again.
func TestLossesPrecedeTheirBatchOnce(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	loss := entry.Loss{Seq: 1, Stage: entry.StageQueue, Records: 3}
	carried := link.Record{Seq: 1, Leaf: leaf(1), Loss: &loss}
	if err := l.Record(t.Context(), carried); err != nil {
		t.Fatal(err)
	}
	die(t, l) // between the loss and its batch
	l = openLog(t, config(dir, k, c))
	if err := l.Record(t.Context(), carried); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(t.Context(), link.Record{Seq: 2, Leaf: leaf(2), Loss: &entry.Loss{Seq: 1, Stage: entry.StageCap, Records: 1}}); !errors.Is(err, ErrStream) {
		t.Fatalf("loss carried by another record: %v", err)
	}
	closeLog(t, l)
	l = openLog(t, config(dir, k, c)) // the batch is logged now: the tail no longer holds the loss
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	if want := []entry.Body{loss, entry.Batch{First: 1, Last: 1, Root: rootOver(t, 1, 1)}}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("log %v, want %v", got, want)
	}
}

func TestSealFollowsTheBatchEndingAtIt(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	seal := entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("shard"))}
	l := openLog(t, config(dir, k, c))
	records(t, l, 1, 3)
	if err := l.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	die(t, l) // between the batch and its seal
	l = openLog(t, config(dir, k, c))
	for range 2 { // the second is a resend
		if err := l.Seal(t.Context(), seal); err != nil {
			t.Fatal(err)
		}
	}
	records(t, l, 4, 4)
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	want := []entry.Body{entry.Batch{First: 1, Last: 3, Root: rootOver(t, 1, 3)}, seal, entry.Batch{First: 4, Last: 4, Root: rootOver(t, 4, 4)}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("log %v, want %v", got, want)
	}
	l = openLog(t, config(dir, k, c))
	defer closeLog(t, l)
	if err := l.Seal(t.Context(), entry.Seal{First: 4, Last: 4, SHA256: seal.SHA256}); err != nil {
		t.Fatal(err)
	}
}

func TestSealConflictsBreakTheLog(t *testing.T) {
	seal := entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("shard"))}
	for name, s := range map[string]entry.Seal{
		"another hash":     {First: 1, Last: 3, SHA256: sha256.Sum256([]byte("other"))},
		"another range":    {First: 2, Last: 3, SHA256: seal.SHA256},
		"out of position":  {First: 1, Last: 2, SHA256: seal.SHA256},
		"past the records": {First: 1, Last: 4, SHA256: seal.SHA256},
	} {
		t.Run(name, func(t *testing.T) {
			dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
			l := openLog(t, config(dir, k, c))
			defer func() { _ = l.Close(t.Context()) }() // a broken log's Close reports why it broke
			records(t, l, 1, 3)
			if s.Last == 3 {
				if err := l.Seal(t.Context(), seal); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.Seal(t.Context(), s); err == nil || l.Broken() == nil {
				t.Fatalf("seal %+v: %v", s, err)
			}
			if err := l.Record(t.Context(), link.Record{Seq: 4, Leaf: leaf(4)}); err == nil {
				t.Fatal("a broken log took a record")
			}
		})
	}
}

func TestHealthIsLoggedOnChange(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	down := entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStoreDown, Unstored: 2}
	up := entry.Health{State: entry.StateOK}
	for _, h := range []entry.Health{down, down, up, up, down} {
		if err := l.Health(t.Context(), h); err != nil {
			t.Fatal(err)
		}
	}
	closeLog(t, l)
	if got, _ := logged(t, dir, k); fmt.Sprint(got) != fmt.Sprint([]entry.Body{down, up, down}) {
		t.Fatalf("log %v", got)
	}
}

func TestASecondLedgerIsRefused(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	if second, err := Open(t.Context(), config(dir, k, c)); err == nil {
		_ = second.Close(t.Context())
		t.Fatal("a second ledger opened the same log")
	}
	closeLog(t, l)
	closeLog(t, openLog(t, config(dir, k, c))) // the lock goes with the process that held it
}

func TestTheCapStopsAppending(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	cfg := config(dir, k, c)
	cfg.CapBytes = 3 * entryBytes
	l := openLog(t, cfg)
	defer func() { _ = l.Close(t.Context()) }()
	if err := l.Health(t.Context(), entry.Health{State: entry.StateOK}); err != nil {
		t.Fatal(err)
	}
	// The second slot takes the cap's UNKNOWN instead of the entry, the third is the final entry's: the log is
	// full, not broken (ADR 0036, point 5).
	if err := l.Health(t.Context(), entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStarting}); !errors.Is(err, ErrFull) ||
		l.Broken() != nil || !l.Full() {
		t.Fatalf("second entry under a cap of three: %v, broken %v", err, l.Broken())
	}
	if err := l.Health(t.Context(), entry.Health{State: entry.StateOK}); !errors.Is(err, ErrFull) {
		t.Fatalf("an entry after the cap's UNKNOWN: %v", err)
	}
	closeLog(t, l)
	l = openLog(t, cfg) // a restart at the cap logs nothing more
	if err := l.Health(t.Context(), entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStoreDown}); !errors.Is(err, ErrFull) {
		t.Fatalf("an entry after a restart at the cap: %v", err)
	}
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	if len(got) != 2 || got[1] != entry.Body(capHealth) {
		t.Fatalf("log %v; want an OK, then the cap's UNKNOWN once", got)
	}
}

// Only the ledger logs the cap's UNKNOWN: a collector claiming it is out of stream, and nothing is logged.
func TestCollectorCannotClaimTheCap(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	if err := l.Health(t.Context(), capHealth); !errors.Is(err, ErrStream) || l.Broken() != nil {
		t.Fatalf("the collector's cap health: %v, broken %v", err, l.Broken())
	}
	closeLog(t, l)
	if got, _ := logged(t, dir, k); len(got) != 0 {
		t.Fatalf("logged %v", got)
	}
}

func TestIncompleteConfigIsRefused(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	for _, change := range []func(*Config){
		func(cfg *Config) { cfg.Signer = nil },
		func(cfg *Config) { cfg.CapBytes = 3*entryBytes - 1 }, // no slot besides the cap's UNKNOWN and the final entry
		func(cfg *Config) { cfg.CheckpointInterval = 0 },
		func(cfg *Config) { cfg.Now = nil },
		func(cfg *Config) { cfg.Dir = "" },
		func(cfg *Config) { cfg.Dir = "relative/log" },
	} {
		cfg := config(dir, k, c)
		change(&cfg)
		if l, err := Open(t.Context(), cfg); err == nil {
			_ = l.Close(t.Context())
			t.Fatalf("opened with %+v", cfg)
		}
	}
}

// consistent checks what a witness checks before it cosigns: the newer checkpoint extends the older.
func consistent(t *testing.T, dir string, older, newer log.Checkpoint) error {
	t.Helper()
	f := client.FileFetcher{Root: dir}
	pb, err := client.NewProofBuilder(t.Context(), newer.Size, f.ReadTile)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pb.ConsistencyProof(t.Context(), older.Size, newer.Size)
	if err != nil {
		t.Fatal(err)
	}
	return proof.VerifyConsistency(rfc6962.DefaultHasher, older.Size, newer.Size, p, older.Hash, newer.Hash)
}

func TestCheckpointsExtendEachOtherAcrossRestarts(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	records(t, l, 1, 3)
	closeLog(t, l)
	_, first := logged(t, dir, k)
	l = openLog(t, config(dir, k, c))
	records(t, l, 4, 9)
	closeLog(t, l)
	_, second := logged(t, dir, k)
	if second.Size <= first.Size || second.Origin != origin {
		t.Fatalf("checkpoints %+v then %+v", first, second)
	}
	if err := consistent(t, dir, first, second); err != nil {
		t.Fatalf("restart broke consistency: %v", err)
	}
	forked := first
	forked.Hash = append([]byte(nil), first.Hash...)
	forked.Hash[0] ^= 1
	if consistent(t, dir, forked, second) == nil {
		t.Fatal("a fork of the older checkpoint passed")
	}
}

// A killed ledger leaves a log whose batches run gap-free from 1, with every loss and seal once in its
// place, and whose newer checkpoint extends the older: kill -9 lands anywhere, after an Add, during
// integration, between a loss and its batch, between a batch and its seal, or before a checkpoint.
func TestAKilledLedgerLeavesAPrefix(t *testing.T) {
	if dir := os.Getenv("BALISTID_ANCHOR_CHILD"); dir != "" {
		appendForever(t, dir)
		return
	}
	if testing.Short() {
		t.Skip("kills a child ledger several times")
	}
	dir, k := t.TempDir(), newKeysFile(t)
	var previous log.Checkpoint
	for round := range 5 {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestAKilledLedgerLeavesAPrefix$") //nolint:gosec // the test binary itself
		cmd.Env = append(os.Environ(), "BALISTID_ANCHOR_CHILD="+dir, "BALISTID_ANCHOR_KEY="+k.skey)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Duration(300+round*170) * time.Millisecond)
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()
		c := &clock{t: time.Now()}
		l := openLog(t, config(dir, k.keys, c)) // reopening reads the tail back
		resume := l.Resume()
		published(t, dir, k.keys, l.size) // integrated before the kill, published after the restart
		closeLog(t, l)
		got, cp := logged(t, dir, k.keys)
		next := checkStream(t, round, got)
		if resume.Last != next-1 {
			t.Fatalf("round %d: resumes after %d, log's batches end at %d", round, resume.Last, next-1)
		}
		if previous.Size > 0 && consistent(t, dir, previous, cp) != nil {
			t.Fatalf("round %d: checkpoint %d does not extend %d", round, cp.Size, previous.Size)
		}
		previous = cp
	}
	if previous.Size < 5 {
		t.Fatalf("the children logged %d entries", previous.Size)
	}
}

// published waits until the log's checkpoint covers size entries, at most a few checkpoint intervals.
func published(t *testing.T, dir string, k keys, size uint64) {
	t.Helper()
	f := client.FileFetcher{Root: dir}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		cp, _, _, err := client.FetchCheckpoint(t.Context(), f.ReadCheckpoint, k.verifier, origin)
		if err == nil && cp.Size >= size {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint %+v, %v; want size %d", cp, err, size)
		}
	}
}

// checkStream checks the log the killed children left: batches gap-free from 1, every fifth record's loss
// once and before its batch, every ninth record's seal once and right after the batch ending at it (the
// last batch's seal may wait for the next child). It returns the seq after the last batch.
func checkStream(t *testing.T, round int, got []entry.Body) uint64 {
	t.Helper()
	next, losses, seals, sealDue := uint64(1), map[uint64]int{}, map[uint64]int{}, uint64(0)
	for _, b := range got {
		switch b := b.(type) {
		case entry.Batch:
			if b.First != next || b.Root != rootOver(t, b.First, b.Last) || sealDue != 0 {
				t.Fatalf("round %d: batch %d-%d after %d, seal due at %d", round, b.First, b.Last, next-1, sealDue)
			}
			for s := b.First; s <= b.Last; s++ {
				if s%5 == 0 && losses[s] != 1 {
					t.Fatalf("round %d: record %d's loss logged %d times before its batch", round, s, losses[s])
				}
			}
			if next = b.Last + 1; b.Last%9 == 0 {
				sealDue = b.Last
			}
		case entry.Loss:
			if b.Seq < next || b.Seq%5 != 0 || b != childLoss(b.Seq) {
				t.Fatalf("round %d: loss %+v after the batches through %d", round, b, next-1)
			}
			losses[b.Seq]++
		case entry.Seal:
			if b != childSeal(next-1) || seals[b.Last] > 0 {
				t.Fatalf("round %d: seal %d-%d after the batch through %d", round, b.First, b.Last, next-1)
			}
			seals[b.Last]++
			sealDue = 0
		}
	}
	return next
}

func childLoss(seq uint64) entry.Loss {
	return entry.Loss{Seq: seq, Stage: entry.StageQueue, Records: seq}
}

func childSeal(last uint64) entry.Seal {
	return entry.Seal{First: last - 8, Last: last, SHA256: sha256.Sum256([]byte("shard " + strconv.FormatUint(last, 10)))}
}

type keyFile struct {
	keys
	skey string
}

func newKeysFile(t *testing.T) keyFile {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return keyFile{keys{s, v}, skey}
}

// appendForever is the child: it resumes the stream and cuts a batch every few records until killed.
func appendForever(t *testing.T, dir string) {
	s, err := note.NewSigner(os.Getenv("BALISTID_ANCHOR_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := Open(context.Background(), Config{Dir: dir, Signer: s, CapBytes: 1 << 30,
		CheckpointInterval: 100 * time.Millisecond, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	// As the collector does: the seal ending where the log resumes goes first, the ledger drops a resend.
	if last := l.Resume().Last; last > 0 && last%9 == 0 {
		if err := l.Seal(t.Context(), childSeal(last)); err != nil {
			t.Fatal(err)
		}
	}
	for seq := l.Resume().Last + 1; ; seq++ {
		r := link.Record{Seq: seq, Leaf: leaf(seq)}
		if seq%5 == 0 {
			loss := childLoss(seq)
			r.Loss = &loss
		}
		if err := l.Record(t.Context(), r); err != nil {
			t.Fatal(err)
		}
		if seq%3 == 0 {
			if err := l.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if seq%9 == 0 {
			if err := l.Seal(t.Context(), childSeal(seq)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A loss resent after a kill with another count than the one logged breaks the log.
func TestALossResentWithAnotherCountBreaksTheLog(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	if err := l.Record(t.Context(), link.Record{Seq: 1, Leaf: leaf(1), Loss: &entry.Loss{Seq: 1, Stage: entry.StageQueue, Records: 3}}); err != nil {
		t.Fatal(err)
	}
	die(t, l)
	l = openLog(t, config(dir, k, c))
	defer func() { _ = l.Close(t.Context()) }()
	if err := l.Record(t.Context(), link.Record{Seq: 1, Leaf: leaf(1), Loss: &entry.Loss{Seq: 1, Stage: entry.StageQueue, Records: 4}}); err == nil || l.Broken() == nil {
		t.Fatalf("a resent loss with another count: %v", err)
	}
}

func TestASealCountsOnceACosignedCheckpointReachesIt(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	first := entry.Seal{First: 1, Last: 3, SHA256: sha256.Sum256([]byte("one"))}
	for _, r := range recs(1, 3) {
		if err := l.Record(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Seal(t.Context(), first); err != nil { // the batch, then the seal: 2 entries
		t.Fatal(err)
	}
	note := []byte("note")
	if _, ok, err := l.Cosigned(cosign.Checkpoint{Size: 1, Note: note}); ok || err != nil {
		t.Fatalf("a checkpoint before the seal: %v, %v", ok, err)
	}
	if m, ok, err := l.Cosigned(cosign.Checkpoint{Size: 2, Note: note}); !ok || err != nil || m.Seal != first || string(m.Note) != "note" {
		t.Fatalf("a checkpoint over the seal: %+v, %v, %v", m, ok, err)
	}
	second := entry.Seal{First: 4, Last: 4, SHA256: sha256.Sum256([]byte("two"))}
	if err := errors.Join(l.Record(t.Context(), recs(4, 4)[0]), l.Seal(t.Context(), second)); err != nil {
		t.Fatal(err)
	}
	if m, ok, _ := l.Cosigned(cosign.Checkpoint{Size: 3}); !ok || m.Seal != first { // the batch of 4 only
		t.Fatalf("the older covered seal stays until the newer one is reached: %+v", m)
	}
	if m, ok, _ := l.Cosigned(cosign.Checkpoint{Size: 4}); !ok || m.Seal != second {
		t.Fatalf("the newer seal: %+v", m)
	}
	if m, ok, err := l.Cosigned(cosign.Checkpoint{Size: 2, Note: []byte("old")}); ok || err != nil { // replayed
		t.Fatalf("a checkpoint older than the covered seal went with it: %+v, %v", m, err)
	}
	if _, ok, err := l.Cosigned(cosign.Checkpoint{Size: 5}); ok || err == nil {
		t.Fatal("a cosigned size past the log was taken")
	}
	if err := l.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	// After a restart no seal counts until one is logged or resent: where earlier ones are is unknown.
	l = openLog(t, config(dir, k, c))
	defer l.Close(t.Context()) //nolint:errcheck // test end
	if _, ok, err := l.Cosigned(cosign.Checkpoint{Size: 4}); ok || err != nil {
		t.Fatalf("after a restart: %v, %v", ok, err)
	}
	if err := l.Seal(t.Context(), second); err != nil { // the collector resends the seal at its resume point
		t.Fatal(err)
	}
	if m, ok, _ := l.Cosigned(cosign.Checkpoint{Size: 4}); !ok || m.Seal != second {
		t.Fatalf("a resent seal: %+v", m)
	}
}
