package anchor

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/link"
)

const next = "balistid.test/log-2027"

func TestAnnounceFollowsTheWaitingBatch(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	records(t, l, 1, 3)
	size, err := l.Announce(t.Context(), entry.AnnounceShutdown)
	if err != nil || size != 2 {
		t.Fatalf("announce: size %d, %v", size, err)
	}
	if size, err = l.Announce(t.Context(), entry.AnnounceSuspend); err != nil || size != 3 {
		t.Fatalf("second announce: size %d, %v", size, err)
	}
	records(t, l, 4, 4) // the stream goes on after an announcement
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	want := []entry.Body{
		entry.Batch{First: 1, Last: 3, Root: rootOver(t, 1, 3)},
		entry.Announce{Kind: entry.AnnounceShutdown}, entry.Announce{Kind: entry.AnnounceSuspend},
		entry.Batch{First: 4, Last: 4, Root: rootOver(t, 4, 4)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("log %v", got)
	}
}

// At the cap the log is full, not broken: an announcement is refused, the final entry takes the slot
// kept for it even while records wait, and those records are left for the next log.
func TestFinalFitsAtCap(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	cfg := config(dir, k, c)
	cfg.CapBytes = 3 * entryBytes
	l := openLog(t, cfg)
	records(t, l, 1, 2)
	if _, err := l.Announce(t.Context(), entry.AnnounceShutdown); err != nil { // the batch, then this: 2 of 3
		t.Fatal(err)
	}
	if _, err := l.Announce(t.Context(), entry.AnnounceShutdown); !errors.Is(err, ErrFull) || l.Broken() != nil {
		t.Fatalf("an announcement at the cap: %v, broken %v", err, l.Broken())
	}
	if err := l.Record(t.Context(), link.Record{Seq: 3, Leaf: leaf(3)}); !errors.Is(err, ErrFull) {
		t.Fatalf("a record at the cap: %v", err)
	}
	closeLog(t, l) // full is no error to close with
	l = openLog(t, cfg)
	if !l.Full() || l.Broken() != nil {
		t.Fatalf("after a restart: full %v, broken %v", l.Full(), l.Broken())
	}
	l.batch, l.batchFirst = entry.NewRoot(), 3 // a record the stream gave before the cap refused it
	if err := l.batch.Add(leaf(3)); err != nil {
		t.Fatal(err)
	}
	if size, err := l.Final(t.Context(), next); err != nil || size != 3 || !l.Ended() || l.Full() {
		t.Fatalf("final at the cap with a record waiting: size %d, %v", size, err)
	}
	closeLog(t, l)
	got, _ := logged(t, dir, k)
	if len(got) != 3 || got[2] != (entry.Final{NextOrigin: next}) {
		t.Fatalf("log %v", got)
	}
}

func TestNothingAfterFinal(t *testing.T) {
	dir, k, c := t.TempDir(), newKeys(t), &clock{t: time.Unix(1e9, 0)}
	l := openLog(t, config(dir, k, c))
	records(t, l, 1, 2)
	for _, bad := range []string{origin, "", "has+plus"} {
		if _, err := l.Final(t.Context(), bad); err == nil {
			t.Fatalf("final naming %q", bad)
		}
	}
	if l.Broken() != nil || l.Ended() {
		t.Fatalf("a refused final changed the log: %v", l.Broken())
	}
	size, err := l.Final(t.Context(), next)
	if err != nil || size != 2 {
		t.Fatalf("final: size %d, %v", size, err)
	}
	refused := func(l *Log) {
		t.Helper()
		for name, err := range map[string]error{
			"record":   l.Record(t.Context(), link.Record{Seq: 3, Leaf: leaf(3)}),
			"seal":     l.Seal(t.Context(), entry.Seal{First: 1, Last: 2, SHA256: leaf(9)}),
			"health":   l.Health(t.Context(), entry.Health{State: entry.StateOK}),
			"announce": func() error { _, err := l.Announce(t.Context(), entry.AnnounceShutdown); return err }(),
			"other":    func() error { _, err := l.Final(t.Context(), next+"x"); return err }(),
		} {
			if !errors.Is(err, ErrFinal) {
				t.Errorf("%s after the final entry: %v", name, err)
			}
		}
		if again, err := l.Final(t.Context(), next); err != nil || again != size {
			t.Errorf("the same final again: size %d, %v", again, err)
		}
		if l.Broken() != nil || !l.Ended() {
			t.Errorf("after the final entry: broken %v, ended %v", l.Broken(), l.Ended())
		}
	}
	refused(l)
	closeLog(t, l)
	l = openLog(t, config(dir, k, c))
	defer l.Close(t.Context()) //nolint:errcheck // test end
	refused(l)
	got, _ := logged(t, dir, k)
	if len(got) != 2 || got[1] != (entry.Final{NextOrigin: next}) {
		t.Fatalf("log %v", got)
	}
}
