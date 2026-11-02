package collector

import (
	"errors"
	"io/fs"
	"os"
	"time"

	"github.com/Balistid/balistid-blue/internal/status"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// statusEvery is how often the report is rewritten while health holds: balistid status reads a report older
// than status.MaxAge as UNKNOWN, so a stopped or stuck writer shows within it.
const statusEvery = time.Second

// publish writes the health the tick computed for balistid status (ADR 0048), at once on a change and every
// statusEvery. A failed write removes the last report, which may say OK while health is not, so the CLI reads
// UNKNOWN at once; only when that removal fails too does the old report stand, until it ages past status.MaxAge.
// Either failure is journaled once until a write succeeds.
func (w *Writer) publish(now time.Time) {
	if w.StatusPath == "" || w.health == w.statusHealth && now.Sub(w.statusAt) < statusEvery {
		return
	}
	err := w.writeStatus(now)
	if err != nil {
		if rerr := os.Remove(w.StatusPath); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, rerr)
		}
		w.statusHealth = ""
	}
	journalRead(w.Log, &w.statusErr, "status report not written", err)
	if err == nil {
		w.statusHealth, w.statusAt = w.health, now
	}
}

func (w *Writer) writeStatus(now time.Time) error {
	h, err := healthEntry(w.health, w.unstored())
	if err != nil {
		return err
	}
	boot, err := w.Boottime()
	if err != nil {
		return err
	}
	b, err := status.Report{Boot: boot, Health: h, At: now.UnixNano()}.Encode()
	if err != nil {
		return err //nolint:wrapcheck // status errors carry their context
	}
	write := w.writeFile
	if write == nil {
		write = wholefile.Write
	}
	// World-readable: every user's balistid status reads it (ADR 0048, Consequences).
	return write(w.StatusPath, b, 0o644)
}
