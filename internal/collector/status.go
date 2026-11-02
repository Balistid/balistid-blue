package collector

import (
	"time"

	"github.com/Balistid/balistid-blue/internal/status"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// statusEvery is how often the report is rewritten while health holds: balistid status reads a report older
// than status.MaxAge as UNKNOWN, so a stopped or stuck writer shows within it.
const statusEvery = time.Second

// publish writes the health the tick computed for balistid status (ADR 0048), at once on a change and every
// statusEvery. A failed write is journaled once until one succeeds; the report it leaves ages into UNKNOWN.
func (w *Writer) publish(now time.Time) {
	if w.StatusPath == "" || w.health == w.statusHealth && now.Sub(w.statusAt) < statusEvery {
		return
	}
	err := w.writeStatus(now)
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
	// World-readable: every user's balistid status reads it (ADR 0048, Consequences).
	return wholefile.Write(w.StatusPath, b, 0o644) //nolint:wrapcheck // names the file
}
