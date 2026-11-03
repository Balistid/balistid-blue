package main

import (
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// A host line is one line of printable ASCII after the marker, at most hostLineMax bytes: a record's bytes or a
// journal's escape codes can neither end it nor put a line of their own in the host's log.
func TestHostLineIsOnePrintableLine(t *testing.T) {
	var out strings.Builder
	hostLine(&out, "a%sb", "\n::error::x\x1b[2Jé")
	hostLine(&out, "%s", strings.Repeat("y", 2*hostLineMax))
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 || lines[0] != hostPrefix+"a?::error::x?[2J??b" || lines[1] != hostPrefix+strings.Repeat("y", hostLineMax) {
		t.Errorf("host lines %q", lines)
	}
}

// A counted loss record shows what was lost and when, the store's and the collector's alike; a body that does not
// decode shows that.
func TestLossLineShowsWhatWasLost(t *testing.T) {
	for _, c := range []struct {
		x    rawrecord.Record
		want string
	}{
		{rawrecord.New(7, store.LossProvider, 0, 1, []byte(`{"schema_version":1,"dropped":12,"first_received":5,"last_received":9}`)),
			`loss record seq 7 balistid-loss kind="" stage="" count=0 dropped=12 at=0..0 received=5..9 decoded=true`},
		{rawrecord.New(8, store.HealthProvider, 0, 1, []byte(`{"schema_version":1,"kind":"lost","stage":"queue","count":3,"first_at":4,"last_at":6}`)),
			`loss record seq 8 balistid-health kind="lost" stage="queue" count=3 dropped=0 at=4..6 received=0..0 decoded=true`},
		{rawrecord.New(9, store.HealthProvider, 0, 1, []byte(`{"kind":"lost","stage":"é\n"`)),
			`loss record seq 9 balistid-health kind="" stage="" count=0 dropped=0 at=0..0 received=0..0 decoded=false`},
	} {
		if got := lossLine(c.x); got != c.want {
			t.Errorf("loss line %q\nwant       %q", got, c.want)
		}
	}
}
