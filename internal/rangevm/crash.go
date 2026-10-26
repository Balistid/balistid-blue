package rangevm

import (
	"fmt"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// Facts of a collector failure (ADR 0023): the store's records of a recovery after the failure, how
// many there are, and of the first one the last seq the failed run left durable and the seq the
// record itself got, the first of the collector's next run (0 and 0 without one).
const (
	FactRecovered     = "recovered"
	FactRecoveredLast = "recovered_last"
	FactRecoveredSeq  = "recovered_seq"
)

// judgeCrash judges a run of collector failure trial tr (crash_loss_ms, ADR 0018 point 3, ADR 0023). H
// in the fail mark is the end of the contiguous numbers execed 900 ms before the failure and S the
// highest seq the collector journaled as committed before it; the guest fails the run itself when the
// load did not hold the trial's rate or S was stale. The host's marks, the closed facts of each boot,
// the target kernel, one recovery record whose seq follows its last, and after a reset ext4 with a
// journal that still needed recovery are required, else INVALID. A number up to H not stored, or a
// next run that starts at or below S (Open reused a seq it had acknowledged), is a MISS.
func judgeCrash(tr rangejob.Trial, o Outcome) (string, string) {
	last := []string{FactTrial, FactPhase, FactKernel, FactStoredPrefix, FactStoredCount, FactRecovered, FactRecoveredLast, FactRecoveredSeq}
	if tr.Failure == FailReset {
		first, err := closedFacts(o.FirstBoot, []string{FactTrial, FactPhase, FactKernel, FactResetArmed})
		if err != nil {
			return Invalid, "first boot: " + err.Error()
		}
		if first[FactKernel] != TargetKernel {
			return Invalid, "first boot ran another kernel"
		}
		last = append(last, FactScratchJournal, FactScratchRecovery)
	}
	f, err := closedFacts(o.Facts, last)
	if err != nil {
		return Invalid, err.Error()
	}
	n := map[string]uint64{}
	for _, name := range []string{FactStoredPrefix, FactStoredCount, FactRecovered, FactRecoveredLast, FactRecoveredSeq} {
		if n[name], err = plainNumber(f[name]); err != nil {
			return Invalid, fmt.Sprintf("fact %s is not a plain number", name)
		}
	}
	h, s := o.Marks.H, o.Marks.Synced
	switch {
	case f[FactKernel] != TargetKernel:
		return Invalid, fmt.Sprintf("guest kernel \"%s\" is not the target %s", Printable(f[FactKernel], 128), TargetKernel)
	case n[FactStoredCount] < n[FactStoredPrefix]:
		return Invalid, "stored counts do not add up"
	case tr.Failure == FailReset && (f[FactScratchJournal] != "yes" || f[FactScratchRecovery] != "yes"):
		return Invalid, "the reset did not leave ext4 with a journal that needs recovery"
	case h == 0:
		return Invalid, "nothing was execed in time to have to survive"
	case s == 0:
		return Invalid, "the collector acknowledged no commit before the failure"
	case n[FactRecovered] != 1:
		return Invalid, fmt.Sprintf("%d recovery records, want the one of this failure", n[FactRecovered])
	case n[FactRecoveredSeq] != n[FactRecoveredLast]+1:
		return Invalid, fmt.Sprintf("the recovery record has seq %d after a durable run to %d", n[FactRecoveredSeq], n[FactRecoveredLast])
	case n[FactStoredPrefix] < h:
		return Miss, fmt.Sprintf("numbers up to H=%d had to survive the %s of the collector; stored through %d", h, tr.Failure, n[FactStoredPrefix])
	case n[FactRecoveredLast] < s:
		return Miss, fmt.Sprintf("the collector acknowledged seq %d as committed, yet its next run starts at %d after the %s",
			s, n[FactRecoveredSeq], tr.Failure)
	}
	return Pass, fmt.Sprintf("every number up to H=%d and every seq up to S=%d survived the %s (stored through %d, durable to %d)",
		h, s, tr.Failure, n[FactStoredPrefix], n[FactRecoveredLast])
}
