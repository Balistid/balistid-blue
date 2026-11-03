package rangevm

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/collector"
)

const rssUnits = "balistid-auditstat.service,balistid-collector.service,balistid-ledger.service,balistid-pi.service," +
	"balistid-range-witness-agent.service,balistid-range-witness.service,balistid-relay.service"

// rssRun is a sound report of RSS trial name, its load held, changed by name=value; a name without "=" is left
// out, an unknown one added.
func rssRun(t *testing.T, name string, change ...string) Outcome {
	t.Helper()
	tr := trial(t, name)
	base := map[string]string{
		FactGenerated: strconv.Itoa(tr.Load.Rate * tr.Load.Seconds), FactWindowMin: strconv.Itoa(tr.Load.Rate * 10),
		FactLostBefore: "3", FactLostAfter: "3", FactOverflowBefore: "no", FactOverflowAfter: "no", FactLostRecords: "0",
		FactUnits: "same", FactRSSRun: "ok", FactRSSUnits: rssUnits, FactRSSSamples: strconv.Itoa(tr.Load.Seconds + 5),
		FactRSSLoadGapMS: "1004", FactRSSProcsMin: "1", FactRSSMaxKiB: "150000", FactRSSHWMKiB: "160000", FactRSSOOM: "0",
		FactRSSQueueBytes: "8388608", FactRSSAuditKiB: "40000",
	}
	return probeRun(name, rssFacts, base, change...)
}

// Every path to PASS with a false or missing fact: the units, the load, the kernel's, the dispatcher's, the
// collector's or the store's loss, a restart, the samples, their gaps and the processes are INVALID; a peak over
// 256 MiB, counting the summed VmHWM and the shipped collector's larger queue, or an OOM event is a MISS that no
// INVALID hides; only a whole run within 256 MiB passes, and the auditd trend never decides.
func TestJudgeRSS(t *testing.T) {
	for _, name := range []string{"rss-1000", "rss-burst", "rss-large"} {
		tr := trial(t, name)
		planned := tr.Load.Rate * tr.Load.Seconds
		run := func(change ...string) Outcome { return rssRun(t, name, change...) }
		judgeCases(t, name, run, map[string][]string{
			Miss: {
				"rss_max_kib=262145", "rss_max_kib=18446744073709551615", "rss_hwm_kib=18446744073709551615",
				// The range's 8 MiB queue holds 57344 KiB less than the shipped 64 MiB one, rounded up.
				"rss_hwm_kib=204801", "rss_max_kib=204801", "rss_queue_bytes=67108863,rss_hwm_kib=262144",
				"rss_queue_bytes=0,rss_hwm_kib=196609", "rss_oom=1", "rss_oom=18446744073709551615",
				// A MISS outranks every INVALID: a restart, the load, a loss, a gap, a fact missing or not a number.
				"rss_max_kib=300000,units=balistid-collector.service: restarted", "rss_oom=1,units=balistid-ledger.service: restarted",
				"rss_max_kib=300000,audit_lost_after=900", "rss_max_kib=300000,generated=500000", "rss_oom=2,rss_units=",
				"rss_max_kib=300000,rss_run=rss: cgroup /system.slice/balistid-ledger.service: gone",
				"rss_max_kib=300000,overflow_after=yes", "rss_max_kib=300000,lost_records=3", "rss_hwm_kib=300000,rss_max_kib=x",
				"rss_max_kib=300000,rss_load_gap_ms=5000", "rss_max_kib=300000,rss_queue_bytes=x", "rss_oom=1,rss_samples",
				"rss_oom=1,rss_hwm_kib=x", "rss_max_kib=262145,rss_oom=x",
			},
			Invalid: {
				// The report: a fact missing, added or repeated, another trial or kernel.
				"rss_max_kib", "rss_auditd_max_kib", "rss_units", "units", "audit_lost_after", "canary=seen",
				"trial=rate-burst", "kernel=6.0.0", "rss_hwm_kib", "rss_oom", "rss_queue_bytes", "rss_load_gap_ms", "rss_run",
				"overflow_before", "overflow_after", "lost_records", "trial=rate-burst,rss_oom=1", "kernel=6.0.0,rss_max_kib=300000",
				// The shipped queue not known, peaks or OOM events not read.
				"rss_queue_bytes=x", "rss_queue_bytes=", "rss_queue_bytes=67108865", "rss_queue_bytes=08388608",
				"rss_hwm_kib=0", "rss_hwm_kib=x", "rss_oom=x", "rss_oom=-1", "rss_oom=",
				// A run not whole, a load not delivered past the kernel, the load not covered by samples.
				"rss_run=generator: exec failed", "rss_run=", "rss_run=ok ", "overflow_before=yes", "overflow_before=missing",
				"overflow_after=yes", "overflow_after=stale", "lost_records=1", "lost_records=x", "rss_load_gap_ms=2001",
				"rss_load_gap_ms=no sample before the load", "rss_load_gap_ms=x",
				// Numbers re-parsed strictly.
				"rss_max_kib=x", "rss_max_kib=-1", "rss_max_kib=18446744073709551616", "rss_max_kib=0200000",
				"rss_max_kib=200000 ", "rss_max_kib=", "rss_samples=+20", "rss_procs_min=1.0",
				// No resident memory, no samples, too few, a unit without a process.
				"rss_max_kib=0", "rss_samples=0", "rss_samples=" + strconv.Itoa(tr.Load.Seconds-1), "rss_procs_min=0",
				// Another set of units than RSSUnits.
				"rss_units=" + rssUnits + ",balistid-new.service", "rss_units=" + rssUnits[len("balistid-auditstat.service,"):],
				"rss_units=" + rssUnits + ",balistid-relay.service", "rss_units=" + rssUnits + ",balistid-range-guest.service",
				"rss_units=" + rssUnits + ",balistid-announce.service", "rss_units=", "rss_units=" + rssUnits + ",",
				// The load not run as asked, the kernel losing records or a unit restarting.
				"generated=" + strconv.Itoa(planned-1), "generated=" + strconv.Itoa(planned+1),
				"window_min=" + strconv.Itoa(tr.Load.Rate*10-1), "window_min=" + strconv.Itoa(planned+1),
				"audit_lost_after=4", "audit_lost_after=2", "audit_lost_before=x", "units=balistid-collector.service: restarted",
				"units=",
			},
			Pass: {
				"rss_max_kib=204800", "rss_hwm_kib=204800", "rss_max_kib=1", "rss_hwm_kib=1",
				"rss_queue_bytes=67108864,rss_max_kib=262144", "rss_queue_bytes=67108864,rss_hwm_kib=262144",
				"rss_queue_bytes=67107840,rss_hwm_kib=262143", "rss_samples=" + strconv.Itoa(tr.Load.Seconds), "rss_procs_min=3",
				"rss_auditd_max_kib=999999999", "rss_auditd_max_kib=cgroup \"\" is not a unit's", "rss_auditd_max_kib=",
				"audit_lost_before=0,audit_lost_after=0", "rss_load_gap_ms=2000", "rss_load_gap_ms=0",
			},
		})
	}
}

// The judge's shipped queue is the collector's.
func TestCollectorQueueBytesIsTheCollectors(t *testing.T) {
	if CollectorQueueBytes != collector.QueueBytes {
		t.Errorf("the judge adds the queue up to %d bytes, the collector holds %d", CollectorQueueBytes, collector.QueueBytes)
	}
}

// The judge's limit is acceptance rss_mib's 256 MiB, so the two cannot drift.
func TestRSSLimitIsTheAcceptance(t *testing.T) {
	data, err := os.ReadFile("../../acceptance/0.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^id = "rss_mib"\nmax = (\d+) `).FindSubmatch(data)
	if m == nil || string(m[1]) != strconv.Itoa(rssLimitKiB>>10) {
		t.Errorf("acceptance rss_mib %q, the judge's limit %d MiB", m, rssLimitKiB>>10)
	}
}

// An RSS run keeps its largest sums, its peaks, the trend's too, and its samples, but not a trend that is no number.
func TestMeasuresOfAnRSSTrial(t *testing.T) {
	tr := trial(t, "rss-burst")
	m := Measures(tr, rssRun(t, "rss-burst"))
	if len(m) != 6 || m[FactRSSMaxKiB] != 150000 || m[FactRSSHWMKiB] != 160000 || m[FactRSSAuditKiB] != 40000 ||
		m[FactRSSSamples] != 15 || m[FactGenerated] != 100000 {
		t.Errorf("measures %v", m)
	}
	if m := Measures(tr, rssRun(t, "rss-burst", FactRSSAuditKiB+"=no laurel")); len(m) != 5 {
		t.Errorf("measures of a trend without a number %v", m)
	}
}

// The OOM control gives its expected MISS only through rss_oom: a run without the event, even one over the limit,
// is INVALID and so fails the control.
func TestOOMControlMissesOnlyByItsOOM(t *testing.T) {
	tr := trial(t, "rss-oom-control")
	if ExpectedVerdict(tr) != Miss {
		t.Fatalf("expected verdict %s", ExpectedVerdict(tr))
	}
	run := func(change ...string) Outcome { return rssRun(t, "rss-oom-control", change...) }
	for change, want := range map[string]string{
		"rss_oom=2": Miss, "rss_oom=1,units=balistid-ledger.service: restarted": Miss,
		"rss_oom=1,rss_max_kib=300000": Miss,
		// Without an OOM event the injection proved nothing: a clean run, a restart or a peak over the limit alone.
		"": Invalid, "units=balistid-ledger.service: restarted": Invalid, "rss_max_kib=300000": Invalid,
		"rss_hwm_kib=300000,units=balistid-ledger.service: restarted": Invalid, "rss_oom=x": Invalid,
	} {
		if v, r := JudgeTrial(tr, run(strings.Split(change, ",")...), cleanBuild, cleanBuild); v != want {
			t.Errorf("%q: %s (%s), want %s", change, v, r, want)
		}
	}
}
