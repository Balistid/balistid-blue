package rangevm

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

const rssUnits = "balistid-auditstat.service,balistid-collector.service,balistid-ledger.service,balistid-pi.service," +
	"balistid-relay.service"

// rssRun is a sound report of RSS trial name, its load held, changed by name=value; a name without "=" is left
// out, an unknown one added.
func rssRun(t *testing.T, name string, change ...string) Outcome {
	t.Helper()
	tr := trial(t, name)
	base := map[string]string{
		FactGenerated: strconv.Itoa(tr.Load.Rate * tr.Load.Seconds), FactWindowMin: strconv.Itoa(tr.Load.Rate * 10),
		FactLostBefore: "3", FactLostAfter: "3", FactUnits: "same", FactRSSUnits: rssUnits,
		FactRSSSamples: strconv.Itoa(tr.Load.Seconds + 5), FactRSSProcsMin: "1", FactRSSMaxKiB: "200000", FactRSSAuditKiB: "40000",
	}
	return probeRun(name, rssFacts, base, change...)
}

// Every path to PASS with a false or missing fact: the units, the load, the kernel's loss, a restart, the
// samples and the processes are INVALID; only a whole run within 256 MiB passes, and the auditd trend never decides.
func TestJudgeRSS(t *testing.T) {
	for _, name := range []string{"rss-1000", "rss-burst", "rss-large"} {
		tr := trial(t, name)
		planned := tr.Load.Rate * tr.Load.Seconds
		run := func(change ...string) Outcome { return rssRun(t, name, change...) }
		judgeCases(t, name, run, map[string][]string{
			Miss: {"rss_max_kib=262145", "rss_max_kib=18446744073709551615"},
			Invalid: {
				// The report: a fact missing, added or repeated, another trial or kernel.
				"rss_max_kib", "rss_auditd_max_kib", "rss_units", "units", "audit_lost_after", "canary=seen",
				"trial=rate-burst", "kernel=6.0.0",
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
				"rss_max_kib=262144", "rss_max_kib=1", "rss_samples=" + strconv.Itoa(tr.Load.Seconds), "rss_procs_min=3",
				"rss_auditd_max_kib=999999999", "rss_auditd_max_kib=cgroup \"\" is not a unit's", "rss_auditd_max_kib=",
				"audit_lost_before=0,audit_lost_after=0",
			},
		})
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

// An RSS run keeps its largest sums, the trend's too, and its samples, but not a trend that is no number.
func TestMeasuresOfAnRSSTrial(t *testing.T) {
	tr := trial(t, "rss-burst")
	m := Measures(tr, rssRun(t, "rss-burst"))
	if len(m) != 5 || m[FactRSSMaxKiB] != 200000 || m[FactRSSAuditKiB] != 40000 || m[FactRSSSamples] != 15 || m[FactGenerated] != 100000 {
		t.Errorf("measures %v", m)
	}
	if m := Measures(tr, rssRun(t, "rss-burst", FactRSSAuditKiB+"=no laurel")); len(m) != 4 {
		t.Errorf("measures of a trend without a number %v", m)
	}
}
