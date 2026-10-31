package rangevm

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// logCapRun is a sound run: a cap of 300 entries set at 100 s, the cap's UNKNOWN cosigned at 400 s and its alert
// at 403 s, one full bundle well under the bytes the cap counts.
func logCapRun(change map[string]string) Outcome {
	base := map[string]string{
		FactInject: "ok", FactCapEntries: "300", FactRestartMS: "100000", FactCapMS: "400000", FactCosignedEnd: "299",
		FactCapEntry: "yes", FactCapRefused: "yes", FactFullBundles: "1", FactFullBytes: "40960",
		FactPosts: "60000:start,403000:logcap", FactRefused: "0", FactPiActive: "active",
	}
	var changes []string
	for k, v := range change {
		if k == "-" {
			changes = append(changes, v)
		} else {
			changes = append(changes, k+"="+v)
		}
	}
	return probeRun("log-cap", logCapFacts, base, changes...)
}

func TestJudgeLogCap(t *testing.T) {
	tr := trial(t, "log-cap")
	over := strconv.Itoa(256*(256+2+33) + 1)
	for want, changes := range map[string][]map[string]string{
		Pass: {
			nil,
			{FactPosts: "60000:start,465000:logcap"}, // 65 s
			{FactPosts: "60000:start,396000:logcap"}, // seen before the guest's sample
			{FactPosts: "50000:logcap,60000:start,403000:logcap"}, // an old one does not count, the new one does
		},
		Miss: {
			{FactPosts: "60000:start,465001:logcap"},
			{FactPosts: "60000:start"},
			{FactPosts: "60000:start,90000:logcap"},   // only before the restart
			{FactPosts: "60000:start,403000:unknown"}, // another cause's UNKNOWN is not the cap's alert
			{FactCosignedEnd: "300"},                  // something took the final slot or more
			{FactCapEntry: "entry 298 is entry.Batch"},
			{FactCapRefused: "no"},
			{FactFullBytes: over},
			{FactPosts: "none", FactRefused: "2"},
		},
		Invalid: {
			{FactInject: "error: systemctl daemon-reload: exit status 1"},
			{FactCapMS: "none"},
			{FactCosignedEnd: "250"},
			{FactCapMS: "90000"},
			{FactFullBundles: "0"}, {FactFullBundles: "2"}, {FactFullBundles: "1000000"},
			// facts no ledger under its 10 GiB cap can make
			{FactCapEntries: "256000001", FactCosignedEnd: "256000000", FactFullBundles: "1000000"},
			{FactCosignedEnd: "301"},
			{FactPiActive: "inactive"},
			{FactPosts: "403000:logcap"},
			{FactCapEntries: "2", FactCosignedEnd: "1"},
			{FactKernel: "6.0.0"}, {"-": FactCapEntry}, {"extra": "1"},
		},
	} {
		for _, c := range changes {
			if v, r := JudgeTrial(tr, logCapRun(c), cleanBuild, cleanBuild); v != want {
				t.Errorf("log-cap with %v: %s (%s), want %s", c, v, r, want)
			}
		}
	}
	m := Measures(tr, logCapRun(nil))
	if m[FactFullBytes] != 40960 || m[FactFullBundles] != 1 || m[FactCapEntries] != 300 {
		t.Errorf("measures %v", m)
	}
}

// The judge's bound is the ledger's own cap constant.
func TestHostLogCapIsTheLedgers(t *testing.T) {
	data, err := os.ReadFile("../../cmd/balistid-ledger/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "capBytes        = 10 << 30\n") || hostLogCap != 10<<30 {
		t.Fatal("hostLogCap is not balistid-ledger's capBytes")
	}
}
