package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// Each case's argv has its stated size of distinct arguments that a JSON string holds unescaped.
func TestArgvCases(t *testing.T) {
	word := regexp.MustCompile(`^[a-z0-9-]+$`)
	want := map[string]int{rangevm.FactRecord131K: 131072, rangevm.FactRecord2M: 2_000_000, rangevm.FactRecord6M: 6_000_000}
	for _, c := range argvCases {
		seen, total := map[string]bool{}, 0
		for _, a := range c.args("balistid-record0f") {
			if !word.MatchString(a) || seen[a] || !strings.HasPrefix(a, "balistid-record0f-") {
				t.Fatalf("%s: argument %.40q", c.fact, a)
			}
			seen[a], total = true, total+len(a)
		}
		if total != want[c.fact] || uint64(total+c.n*8) > c.stack/4 { //nolint:gosec // a few MB
			t.Errorf("%s: %d bytes of argv under a %d stack", c.fact, total, c.stack)
		}
	}
}

// laurelExecOf is a stored Laurel line of the exec of args, seq its seq.
func laurelExecOf(t *testing.T, seq uint64, args []string) rawrecord.Record {
	t.Helper()
	line, err := json.Marshal(map[string]any{"ID": fmt.Sprintf("1.000:%d", seq),
		"EXECVE": map[string]any{"argc": len(args) + 1, "ARGV": append([]string{"/usr/bin/true"}, args...)}})
	if err != nil {
		t.Fatal(err)
	}
	return rawrecord.New(seq, store.SensorProvider, seq, 1, line)
}

func statsRecord(seq uint64, truncated, malformed int) rawrecord.Record {
	return rawrecord.New(seq, store.HealthProvider, 0, 1,
		fmt.Appendf(nil, `{"schema_version":1,"kind":"stats","truncated":%d,"malformed":%d,"lost":0,"lost_health":0}`, truncated, malformed))
}

// A sound store: both smaller execs whole, the large one truncated, the three lines stored and a
// stats record after them counting what the store holds before it.
func TestRecordScanOfASoundStore(t *testing.T) {
	const tok = "balistid-record0f"
	s := newRecordScan(tok)
	seq := uint64(10)
	next := func() uint64 { seq++; return seq }
	for _, c := range argvCases {
		_ = s.add(laurelExecOf(t, next(), c.args(tok)))
	}
	for _, l := range malformedLines(tok) {
		_ = s.add(rawrecord.New(next(), store.SensorProvider, 0, 1, []byte(l)))
	}
	_ = s.add(statsRecord(next(), 2, 3))
	_ = s.add(laurelExecOf(t, next(), []string{"barrier"}))
	r := &report{}
	s.report(r)
	want := "record_131k=whole record_2m=whole record_6m=truncated malformed_stored=3 stats_after=yes " +
		"stats_truncated=2 stored_truncated=2 stats_malformed=3 stored_malformed=3 lost_records=0"
	if g := factsString(r.facts); g != want {
		t.Errorf("facts\n%s\nwant\n%s", g, want)
	}
}

// What a record trial must not take for sound: an argument missing, a record twice, a large record
// stored whole, a stats record only before its lines.
func TestRecordScanFindsEachFault(t *testing.T) {
	const tok = "balistid-record0f"
	small, large := argvCases[0], argvCases[2]
	cut := small.args(tok)
	cut[7] = "other"
	cases := map[string]struct {
		records []rawrecord.Record
		want    string
	}{
		"cut":        {[]rawrecord.Record{laurelExecOf(t, 1, cut)}, "record_131k=cut"},
		"twice":      {[]rawrecord.Record{laurelExecOf(t, 1, small.args(tok)), laurelExecOf(t, 2, small.args(tok))}, "record_131k=twice"},
		"missing":    {nil, "record_131k=missing"},
		"stats late": {[]rawrecord.Record{statsRecord(1, 0, 0), laurelExecOf(t, 2, small.args(tok))}, "stats_after=no"},
		"large whole": {[]rawrecord.Record{{Seq: 1, Provider: store.SensorProvider, ProviderSeq: 1,
			Data: laurelExecOf(t, 1, large.args(tok)[:1]).Data, OrigLen: 100}}, "record_6m=truncated without its length or tail"},
		"large without its tail": {[]rawrecord.Record{func() rawrecord.Record {
			x := laurelExecOf(t, 1, large.args(tok))
			x.Data = x.Data[:len(x.Data)/2]
			return x
		}()}, "record_6m=truncated without its length or tail"},
		"loss": {[]rawrecord.Record{rawrecord.New(1, store.LossProvider, 0, 1, []byte(`{}`)),
			rawrecord.New(2, store.HealthProvider, 0, 1, []byte(`{"schema_version":1,"kind":"lost"}`))}, "lost_records=2"},
		"long line changed": {[]rawrecord.Record{func() rawrecord.Record {
			l := []byte(malformedLines(tok)[2])
			x := rawrecord.New(1, store.SensorProvider, 0, 1, l)
			x.OrigSHA256[0] ^= 1
			return x
		}()}, "malformed_stored=0"},
		"short line cut": {[]rawrecord.Record{rawrecord.New(1, store.SensorProvider, 0, 1, []byte(malformedLines(tok)[0][:35]))},
			"malformed_stored=0"},
	}
	for name, c := range cases {
		s := newRecordScan(tok)
		for _, x := range c.records {
			_ = s.add(x)
		}
		r := &report{}
		s.report(r)
		if g := factsString(r.facts); !strings.Contains(g, c.want) {
			t.Errorf("%s: %s, want %s", name, g, c.want)
		}
	}
}
