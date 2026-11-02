package rangevm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// cliPart and cliResult build what the CLI prints, with the field names the judge decodes.
type cliPart struct {
	Name   string `json:"part"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

type cliResult struct {
	SchemaVersion int       `json:"schema_version"`
	OK            bool      `json:"ok"`
	Parts         []cliPart `json:"parts"`
}

// cliFor is the result a sound CLI prints for run: every part OK but the broken one.
func cliFor(run StatusRun) cliResult {
	res := cliResult{SchemaVersion: 1, OK: run.Kind == StatusHealthy}
	for _, p := range append(StatusUnits(), statusHealth) {
		state := "OK"
		if p == run.Part {
			state = "FAIL"
		}
		res.Parts = append(res.Parts, cliPart{Name: p, State: state, Detail: "x"})
	}
	return res
}

func runValue(res cliResult, exit int, health, proof string) string {
	b, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%d %s %s %s", exit, health, base64.StdEncoding.EncodeToString(append(b, '\n')), proof)
}

// soundHealth is the store's health a sound run reports: OK while healthy, UNKNOWN while frozen, unread when stopped.
func soundHealth(run StatusRun) string {
	switch run.Kind {
	case StatusHealthy:
		return StoreOK
	case StatusStopUnit:
		return StoreUnread
	}
	return StoreUnknown
}

const installedUnits = "balistid-announce-suspend.service,balistid-announce.service,balistid-auditstat.service," +
	"balistid-collector.service,balistid-collector.socket,balistid-ledger.service,balistid-net.service," +
	"balistid-pi-failed.service,balistid-pi.service,balistid-range-guest.service,balistid-range-store.service," +
	"balistid-relay.service"

// soundPolls are the waits of a sound trial: OK over an OK store before each run, not OK over UNKNOWN in a freeze.
func soundPolls() string {
	var polls []string
	for i := range StatusRuns() {
		polls = append(polls, fmt.Sprintf("%d:0:OK", i), fmt.Sprintf("%d:1:UNKNOWN", i), fmt.Sprintf("%d:1:mixed", i))
	}
	return strings.Join(polls, ",")
}

// statusOutcome is a sound status report; edit changes the value of one run before it is encoded.
func statusOutcome(t *testing.T, edit map[string]func(*cliResult, *int, *string)) Outcome {
	t.Helper()
	return statusOutcomeStore(t, edit, nil)
}

// statusOutcomeStore is statusOutcome with the store's health of some runs replaced.
func statusOutcomeStore(t *testing.T, edit map[string]func(*cliResult, *int, *string), health map[string]string) Outcome {
	t.Helper()
	tr := trial(t, "status-1")
	facts := []Record{{Name: FactTrial, Value: tr.Name}, {Name: FactPhase, Value: "1"}, {Name: FactKernel, Value: TargetKernel},
		{Name: FactStatusUID, Value: "985"}, {Name: FactUnitsInstalled, Value: installedUnits}, {Name: FactStatusPolls, Value: soundPolls()}}
	for _, run := range StatusRuns() {
		res, exit, proof := cliFor(run), 1, "yes"
		if run.Kind == StatusHealthy {
			exit = 0
		}
		if e := edit[run.Name]; e != nil {
			e(&res, &exit, &proof)
		}
		h, ok := health[run.Name]
		if !ok {
			h = soundHealth(run)
		}
		facts = append(facts, Record{Name: FactStatusRun + run.Name, Value: runValue(res, exit, h, proof)})
	}
	return Outcome{Facts: facts}
}

func setFact(o Outcome, name, value string) Outcome {
	for i := range o.Facts {
		if o.Facts[i].Name == name {
			o.Facts[i].Value = value
		}
	}
	return o
}

func TestStatusSoundRunPasses(t *testing.T) {
	if v, why := judgeStatus(trial(t, "status-1"), statusOutcome(t, nil)); v != Pass {
		t.Fatalf("%s: %s", v, why)
	}
}

// Every break is one run, and the runs break each floor-0 unit and Laurel between two healthy ones.
func TestStatusRunsBreakEveryPart(t *testing.T) {
	runs := StatusRuns()
	if runs[0].Kind != StatusHealthy || runs[len(runs)-1].Kind != StatusHealthy || len(runs) != len(statusUnits)+3 {
		t.Fatalf("%+v", runs)
	}
	broken := map[string]bool{}
	for _, r := range runs[1 : len(runs)-1] {
		broken[r.Name] = r.Part != ""
	}
	for _, u := range append(StatusUnits(), "laurel") {
		if !broken[u] {
			t.Errorf("%s is not broken with a part to show", u)
		}
	}
}

// Each way a false OK or a healthy run not OK could pass is a MISS.
func TestStatusFalseOKIsAMiss(t *testing.T) {
	broken := StatusRuns()[2].Name // a stopped unit
	for name, edit := range map[string]map[string]func(*cliResult, *int, *string){
		"broken run shows ok": {broken: func(r *cliResult, _ *int, _ *string) { r.OK = true }},
		"broken run exits 0":  {broken: func(_ *cliResult, e *int, _ *string) { *e = 0 }},
		"broken run exits 2":  {broken: func(_ *cliResult, e *int, _ *string) { *e = 2 }},
		"broken part OK, another not": {broken: func(r *cliResult, _ *int, _ *string) {
			for i := range r.Parts {
				r.Parts[i].State = map[bool]string{true: "OK", false: "FAIL"}[r.Parts[i].Name == broken]
			}
		}},
		"frozen Laurel, health OK": {"laurel": func(r *cliResult, _ *int, _ *string) {
			for i := range r.Parts {
				if r.Parts[i].Name == statusHealth {
					r.Parts[i].State = "OK"
				}
			}
		}},
		"frozen auditd, only the unit FAIL": {"auditd.service": func(r *cliResult, _ *int, _ *string) {
			for i := range r.Parts {
				r.Parts[i].State = map[bool]string{true: "FAIL", false: "OK"}[r.Parts[i].Name == "auditd.service"]
			}
		}},
		"always not OK":      {"healthy": func(r *cliResult, e *int, _ *string) { r.OK, *e = false, 1 }},
		"end run not OK":     {"end": func(r *cliResult, _ *int, _ *string) { r.Parts[0].State = "UNKNOWN" }},
		"healthy exit 1":     {"healthy": func(_ *cliResult, e *int, _ *string) { *e = 1 }},
		"healthy ok false":   {"end": func(r *cliResult, _ *int, _ *string) { r.OK = false }},
		"a unit not shown":   {broken: func(r *cliResult, _ *int, _ *string) { r.Parts = r.Parts[:len(r.Parts)-1] }},
		"health not shown":   {"laurel": func(r *cliResult, _ *int, _ *string) { r.Parts = r.Parts[:len(r.Parts)-1] }},
		"a part shown twice": {broken: func(r *cliResult, _ *int, _ *string) { r.Parts = append(r.Parts, r.Parts[0]) }},
		"an unknown part": {broken: func(r *cliResult, _ *int, _ *string) {
			r.Parts = append(r.Parts, cliPart{Name: "other", State: "FAIL"})
		}},
	} {
		if v, why := judgeStatus(trial(t, "status-1"), statusOutcome(t, edit)); v != Miss {
			t.Errorf("%s: %s (%s)", name, v, why)
		}
	}
}

// A run the guest could not prove, a CLI as root, an image unit the trial does not break or a report that is not
// the closed set is INVALID, never a PASS.
func TestStatusUnprovenRunIsInvalid(t *testing.T) {
	tr := trial(t, "status-1")
	unproven := func(run string) map[string]func(*cliResult, *int, *string) {
		return map[string]func(*cliResult, *int, *string){run: func(_ *cliResult, _ *int, p *string) { *p = "after: x is \"active\"" }}
	}
	cases := map[string]Outcome{
		"break not proven":   statusOutcome(t, unproven(StatusRuns()[2].Name)),
		"healthy not proven": statusOutcome(t, unproven("healthy")),
		"as root":            setFact(statusOutcome(t, nil), FactStatusUID, "0"),
		"uid not a number":   setFact(statusOutcome(t, nil), FactStatusUID, "0985"),
		"another kernel":     setFact(statusOutcome(t, nil), FactKernel, "6.1"),
		"another trial":      setFact(statusOutcome(t, nil), FactTrial, "status-2"),
		"an unbroken unit":   setFact(statusOutcome(t, nil), FactUnitsInstalled, installedUnits+",balistid-new.service"),
		"a unit missing":     setFact(statusOutcome(t, nil), FactUnitsInstalled, strings.Replace(installedUnits, "balistid-net.service,", "", 1)),
		"exit not plain":     setFact(statusOutcome(t, nil), FactStatusRun+"healthy", "+0 e30= yes"),
		"no proof field":     setFact(statusOutcome(t, nil), FactStatusRun+"healthy", "0 OK e30="),
		"base64 not canonical": setFact(statusOutcome(t, nil), FactStatusRun+"healthy",
			"0 OK "+strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(`{"schema_version":1,"ok":true,"parts":[]}`)), "=")+" yes"),
		"no polls":         setFact(statusOutcome(t, nil), FactStatusPolls, ""),
		"a poll of no run": setFact(statusOutcome(t, nil), FactStatusPolls, "11:0:OK"),
		"a poll malformed": setFact(statusOutcome(t, nil), FactStatusPolls, "0:0"),
		"a poll exit -1":   setFact(statusOutcome(t, nil), FactStatusPolls, "0:-1:OK"),
		"a poll unread":    setFact(statusOutcome(t, nil), FactStatusPolls, "0:0:-"),
		"over the cap": setFact(statusOutcome(t, nil), FactStatusRun+"healthy",
			"0 OK "+base64.StdEncoding.EncodeToString(make([]byte, MaxStatusOut+1))+" yes"),
	}
	dup := statusOutcome(t, nil)
	dup.Facts = append(dup.Facts, dup.Facts[len(dup.Facts)-1])
	cases["a run twice"] = dup
	short := statusOutcome(t, nil)
	short.Facts = short.Facts[:len(short.Facts)-1]
	cases["a run missing"] = short
	for name, o := range cases {
		if v, why := judgeStatus(tr, o); v != Invalid {
			t.Errorf("%s: %s (%s)", name, v, why)
		}
	}
}

// Output that is not exactly what the CLI's encoder writes, or a part in a state of no known kind, counts against the
// metric: a MISS, never an INVALID that a later run could replace.
func TestStatusOutputNotCanonicalIsAMiss(t *testing.T) {
	tr := trial(t, "status-1")
	healthy := cliFor(StatusRuns()[0])
	good, err := json.Marshal(healthy)
	if err != nil {
		t.Fatal(err)
	}
	raw := func(out string) string { return "0 OK " + base64.StdEncoding.EncodeToString([]byte(out)) + " yes" }
	g := string(good)
	cases := map[string]string{
		"unknown field":     raw(strings.Replace(g, `"ok":true`, `"ok":true,"mode":"x"`, 1) + "\n"),
		"another schema":    raw(strings.Replace(g, `"schema_version":1`, `"schema_version":2`, 1) + "\n"),
		"two objects":       raw(g + "{}\n"),
		"a trailing ]":      raw(g + "]\n"),
		"a trailing brace":  raw(g + "}\n"),
		"no newline":        raw(g),
		"ok twice":          raw(strings.Replace(g, `"ok":true`, `"ok":true,"ok":false`, 1) + "\n"),
		"no ok":             raw(strings.Replace(g, `"ok":true,`, ``, 1) + "\n"),
		"spaces":            raw(strings.Replace(g, `"ok":true`, `"ok": true`, 1) + "\n"),
		"terminal controls": raw(g + "\n\x1b[2Jbalistid status: OK\n"),
	}
	for name, v := range cases {
		if v, why := judgeStatus(tr, setFact(statusOutcome(t, nil), FactStatusRun+"healthy", v)); v != Miss {
			t.Errorf("%s: %s (%s)", name, v, why)
		}
	}
	for _, state := range []string{"", "HEALTHY", "ok", "Fail"} {
		edit := map[string]func(*cliResult, *int, *string){StatusRuns()[2].Name: func(r *cliResult, _ *int, _ *string) {
			for i := range r.Parts {
				if r.Parts[i].State == "FAIL" {
					r.Parts[i].State = state
				}
			}
		}}
		if v, why := judgeStatus(tr, statusOutcome(t, edit)); v != Miss {
			t.Errorf("state %q: %s (%s)", state, v, why)
		}
	}
}

// A CLI call in any wait that exited 0 while the store was UNKNOWN throughout is a false OK, though the measured run
// came later and showed the break.
func TestStatusFalseOKInAPollIsAMiss(t *testing.T) {
	o := setFact(statusOutcome(t, nil), FactStatusPolls, soundPolls()+",12:0:UNKNOWN")
	if v, why := judgeStatus(trial(t, "status-1"), o); v != Invalid {
		t.Fatalf("a poll of run 12: %s (%s)", v, why)
	}
	laurel := len(StatusRuns()) - 2
	o = setFact(statusOutcome(t, nil), FactStatusPolls, soundPolls()+fmt.Sprintf(",%d:0:UNKNOWN", laurel))
	if v, why := judgeStatus(trial(t, "status-1"), o); v != Miss || !strings.Contains(why, "laurel: false OK in a poll") {
		t.Fatalf("%s (%s)", v, why)
	}
}

// The store decides healthy and frozen runs: the CLI showing OK while the store was UNKNOWN throughout is a false OK,
// whatever the run; a run the store leaves open, or a store read for a stopped unit, proves nothing.
func TestStatusStoreDecidesHealthyAndFrozenRuns(t *testing.T) {
	tr := trial(t, "status-1")
	stopped := StatusRuns()[2].Name
	cliOK := func(r *cliResult, e *int, _ *string) {
		*e, r.OK = 0, true
		for i := range r.Parts {
			r.Parts[i].State = "OK"
		}
	}
	for name, c := range map[string]struct {
		edit   map[string]func(*cliResult, *int, *string)
		health map[string]string
		want   string
	}{
		"healthy OK over UNKNOWN":       {nil, map[string]string{"healthy": StoreUnknown}, Miss},
		"end OK over UNKNOWN":           {nil, map[string]string{"end": StoreUnknown}, Miss},
		"frozen Laurel OK over UNKNOWN": {map[string]func(*cliResult, *int, *string){"laurel": cliOK}, nil, Miss},
		"healthy not OK over UNKNOWN": {map[string]func(*cliResult, *int, *string){"healthy": func(r *cliResult, e *int, _ *string) {
			*e, r.OK = 1, false
		}}, map[string]string{"healthy": StoreUnknown}, Invalid},
		"healthy over a mixed store":       {nil, map[string]string{"healthy": StoreMixed}, Invalid},
		"healthy with no store record":     {nil, map[string]string{"end": StoreNone}, Invalid},
		"frozen auditd over an OK store":   {nil, map[string]string{"auditd.service": StoreOK}, Invalid},
		"frozen Laurel over a mixed store": {nil, map[string]string{"laurel": StoreMixed}, Invalid},
		"store read for a stopped unit":    {nil, map[string]string{stopped: StoreOK}, Invalid},
		"a store health of another form":   {nil, map[string]string{"healthy": "ok"}, Invalid},
	} {
		if v, why := judgeStatus(tr, statusOutcomeStore(t, c.edit, c.health)); v != c.want {
			t.Errorf("%s: %s (%s), want %s", name, v, why, c.want)
		}
	}
}

// Whatever value statusOf reads is a proven run within the cap.
func FuzzStatusOf(f *testing.F) {
	f.Add(runValue(cliFor(StatusRuns()[0]), 0, StoreOK, "yes"))
	f.Add("0 OK e30= yes")
	f.Fuzz(func(t *testing.T, v string) {
		_, _, out, err := statusOf(v)
		if err != nil {
			return
		}
		if !strings.HasSuffix(v, " yes") || len(out) > MaxStatusOut {
			t.Fatalf("statusOf(%q) = %d bytes", v, len(out))
		}
	})
}

// Whatever resultOf accepts is the canonical encoding of what it returns, newline included.
func FuzzResultOf(f *testing.F) {
	b, err := json.Marshal(cliFor(StatusRuns()[0]))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append(b, '\n'))
	f.Fuzz(func(t *testing.T, out []byte) {
		res, bad := resultOf(out)
		if bad != "" {
			return
		}
		back, err := json.Marshal(res)
		if err != nil || !bytes.Equal(append(back, '\n'), out) {
			t.Fatalf("resultOf(%q) = %+v", out, res)
		}
	})
}
