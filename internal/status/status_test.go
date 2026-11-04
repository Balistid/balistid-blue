package status

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
)

const nowBoot = uint64(100 * time.Second)

// healthy is every unit doing its job and a fresh OK report; each case changes one source.
func healthy() Sources {
	return Sources{
		Units: func(_ context.Context, names []string) ([]UnitState, error) {
			out := make([]UnitState, len(names))
			for i, u := range units {
				out[i] = UnitState{ID: u.Name, Load: "loaded", Active: "active", Sub: u.Subs[0]}
			}
			return out, nil
		},
		Report: func() (Report, error) {
			return Report{Boot: nowBoot - uint64(time.Second), Health: entry.Health{State: entry.StateOK}}, nil
		},
		Boottime: func() (uint64, error) { return nowBoot, nil },
	}
}

func withUnit(src Sources, name string, s UnitState) Sources {
	prev := src.Units
	src.Units = func(ctx context.Context, names []string) ([]UnitState, error) {
		out, err := prev(ctx, names)
		for i := range out {
			if out[i].ID == name {
				out[i] = s
			}
		}
		return out, err
	}
	return src
}

func withReport(src Sources, r Report, err error) Sources {
	src.Report = func() (Report, error) { return r, err }
	return src
}

func part(res Result, name string) Part {
	for _, p := range res.Parts {
		if p.Name == name {
			return p
		}
	}
	return Part{}
}

func TestHealthyFloorIsOK(t *testing.T) {
	res := Check(t.Context(), healthy())
	if !res.OK || len(res.Parts) != len(units)+1 {
		t.Fatalf("%+v", res)
	}
	for _, p := range res.Parts {
		if p.State != OK || p.Hint != "" {
			t.Errorf("%+v", p)
		}
	}
}

// Every unit stopped, failed, missing or in another substate makes its own part FAIL and the floor not OK.
func TestEachUnitNotDoingItsJobFails(t *testing.T) {
	for _, u := range units {
		for _, s := range []UnitState{
			{u.Name, "loaded", "inactive", "dead"}, {u.Name, "loaded", "failed", "failed"},
			{u.Name, "not-found", "inactive", "dead"}, {u.Name, "masked", "inactive", "dead"},
			{u.Name, "loaded", "activating", "start"}, {u.Name, "loaded", "deactivating", "stop-sigterm"},
			{u.Name, "loaded", "active", "other"},
		} {
			res := Check(t.Context(), withUnit(healthy(), u.Name, s))
			if p := part(res, u.Name); res.OK || p.State != Fail || p.Hint == "" {
				t.Errorf("%s %+v: ok %v, part %+v", u.Name, s, res.OK, p)
			}
		}
	}
}

// A socket whose service holds its fd is running, and that is its job.
func TestSocketRunningIsOK(t *testing.T) {
	name := "balistid-collector.socket"
	if res := Check(t.Context(), withUnit(healthy(), name, UnitState{name, "loaded", "active", "running"})); !res.OK {
		t.Fatalf("%+v", part(res, name))
	}
}

// A systemd that does not answer leaves every unit UNKNOWN.
func TestNoAnswerFromSystemdIsUnknown(t *testing.T) {
	src := healthy()
	src.Units = func(context.Context, []string) ([]UnitState, error) { return nil, errors.New("bus") }
	res := Check(t.Context(), src)
	for _, u := range units {
		if p := part(res, u.Name); res.OK || p.State != Unknown {
			t.Errorf("%s: %+v", u.Name, p)
		}
	}
}

// Health is OK only from a fresh OK report: a missing, unreadable, stale or future report, a missing clock or
// any UNKNOWN reason is UNKNOWN.
func TestHealthIsOKOnlyFromAFreshOKReport(t *testing.T) {
	ok := entry.Health{State: entry.StateOK}
	fresh := nowBoot - uint64(MaxAge)
	cases := map[string]Sources{
		"no report":        withReport(healthy(), Report{}, fs.ErrNotExist),
		"refused report":   withReport(healthy(), Report{}, errors.New("not its writer's file")),
		"stale report":     withReport(healthy(), Report{Boot: fresh - 1, Health: ok}, nil),
		"future report":    withReport(healthy(), Report{Boot: nowBoot + 1, Health: ok}, nil),
		"unknown reason":   withReport(healthy(), Report{Boot: nowBoot, Health: entry.Health{State: entry.StateUnknown, Reason: 200}}, nil),
		"no clock":         healthy(),
		"zero boot of now": withReport(healthy(), Report{Boot: 0, Health: ok}, nil),
	}
	cases["no clock"] = func() Sources {
		s := healthy()
		s.Boottime = func() (uint64, error) { return 0, errors.New("clock") }
		return s
	}()
	for r := range reasons {
		cases["reason "+reasons[r].name] = withReport(healthy(), Report{Boot: nowBoot, Health: entry.Health{State: entry.StateUnknown, Reason: r}}, nil)
	}
	for name, src := range cases {
		res := Check(t.Context(), src)
		if p := part(res, HealthPart); res.OK || p.State != Unknown || p.Hint == "" {
			t.Errorf("%s: ok %v, %+v", name, res.OK, p)
		}
	}
	if res := Check(t.Context(), withReport(healthy(), Report{Boot: fresh, Health: ok}, nil)); !res.OK {
		t.Fatalf("a report MaxAge old: %+v", part(res, HealthPart))
	}
}

// Every reason the collector can send has a name and a hint.
func TestEveryReasonIsExplained(t *testing.T) {
	for r := entry.ReasonStarting; r <= entry.ReasonRulesDiffer; r++ {
		if why, ok := reasons[r]; !ok || why.name == "" || why.hint == "" {
			t.Errorf("reason %d: %+v", r, why)
		}
	}
}

func TestTextShowsTheVerdictAndEachHint(t *testing.T) {
	res := Check(t.Context(), withUnit(healthy(), "balistid-ledger.service", UnitState{"balistid-ledger.service", "loaded", "inactive", "dead"}))
	var b bytes.Buffer
	if err := WriteText(&b, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"balistid status: NOT OK\n", "FAIL     balistid-ledger.service", "-> systemctl status balistid-ledger.service", Scope} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

func TestJSONIsOneObjectOfTheSchema(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, Check(t.Context(), healthy())); err != nil {
		t.Fatal(err)
	}
	var back Result
	d := json.NewDecoder(&b)
	d.DisallowUnknownFields()
	if err := d.Decode(&back); err != nil || !back.OK || back.SchemaVersion != SchemaVersion || len(back.Parts) != len(units)+1 || d.More() {
		t.Fatalf("%+v, %v", back, err)
	}
}
