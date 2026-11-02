package status

import (
	"strings"
	"testing"
)

func show(states ...UnitState) string {
	var b strings.Builder
	for i, s := range states {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("Id=" + s.ID + "\nLoadState=" + s.Load + "\nActiveState=" + s.Active + "\nSubState=" + s.Sub + "\n")
	}
	return b.String()
}

var twoNames = []string{"a.service", "b.socket"}

func TestParseShowReadsEachUnitInOrder(t *testing.T) {
	want := []UnitState{{"a.service", "loaded", "active", "running"}, {"b.socket", "not-found", "inactive", "dead"}}
	got, err := parseShow([]byte(show(want...)), twoNames)
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("%+v, %v", got, err)
	}
}

// Output status cannot read whole is refused whole, never read as some units.
func TestParseShowRefusesAnythingElse(t *testing.T) {
	a := UnitState{"a.service", "loaded", "active", "running"}
	b := UnitState{"b.socket", "loaded", "active", "listening"}
	good := show(a, b)
	for name, out := range map[string]string{
		"one unit":          show(a),
		"three units":       show(a, b, b),
		"another order":     show(b, a),
		"a missing key":     strings.Replace(good, "SubState=running\n", "", 1),
		"a key twice":       strings.Replace(good, "SubState=running\n", "SubState=running\nSubState=dead\n", 1),
		"an unknown key":    strings.Replace(good, "SubState=running\n", "SubState=running\nResult=success\n", 1),
		"a line without =":  strings.Replace(good, "SubState=running\n", "SubState=running\nrunning\n", 1),
		"another Id":        strings.Replace(good, "Id=a.service", "Id=c.service", 1),
		"an escape":         strings.Replace(good, "active\nSubState=running", "active\x1b[2J\nSubState=running", 1),
		"an empty state":    strings.Replace(good, "SubState=running", "SubState=", 1),
		"upper case":        strings.Replace(good, "SubState=running", "SubState=Running", 1),
		"blank lines run":   strings.Replace(good, "\n\n", "\n\n\n", 1),
		"nothing":           "",
		"a key with spaces": strings.Replace(good, "SubState=running", "SubState =running", 1),
	} {
		if got, err := parseShow([]byte(out), twoNames); err == nil {
			t.Errorf("%s: read %+v", name, got)
		}
	}
}

// Whatever parseShow accepts is one state per name, each of the plain form.
func FuzzParseShow(f *testing.F) {
	f.Add([]byte(show(UnitState{"a.service", "loaded", "active", "running"}, UnitState{"b.socket", "loaded", "active", "listening"})))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseShow(b, twoNames)
		if err != nil {
			return
		}
		for i, s := range got {
			if s.ID != twoNames[i] || !stateValue.MatchString(s.Load) || !stateValue.MatchString(s.Active) || !stateValue.MatchString(s.Sub) {
				t.Fatalf("parseShow(%q) = %+v", b, got)
			}
		}
		if show(got...) != string(b) && show(got...) != strings.TrimSuffix(string(b), "\n")+"\n" {
			t.Fatalf("parseShow(%q) = %+v, which prints as %q", b, got, show(got...))
		}
	})
}
