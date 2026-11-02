package status

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Balistid/balistid-blue/internal/entry"
)

var unknownStore = entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStoreDown, Unstored: 3}

func TestReportRoundTrips(t *testing.T) {
	for _, h := range []entry.Health{{State: entry.StateOK}, unknownStore} {
		r := Report{Boot: 12345, Health: h, At: 1790899200e9}
		b, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != ReportBytes {
			t.Fatalf("%d bytes, want %d", len(b), ReportBytes)
		}
		if back, err := DecodeReport(b); err != nil || back != r {
			t.Fatalf("%+v back as %+v, %v", r, back, err)
		}
	}
}

// A health the collector never computes cannot be published, and a report that holds one is refused.
func TestReportRefusesAHealthOutsideTheEntryRules(t *testing.T) {
	for name, h := range map[string]entry.Health{
		"OK with a reason":     {State: entry.StateOK, Reason: entry.ReasonStoreDown},
		"UNKNOWN without one":  {State: entry.StateUnknown},
		"no state":             {},
		"reason past the last": {State: entry.StateUnknown, Reason: entry.ReasonAuditd + 1},
	} {
		if _, err := (Report{Health: h}).Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	good, err := Report{Boot: 1, Health: unknownStore}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	reason := len(good) - 9 // the reason byte before unstored
	for name, mutate := range map[string]func([]byte) []byte{
		"OK with a reason": func(b []byte) []byte { b[reason-1] = byte(entry.StateOK); return b },
		"another label":    func(b []byte) []byte { b[0] ^= 1; return b },
		"another entry":    func(b []byte) []byte { b[len(Label)+1+8] ^= 1; return b },
		"short":            func(b []byte) []byte { return b[:len(b)-1] },
		"long":             func(b []byte) []byte { return append(b, 0) },
	} {
		if _, err := DecodeReport(mutate(bytes.Clone(good))); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestReadReportReadsTheOwnersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	b, err := Report{Boot: 7, Health: entry.Health{State: entry.StateOK}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err := ReadReport(path, os.Getuid()); err != nil || r.Boot != 7 {
		t.Fatalf("%+v, %v", r, err)
	}
	if _, err := ReadReport(path, os.Getuid()+1); err == nil {
		t.Fatal("read another owner's report")
	}
}

// Whatever DecodeReport accepts, Encode gives back byte for byte.
func FuzzDecodeReport(f *testing.F) {
	for _, h := range []entry.Health{{State: entry.StateOK}, unknownStore} {
		b, err := Report{Boot: 4, Health: h}.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeReport(b)
		if err != nil {
			return
		}
		if back, err := r.Encode(); err != nil || !bytes.Equal(back, b) {
			t.Fatalf("DecodeReport(%x) = %+v, encodes to %x, %v", b, r, back, err)
		}
	})
}
