package main

import (
	"maps"
	"slices"
	"syscall"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// The child asks exactly the requests the host judges, so none is missing and none goes unjudged.
func TestAuditAsksAreTheJudgedOps(t *testing.T) {
	got := slices.Sorted(maps.Keys(auditAsks(&auditAsker{fd: -1})))
	if want := slices.Sorted(slices.Values(rangevm.AuditSetOps())); !slices.Equal(got, want) {
		t.Errorf("child asks %v, host judges %v", got, want)
	}
}

// An errno the kernel returns is reported by its name, one x/sys does not name by its number.
func TestErrnoName(t *testing.T) {
	for e, want := range map[syscall.Errno]string{1: "EPERM", 17: "EEXIST", 4095: "E4095"} {
		if got := errnoName(e); got != want {
			t.Errorf("%d: %q, want %q", int(e), got, want)
		}
	}
}
