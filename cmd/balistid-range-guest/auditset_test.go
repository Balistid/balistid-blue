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

func errnoOf(n int) error { return syscall.Errno(n) }

type errPlain struct{}

func (errPlain) Error() string { return "not an errno" }

// An errno the kernel returns is reported by its name, one x/sys does not name by its number.
func TestErrnoResult(t *testing.T) {
	for err, want := range map[error]string{errnoOf(1): "EPERM", errnoOf(17): "EEXIST", errnoOf(4095): "E4095", errPlain{}: "EIO"} {
		if got := errnoResult(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}
