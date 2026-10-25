package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// Only a run's first boot formats the disk, so a reset's second boot finds what the first wrote and
// reads the superblock before mounting; every mount is noexec, nosuid, nodev, and only a failure
// trial's has commit=300 (ADR 0022 point 2, ADR 0020).
func TestPlanScratch(t *testing.T) {
	trial := func(name string) rangejob.Trial {
		tr, ok := rangejob.Lookup(name)
		if !ok {
			t.Fatalf("no trial %s", name)
		}
		return tr
	}
	safe := uintptr(syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV)
	for name, c := range map[string]struct {
		tr   rangejob.Trial
		boot int
		want scratchSteps
	}{
		"self-test or exec": {rangejob.Trial{}, 1, scratchSteps{format: true, flags: safe}},
		"rate trial":        {trial("rate-burst"), 1, scratchSteps{format: true, flags: safe}},
		"kill trial":        {trial("kill-control-buffer2s"), 1, scratchSteps{format: true, flags: safe, data: "commit=300"}},
		"reset, boot 1":     {trial("reset-control-sync250"), 1, scratchSteps{format: true, flags: safe, data: "commit=300"}},
		"reset, boot 2":     {trial("reset-control-sync250"), 2, scratchSteps{superblock: true, flags: safe, data: "commit=300"}},
	} {
		if got := planScratch(c.tr, c.boot); got != c.want {
			t.Errorf("%s: %+v, want %+v", name, got, c.want)
		}
	}
}

// Boot 2 reports exactly the two superblock facts store-setup recorded; anything else is the
// trial's error, never a guess.
func TestReportSuperblock(t *testing.T) {
	good := rangevm.FactScratchJournal + " yes\n" + rangevm.FactScratchRecovery + " no\n"
	for name, c := range map[string]struct {
		text string
		ok   bool
	}{
		"recorded":    {good, true},
		"one fact":    {rangevm.FactScratchJournal + " yes\n", false},
		"swapped":     {rangevm.FactScratchRecovery + " no\n" + rangevm.FactScratchJournal + " yes\n", false},
		"other value": {rangevm.FactScratchJournal + " maybe\n" + rangevm.FactScratchRecovery + " no\n", false},
		"extra line":  {good + "x y\n", false},
	} {
		path := filepath.Join(t.TempDir(), "superblock")
		if err := os.WriteFile(path, []byte(c.text), 0o600); err != nil {
			t.Fatal(err)
		}
		r := &report{}
		err := r.superblock(path)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if c.ok && (len(r.facts) != 2 || r.facts[0] != (fact{rangevm.FactScratchJournal, "yes"}) || r.facts[1] != (fact{rangevm.FactScratchRecovery, "no"})) {
			t.Errorf("%s: facts %v", name, r.facts)
		}
	}
	if err := (&report{}).superblock(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("a missing superblock file was accepted")
	}
}

// A failure trial writes its numbers only to a mounted scratch disk, never into the root below it.
func TestMountedTellsAMountFromADirectory(t *testing.T) {
	if mounted(t.TempDir()) {
		t.Error("a plain directory counts as mounted")
	}
	if !mounted("/proc") {
		t.Error("/proc does not count as mounted")
	}
}
