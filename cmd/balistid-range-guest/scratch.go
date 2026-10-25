package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

// The run's scratch disk, where range/balistid-range-store.service mounts it for the collector's store
// (ADR 0022, point 2), and the file in /run where it leaves a second boot's superblock for the guest.
const (
	storeSetupArg  = "store-setup"
	scratchDev     = "/dev/disk/by-id/virtio-balistid-scratch"
	scratchMount   = "/var/lib/balistid-range/scratch"
	storeDir       = scratchMount + "/store"
	superblockFile = "/run/balistid-range/superblock"
	collectorUser  = "balistid-collector"
)

// scratchSteps is what store-setup does for one boot: format the disk (only a run's first boot, so
// a reset leaves the second boot what the first wrote), read the superblock before the mount (the
// second boot of a reset, ADR 0018 point 3), and the mount's flags and data.
type scratchSteps struct {
	format, superblock bool
	flags              uintptr
	data               string
}

// planScratch returns the steps for boot of tr; a self-test or exec job is a first boot without a
// trial. Only a failure trial mounts with commit=300: there only an fsync may put data on the disk
// (ADR 0020).
func planScratch(tr rangejob.Trial, boot int) scratchSteps {
	s := scratchSteps{format: boot == 1, superblock: boot == 2, flags: syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV}
	if tr.Failure != "" {
		s.data = "commit=300"
	}
	return s
}

// storeSetup formats and mounts the scratch disk at scratchMount and gives the store directory to the
// collector's uid. In a reset's second boot it first records the superblock in superblockFile.
func storeSetup(ctx context.Context) error {
	name, phase, err := rangeguest.TrialCredentials(credentials())
	if err != nil {
		return fmt.Errorf("trial: %w", err)
	}
	tr, boot := rangejob.Trial{}, 1
	if name != "" {
		if tr, boot, err = rangeguest.TrialFor(name, phase); err != nil {
			return fmt.Errorf("trial: %w", err)
		}
	}
	steps := planScratch(tr, boot)
	if steps.superblock {
		if err := recordSuperblock(); err != nil {
			return err
		}
	}
	if steps.format {
		if out, err := exec.CommandContext(ctx, "/usr/bin/mkfs.ext4", "-q", "-F", scratchDev).CombinedOutput(); err != nil {
			return fmt.Errorf("mkfs: %w: %.200s", err, out)
		}
	}
	if err := os.MkdirAll(scratchMount, 0o755); err != nil { //nolint:gosec // the collector must traverse it to its store
		return fmt.Errorf("mount point: %w", err)
	}
	if err := syscall.Mount(scratchDev, scratchMount, "ext4", steps.flags, steps.data); err != nil {
		return fmt.Errorf("mount scratch: %w", err)
	}
	return ownStore()
}

// recordSuperblock writes whether the scratch disk holds a journal and needs recovery, read before
// anything mounted it, as the two facts the guest reports.
func recordSuperblock() error {
	head := make([]byte, rangeguest.SuperblockEnd)
	if err := readHead(scratchDev, head); err != nil {
		return fmt.Errorf("superblock: %w", err)
	}
	journal, recovery, err := rangeguest.Superblock(head)
	if err != nil {
		return fmt.Errorf("superblock: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(superblockFile), 0o700); err != nil {
		return fmt.Errorf("superblock: %w", err)
	}
	text := rangevm.FactScratchJournal + " " + yesNo(journal) + "\n" + rangevm.FactScratchRecovery + " " + yesNo(recovery) + "\n"
	if err := os.WriteFile(superblockFile, []byte(text), 0o600); err != nil {
		return fmt.Errorf("superblock: %w", err)
	}
	return nil
}

// ownStore creates the store directory, 0700 and owned by the collector, as the collector's Open
// requires; on a second boot it is already there.
func ownStore() error {
	u, err := user.Lookup(collectorUser)
	if err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	uid, errU := strconv.Atoi(u.Uid)
	gid, errG := strconv.Atoi(u.Gid)
	if err := errors.Join(errU, errG); err != nil {
		return fmt.Errorf("store directory: %w", err)
	}
	if err := os.Mkdir(storeDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("store directory: %w", err)
	}
	if err := errors.Join(os.Lchown(storeDir, uid, gid), os.Chmod(storeDir, 0o700)); err != nil { //nolint:gosec // a directory its owner must enter
		return fmt.Errorf("store directory: %w", err)
	}
	return nil
}

// mounted reports whether path is a mount point: a file the guest writes there must reach the scratch
// disk, never the root file system below a mount that failed.
func mounted(path string) bool {
	var st, parent syscall.Stat_t
	return syscall.Lstat(path, &st) == nil && syscall.Lstat(filepath.Dir(path), &parent) == nil && st.Dev != parent.Dev
}
