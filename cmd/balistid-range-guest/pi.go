package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/watch"
)

const (
	piUnit  = "balistid-pi.service"
	piState = "/var/lib/balistid-pi"
)

// piVerified: the Pi's watcher, standing in for the Pi (ADR 0031), verified the log up to the size the
// witness cosigned, from the bundles the relay served it. Stopped, it saves its state, which Load reads
// back only when its range gives its root; a step still running when it stops is tried again.
func piVerified(ctx context.Context) string {
	keys, err := rangeKeys()
	if err != nil {
		return "error: " + err.Error()
	}
	cp, err := cosign.Read(filepath.Join(relayState, cosign.Name), keys)
	if err != nil {
		return "error: " + err.Error()
	}
	for deadline := time.Now().Add(cosignWait); ; time.Sleep(time.Second) {
		n, err := cosign.ReadServed(filepath.Join(relayState, cosign.ServedName), keys.Origin)
		if err == nil && n >= cp.Size {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Sprintf("error: the relay served %d of %d entries (%v); %s", n, cp.Size, err, piDiag(ctx))
		}
	}
	store, err := watch.OpenStore(piState, keys.Origin)
	if err != nil {
		return "error: " + err.Error()
	}
	var l watch.Log
	for range 5 {
		time.Sleep(2 * time.Second)
		if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", piUnit).Run(); err != nil {
			return "error: stop " + piUnit + ": " + err.Error()
		}
		if l, _, err = store.Load(); err != nil {
			return "error: " + err.Error()
		}
		if l.Size >= cp.Size {
			if l.Size == cp.Size && !bytes.Equal(l.Root[:], cp.Root) {
				return "error: the Pi verified another root at the cosigned size"
			}
			return "yes"
		}
		if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "start", piUnit).Run(); err != nil {
			return "error: start " + piUnit + ": " + err.Error()
		}
	}
	return fmt.Sprintf("error: the Pi verified %d of %d entries; %s", l.Size, cp.Size, piDiag(ctx))
}

// piDiag is the watcher's unit state and its last journal lines, bounded, for a fact that failed: the
// range keeps no guest journal.
func piDiag(ctx context.Context) string {
	state := output(ctx, "/usr/bin/systemctl", "show", "--value", "-p", "ActiveState,SubState,Result,NRestarts", piUnit)
	journal := output(ctx, "/usr/bin/journalctl", "-u", piUnit, "-o", "cat", "--no-pager", "-n", "6")
	d := strings.Join(strings.Fields(state+" | "+journal), " ")
	return d[:min(len(d), 1500)]
}
