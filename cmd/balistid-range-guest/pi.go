package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
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
			return fmt.Sprintf("error: the relay served %d of %d entries (%v)", n, cp.Size, err)
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
	return fmt.Sprintf("error: the Pi verified %d of %d entries", l.Size, cp.Size)
}
