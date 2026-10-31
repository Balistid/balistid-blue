package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

const (
	// capDropIn lowers the ledger's cap through the variable of range/balistid-ledger-range.conf.
	capDropIn = "/run/systemd/system/balistid-ledger.service.d/zz-log-cap.conf"
	// capHeadroom is how many entries past the cosigned size the lowered cap allows, at about one batch a
	// second; capMin makes the log cross a full bundle, so its bytes can be measured.
	capHeadroom = 150
	capMin      = 300
	capFillWait = 7 * time.Minute
	// capSettle covers the refusal summary, logged once a minute, and a checkpoint that would show growth past
	// the cap's UNKNOWN.
	capSettle = 75 * time.Second
)

// runLogCap lowers the ledger's cap past the cosigned size (ADR 0036, point 5), keeps the log growing until the
// cap's UNKNOWN is cosigned, then reports what the cap left in the log and when the Pi's alert reached the sink.
func runLogCap(ctx context.Context, r *report) error {
	keys, err := rangeKeys()
	if err != nil {
		return r.fail(err.Error())
	}
	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	var cw cosignWatch
	go cw.run(wctx, keys)
	lctx, stopLoad := context.WithCancel(ctx)
	defer stopLoad()
	go lightLoad(lctx)
	if why := alarmReady(ctx, &cw); why != "" {
		return r.fail(why)
	}
	entries := max(cw.cosignedSize()+capHeadroom, capMin)
	inject := "ok"
	if err := lowerCap(ctx, entries); err != nil {
		inject = "error: " + err.Error()
	}
	restart, err := uptime()
	if err != nil {
		return r.fail(err.Error())
	}
	capAt := "none"
	for deadline := time.Now().Add(capFillWait); inject == "ok"; {
		if size := cw.cosignedSize(); size >= entries-1 {
			grew, _, _ := cw.state()
			capAt = strconv.FormatInt(grew.Milliseconds(), 10)
			break
		}
		if time.Now().After(deadline) || !pause(ctx, time.Second) {
			break
		}
	}
	stopLoad()
	pause(ctx, capSettle)
	stopWatch()
	cp, cpErr := cosign.Read(filepath.Join(relayState, cosign.Name), keys)
	posts, refused, err := readSink()
	if err != nil {
		return r.fail(err.Error())
	}
	if cpErr != nil {
		return r.fail("cosigned: " + cpErr.Error())
	}
	bundles, bytes := fullBundleBytes(ledgerLog, cp.Size)
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactInject, inject)
	r.add(rangevm.FactCapEntries, u(entries))
	r.add(rangevm.FactRestartMS, strconv.FormatInt(restart.Milliseconds(), 10))
	r.add(rangevm.FactCapMS, capAt)
	r.add(rangevm.FactCosignedEnd, u(cp.Size))
	r.add(rangevm.FactCapEntry, capEntry(ctx, cp, entries))
	r.add(rangevm.FactCapRefused, yesNo(strings.Contains(output(ctx, "/usr/bin/journalctl", "-b", "-u", ledgerUnit, "-o", "cat",
		"--no-pager", "-g", "refused connections"), `"cap":`)))
	r.add(rangevm.FactFullBundles, u(bundles))
	r.add(rangevm.FactFullBytes, u(bytes))
	r.add(rangevm.FactPosts, postsFact(posts, uint64(restart.Milliseconds()))) //nolint:gosec // uptime is positive
	r.add(rangevm.FactRefused, strconv.Itoa(refused))
	r.add(rangevm.FactPiActive, valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", piUnit))))
	return r.send(r.facts)
}

// lowerCap sets the ledger's cap to entries and restarts it with it.
func lowerCap(ctx context.Context, entries uint64) error {
	if err := os.MkdirAll(filepath.Dir(capDropIn), 0o755); err != nil { //nolint:gosec // systemd reads its drop-in directory
		return fmt.Errorf("drop-in: %w", err)
	}
	body := fmt.Sprintf("[Service]\nEnvironment=BALISTID_RANGE_LEDGER_CAP=%d\n", entries*entry.LogBytes)
	if err := os.WriteFile(capDropIn, []byte(body), 0o644); err != nil { //nolint:gosec // as above
		return fmt.Errorf("drop-in: %w", err)
	}
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	return systemctl(ctx, "restart", ledgerUnit)
}

// capEntry is "yes" when the entry before the final slot of a cap of entries is the cap's UNKNOWN, proven
// included in the cosigned root, else what it is.
func capEntry(ctx context.Context, cp cosign.Checkpoint, entries uint64) string {
	at := entries - 2
	if cp.Size <= at {
		return fmt.Sprintf("cosigned size %d does not reach %d", cp.Size, at)
	}
	e, err := cosign.ProvenEntry(ctx, ledgerLog, cp, at)
	if err != nil {
		return "error: " + err.Error()
	}
	if e.Body != entry.Body(entry.Health{State: entry.StateUnknown, Reason: entry.ReasonLogCap}) {
		return fmt.Sprintf("entry %d is %T", at, e.Body)
	}
	return "yes"
}

// fullBundleBytes is how many full entry bundles the log of size holds and their bytes on disk with their
// level-0 hash tiles, and the partial copies (.p/) of both that Tessera keeps until its GC: what the cap counts
// per entry, without the right edge, whose partials belong to the bundle still filling.
func fullBundleBytes(dir string, size uint64) (bundles, bytes uint64) {
	for i := range size / layout.EntryBundleWidth {
		for _, p := range []string{layout.EntriesPath(i, 0), layout.TilePath(0, i, 0)} {
			var st syscall.Stat_t
			if err := syscall.Lstat(filepath.Join(dir, p), &st); err != nil {
				return 0, 0 // a full bundle without its file measures nothing
			}
			bytes += uint64(st.Blocks) * 512 //nolint:gosec // st_blocks is never negative
			partials, _ := os.ReadDir(filepath.Join(dir, p+".p"))
			for _, e := range partials {
				if err := syscall.Lstat(filepath.Join(dir, p+".p", e.Name()), &st); err == nil {
					bytes += uint64(st.Blocks) * 512 //nolint:gosec // as above
				}
			}
		}
		bundles++
	}
	return bundles, bytes
}
