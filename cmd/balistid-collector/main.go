// Command balistid-collector takes Laurel's records over the socket systemd passes and stores them as
// evidence (ADR 0016, 0017). It runs as its own uid without privilege (ADR 0007).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/collector"
	"github.com/Balistid/balistid-blue/internal/store"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// memLimit keeps the heap well under the unit's share of rss_mib (512 MiB for all of floor 0).
	memLimit = 192 << 20
	// The raw store's caps: raw_cap_gib 150, headroom_gib 2, and shards of 512 MiB so that sealing
	// one stays within crash_loss_ms (ADR 0016, point 6).
	rawCap, headroom, shardMax = 150 << 30, 2 << 30, 512 << 20
)

func main() { os.Exit(run()) }

func run() int {
	storeDir := flag.String("store", "/var/lib/balistid/collector/store", "raw store directory")
	canaryDir := flag.String("canary", "/var/lib/balistid/collector/canary", "directory the canary audit rule watches")
	ruleVersion := flag.String("rule-version", "", "version of the installed audit rules, for the started record")
	// The range image alone sets these two (ADR 0022): its root has no room for the host's reserve.
	headroomBytes := flag.Int64("headroom", headroom, "bytes the store reserves for its own records")
	logCommits := flag.Bool("log-commits", false, "journal the store's last durable seq on every change")
	ledgerSocket := flag.String("ledger", "", "the ledger's socket; empty runs without a ledger (ADR 0027)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ln, err := collector.ListenFD()
	if err != nil {
		log.Error("no socket from systemd", "err", err)
		return 1
	}
	var ledger *collector.Ledger
	if *ledgerSocket != "" {
		ledger = collector.NewLedger(collector.DialLedger(*ledgerSocket, uidOf("balistid-ledger", log)), log)
	}
	err = collector.Run(ctx, collector.Config{
		Listener: ln, LaurelUID: uidOf("_laurel", log), CanaryDir: *canaryDir, Ledger: ledger,
		OpenStore: openStore(*storeDir, *headroomBytes), Notify: unixsock.Notify, Log: log,
		Started:    map[string]string{"version": buildinfo.String(), "boot_id": bootID(), "rule_version": *ruleVersion},
		LogCommits: *logCommits,
	})
	if err != nil {
		log.Error("collector stopped", "err", err)
		return 1
	}
	return 0
}

// uidOf resolves a peer's account; -1 when it cannot, so every peer is refused (R6).
func uidOf(name string, log *slog.Logger) int {
	uid, err := unixsock.LookupUID(name)
	if err != nil {
		log.Error("account not resolved, refusing every peer", "account", name, "err", err)
	}
	return uid
}

// openStore opens the raw store; a failed Open yields a nil Store, never a nil *store.Store in it.
// Open refuses a headroom too small for a loss record.
func openStore(dir string, reserve int64) func(context.Context) (collector.Store, error) {
	return func(ctx context.Context) (collector.Store, error) {
		st, err := store.Open(ctx, dir, store.Limits{Cap: rawCap, ShardMax: shardMax, Headroom: reserve})
		if err != nil {
			return nil, err //nolint:wrapcheck // store errors carry their context
		}
		return st, nil
	}
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
