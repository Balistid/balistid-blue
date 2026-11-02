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
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/auditstat"
	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/collector"
	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/store"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

const (
	// memLimit is a soft Go runtime memory target, not a bound on RSS. rss_mib is 256 MiB for all of
	// floor 0 (ADR 0040), so this share is re-cut when rss_mib is first measured.
	memLimit = 192 << 20
	// The raw store's caps: raw_cap_gib 150, headroom_gib 2, and shards of 512 MiB so that sealing
	// one stays within crash_loss_ms (ADR 0016, point 6).
	rawCap, headroom, shardMax = 150 << 30, 2 << 30, 512 << 20
	// ledgerSocket is where the ledger's unit listens (RuntimeDirectory); the collector always streams
	// to it (ADR 0027) and redials while it is down.
	ledgerSocket = "/run/balistid-ledger/ledger.sock"
	// retention is raw_retention_days (acceptance/0.toml): both the witness's and the store's clock must
	// be this far past a shard's seal before it is retired (ADR 0029).
	retention = 30 * 24 * time.Hour
	// auditdState is auditd's state file, which the collector reads through auditd's log_group; auditSeen is its
	// own file of the last audit report it stored, in its StateDirectory (ADR 0038, points 2 and 3).
	auditdState = "/run/audit/auditd.state"
	auditSeen   = "/var/lib/balistid/collector/audit-seen"
)

func main() { os.Exit(run()) }

func run() int {
	storeDir := flag.String("store", "/var/lib/balistid/collector/store", "raw store directory")
	canaryDir := flag.String("canary", "/var/lib/balistid/collector/canary", "directory the canary audit rule watches")
	ruleVersion := flag.String("rule-version", "", "version of the installed audit rules, for the started record")
	// The range image alone sets these two (ADR 0022): its root has no room for the host's reserve.
	headroomBytes := flag.Int64("headroom", headroom, "bytes the store reserves for its own records")
	logCommits := flag.Bool("log-commits", false, "journal the store's last durable seq on every change")
	logKey := flag.String("log-key", "/etc/balistid/ledger-key.pub", "the ledger's checkpoint verifier key")
	witnessKey := flag.String("witness-key", "/etc/balistid/witness.vkey", "the witness's cosignature/v1 verifier key")
	cpuProfile := flag.String("cpuprofile", "", "exp only: write a CPU profile here until exit")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Error("cpu profile", "err", err)
			return 1
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Error("cpu profile", "err", err)
			return 1
		}
		defer func() { pprof.StopCPUProfile(); _ = f.Close() }()
	}
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
	ledger := collector.NewLedger(collector.DialLedger(ledgerSocket, uidOf("balistid-ledger", log)), log)
	// Recording never waits for the witness's keys: without them nothing is retired, and the cap drops.
	var keys *cosign.Keys
	if k, err := cosign.ReadKeys(*logKey, *witnessKey); err != nil {
		log.Error("verifier keys not read, no shard will be retired", "err", err)
	} else {
		keys = &k
	}
	boot := bootID()
	audit := collector.NewAudit(collector.AuditConfig{ReportPath: auditstat.ReportPath,
		ReportUID: uidOf("balistid-auditstat", log), StatePath: auditdState, SeenPath: auditSeen, BootID: boot})
	err = collector.Run(ctx, collector.Config{
		Listener: ln, LaurelUID: uidOf("_laurel", log), CanaryDir: *canaryDir, Ledger: ledger,
		OpenStore: openStore(*storeDir, *headroomBytes), Notify: unixsock.Notify, Log: log,
		Started:    map[string]string{"version": buildinfo.String(), "boot_id": boot, "rule_version": *ruleVersion},
		Audit:      audit,
		LogCommits: *logCommits, Cosign: keys, Retention: retention,
	})
	if err != nil {
		log.Error("collector stopped", "err", err)
		return 1
	}
	return 0
}

// uidOf resolves an account; -1 when it cannot, so every peer or report of it is refused (R6).
func uidOf(name string, log *slog.Logger) int {
	uid, err := unixsock.LookupUID(name)
	if err != nil {
		log.Error("account not resolved, refusing it", "account", name, "err", err)
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
