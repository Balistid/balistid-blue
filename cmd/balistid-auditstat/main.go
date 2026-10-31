// balistid-auditstat reports the kernel's audit status every 5 s for the collector (ADR 0038). It is the one
// long-running process with CAP_AUDIT_CONTROL and sends only AUDIT_GET (ADR 0007, R13).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/auditstat"
)

const memLimit = 8 << 20

func main() { os.Exit(run()) }

func run() int {
	report := flag.String("report", "/run/balistid-auditstat/report", "the report file, in the unit's runtime directory")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := auditstat.Run(ctx, *report); err != nil {
		log.Error("auditstat stopped", "err", err)
		return 1
	}
	return 0
}
