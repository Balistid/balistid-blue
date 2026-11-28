// Command balistid-judge reads the collector's sealed store and writes the recorder's state and the users' execs
// (ADR 0082): run by its unit without arguments, as the collector's uid. `view`, which any user runs, assigns those
// runs to agents and checks the probes. It judges no recording day yet (ADR 0074 points 3 to 8 wait with the
// recorder, ADR 0076), and nothing it writes says OK (R6).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/shard"
)

// Where the unit has the store, its results and its own tmpfs; shards are at most the collector's shardMax and
// a WAL (cmd/balistid-range-guest copies them the same way).
const (
	storeDir   = "/var/lib/balistid/collector/store"
	resultsDir = "/var/lib/balistid/judge"
	scratchDir = "/tmp"
	scratchMax = 512<<20 + shard.WALMaxBytes
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "view" { // no handler: Ctrl-C ends view as it ends any program
		os.Exit(run(context.Background(), os.Args[1:]))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	code := run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

const usage = "usage: balistid-judge | balistid-judge view <dir> [manifest.json ...]"

// run is the judge with its arguments: none, as the unit starts it, or view, which any user runs on its results.
// The judge returns 0 only when every sealed shard was read, 2 when the state is PARTIAL or UNKNOWN; view 0 when
// it read both files, 2 when not; either 1 on a usage error.
func run(ctx context.Context, args []string) int {
	if len(args) >= 2 && args[0] == "view" {
		owners, err := collector()
		if err == nil {
			err = view(args[1], args[2:], owners, os.Stdout)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "balistid-judge: UNKNOWN %v\n", err)
			return 2
		}
		return 0
	}
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 1
	}
	status, err := judge(ctx, config{Store: storeDir, Out: resultsDir, Scratch: shard.Scratch{Dir: scratchDir, Max: scratchMax},
		Now: time.Now, Limit: readLimit})
	if err != nil {
		fmt.Fprintf(os.Stderr, "balistid-judge: %s %v\n", status, err)
	}
	return exitCode(status, err)
}

// exitCode is 0 only for a COMPLETE read whose every file was written.
func exitCode(status string, err error) int {
	if err != nil || status != statusComplete {
		return 2
	}
	return 0
}
