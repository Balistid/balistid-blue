// Command balistid-judge reads the collector's sealed store and writes the recorder's state and the users' execs
// (ADR 0082): run by its unit without arguments, as the collector's uid. It judges no recording day yet (ADR 0074
// points 3 to 8 wait with the recorder, ADR 0076), and nothing it writes says OK (R6).
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	code := run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// run is the judge with its arguments: none, as the unit starts it. It returns 0 only when every sealed shard
// was read, 2 when the state is PARTIAL or UNKNOWN, 1 on a usage error.
func run(ctx context.Context, args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: balistid-judge")
		return 1
	}
	status, err := judge(ctx, config{Store: storeDir, Out: resultsDir, Scratch: shard.Scratch{Dir: scratchDir, Max: scratchMax},
		Now: time.Now, Limit: readLimit})
	if err != nil {
		fmt.Fprintf(os.Stderr, "balistid-judge: %s %v\n", status, err)
	}
	if status != statusComplete {
		return 2
	}
	return 0
}
