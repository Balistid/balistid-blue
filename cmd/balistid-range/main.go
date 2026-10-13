// Command balistid-range builds the range base image and runs its self-test (ADR 0009). It runs as
// the maintainer from the repository root; the VM, not this program, is the isolation boundary.
package main

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx)
	stop()
	os.Exit(code)
}

func run(ctx context.Context) int {
	cache, state, err := dirs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "balistid-range:", err)
		return 1
	}
	switch {
	case len(os.Args) == 2 && os.Args[1] == "build":
		image, err := rangevm.Build(ctx, ".", cache, os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "balistid-range:", err)
			return 1
		}
		fmt.Println(image)
		return 0
	case len(os.Args) == 3 && os.Args[1] == "run":
		res, err := rangevm.Check(ctx, os.Args[2], cache, state)
		if err != nil {
			fmt.Fprintln(os.Stderr, "balistid-range:", err)
			return 1
		}
		fmt.Printf("%s: %s (result %s)\n", res.Verdict, res.Reason, res.ID)
		if res.Verdict != rangevm.Pass {
			return 1
		}
		return 0
	case len(os.Args) == 4 && os.Args[1] == "trial":
		tr, ok := rangejob.Lookup(os.Args[2])
		if !ok {
			fmt.Fprintln(os.Stderr, "balistid-range: no such trial")
			return 2
		}
		res, err := rangevm.CheckTrial(ctx, os.Args[3], cache, state, tr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "balistid-range:", err)
			return 1
		}
		fmt.Printf("%s %s %s: %s (result %s)\n", tr.Name, res.Label, res.Verdict, res.Reason, res.ID)
		if len(res.Measures) > 0 {
			keys := slices.Sorted(maps.Keys(res.Measures))
			fmt.Print("measures:")
			for _, k := range keys {
				fmt.Printf(" %s=%d", k, res.Measures[k])
			}
			fmt.Println()
		}
		if want := rangevm.ExpectedVerdict(tr); res.Verdict != want {
			fmt.Printf("%s must give %s\n", tr.Name, want)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: balistid-range build | balistid-range run <image.raw> | balistid-range trial <name> <image.raw>")
		return 2
	}
}

func dirs() (cache, state string, err error) {
	c, err := os.UserCacheDir()
	if err != nil {
		return "", "", fmt.Errorf("cache directory: %w", err)
	}
	state = os.Getenv("XDG_STATE_HOME")
	if state == "" || !filepath.IsAbs(state) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", fmt.Errorf("state directory: %w", err)
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(c, "balistid-range"), filepath.Join(state, "balistid-range"), nil
}
