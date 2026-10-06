// Command balistid-runner runs range jobs for agents as its own user (ADR 0011): "build" at
// install builds the image of its own commit, "tick" from its timer runs one evidence run or one
// agent job. Every path comes from its unit; nothing has a default.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/rangerun"
)

const usage = "usage: balistid-runner version | build --state DIR --objects DIR | tick --state DIR --inbox DIR --results DIR"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println(buildinfo.String())
		return 0
	}
	if len(args) == 0 || (args[0] != "build" && args[0] != "tick") {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	// Each command takes exactly its own flags, all required.
	names := map[string][]string{"build": {"state", "objects"}, "tick": {"state", "inbox", "results"}}[args[0]]
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	paths := map[string]*string{}
	for _, n := range names {
		paths[n] = flags.String(n, "", "an absolute, clean path")
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	for _, n := range names {
		if p := *paths[n]; !filepath.IsAbs(p) || filepath.Clean(p) != p {
			fmt.Fprintln(os.Stderr, usage+"\nevery path must be absolute and clean")
			return 2
		}
	}
	get := func(n string) string {
		if p, ok := paths[n]; ok {
			return *p
		}
		return ""
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	commit, err := buildinfo.Commit()
	if err != nil {
		log.Error("refused", "err", err, "rule", rangerun.RuleVersion)
		return 1
	}
	r := rangerun.New(get("state"), get("inbox"), get("results"), commit, log)
	if args[0] == "build" {
		err = r.Build(ctx, get("objects"), os.Stderr)
	} else {
		err = r.Tick(ctx)
	}
	if err != nil {
		log.Error(args[0]+" failed", "err", err, "rule", rangerun.RuleVersion)
		return 1
	}
	return 0
}
