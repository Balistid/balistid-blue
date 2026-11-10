// Command balistid-install installs a Balistid Blue component only from a release whose MANIFEST the maintainer
// signed (ADR 0053, 0058, 0068). `verify` is the unprivileged dry run; `recorder`, `judge` and `runner` install as root.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Balistid/balistid-blue/internal/install"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Geteuid())) }

const usage = "usage: balistid-install verify recorder|judge|runner <dir> [<fingerprint>] | " +
	"balistid-install recorder <dir> [<fingerprint>] | balistid-install judge <dir> [<fingerprint>] | " +
	"balistid-install runner <dir> <maintainer> [<fingerprint>]"

// run is the exit status: 0 verified or installed, 1 refused or stopped, 2 a usage error.
func run(ctx context.Context, args []string, euid int) int {
	cfg := install.DefaultConfig()
	switch {
	case len(args) >= 3 && len(args) <= 4 && args[0] == "verify":
		r, err := install.Check(ctx, cfg, args[1], args[2], optional(args, 3))
		if err != nil {
			fmt.Fprintln(os.Stderr, "balistid-install: refused: "+err.Error())
			return 1
		}
		fmt.Printf("verified: component %s, commit %s, signed by %s\n", r.Manifest.Component, r.Manifest.Commit,
			r.Signer.Fingerprint())
		for _, f := range r.Manifest.Files {
			fmt.Printf("%x  %s\n", f.SHA256, f.Name)
		}
		if r.Manifest.Component == "recorder" {
			fmt.Println(install.RecorderNotice)
		}
		return 0
	case len(args) >= 2 && len(args) <= 3 && args[0] == "recorder":
		if euid != 0 {
			fmt.Fprintln(os.Stderr, "balistid-install: recorder installs as root only")
			return 1
		}
		fmt.Fprintln(os.Stderr, "balistid-install: "+install.RecorderNotice)
		if install.Recorder(ctx, cfg, args[1], optional(args, 2)) != nil {
			return 1 // Recorder logged the reason
		}
		fmt.Println("installed and enabled, nothing started. Reboot to load and lock the rules, then run balistid status.")
		return 0
	case len(args) >= 2 && len(args) <= 3 && args[0] == "judge":
		if euid != 0 {
			fmt.Fprintln(os.Stderr, "balistid-install: judge installs as root only")
			return 1
		}
		if install.Judge(ctx, cfg, args[1], optional(args, 2)) != nil {
			return 1 // Judge logged the reason
		}
		fmt.Println("installed, nothing enabled or started. To judge: systemctl start balistid-judge; results are in /var/lib/balistid/judge.")
		return 0
	case len(args) >= 3 && len(args) <= 4 && args[0] == "runner":
		if euid != 0 {
			fmt.Fprintln(os.Stderr, "balistid-install: runner installs as root only")
			return 1
		}
		if install.Runner(ctx, cfg, args[1], args[2], optional(args, 3)) != nil {
			return 1 // Runner logged the reason
		}
		fmt.Println("installed. As the maintainer: copy the commit's .git/objects into /var/lib/balistid/objects/.git/objects;")
		fmt.Println("then as root: systemctl start balistid-runner-build && systemctl enable --now balistid-runner-tick.timer")
		return 0
	}
	fmt.Fprintln(os.Stderr, usage)
	return 2
}

// optional is args[i], or "" when it was not given.
func optional(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}
