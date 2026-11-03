// Command balistid-install installs a Balistid Blue component only from a release whose MANIFEST the maintainer
// signed (ADR 0053, 0058). `verify` is the unprivileged dry run; `runner` installs the range runner as root.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Balistid/balistid-blue/internal/install"
)

func main() { os.Exit(run(context.Background(), os.Args[1:], os.Geteuid())) }

const usage = "usage: balistid-install verify <dir> [<fingerprint>] | balistid-install runner <dir> <maintainer> [<fingerprint>]"

// run is the exit status: 0 verified or installed, 1 refused or stopped, 2 a usage error.
func run(ctx context.Context, args []string, euid int) int {
	cfg := install.DefaultConfig()
	switch {
	case len(args) >= 2 && len(args) <= 3 && args[0] == "verify":
		r, err := install.Check(ctx, cfg, args[1], optional(args, 2))
		if err != nil {
			fmt.Fprintln(os.Stderr, "balistid-install: refused: "+err.Error())
			return 1
		}
		fmt.Printf("verified: component %s, commit %s, signed by %s\n", r.Manifest.Component, r.Manifest.Commit,
			r.Signer.Fingerprint())
		for _, f := range r.Manifest.Files {
			fmt.Printf("%x  %s\n", f.SHA256, f.Name)
		}
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
