// Command balistid is the unprivileged command-line client.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/status"
)

func main() { os.Exit(run(os.Args[1:])) }

// run is the exit status: 0 OK, 1 a floor that is not OK, 2 a usage or output error.
func run(args []string) int {
	switch {
	case len(args) == 1 && args[0] == "version":
		fmt.Println(buildinfo.String())
		return 0
	case len(args) == 1 && args[0] == "status", len(args) == 2 && args[0] == "status" && args[1] == "--json":
		res := status.Check(context.Background(), status.Host())
		write := status.WriteText
		if len(args) == 2 {
			write = status.WriteJSON
		}
		if err := write(os.Stdout, res); err != nil {
			fmt.Fprintln(os.Stderr, "balistid: "+err.Error())
			return 2
		}
		if !res.OK {
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: balistid version | balistid status [--json]")
	return 2
}
