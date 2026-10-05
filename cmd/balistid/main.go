// Command balistid is the unprivileged command-line client.
package main

import (
	"fmt"
	"os"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String())
		return
	}
	fmt.Fprintln(os.Stderr, "usage: balistid version")
	os.Exit(2)
}
