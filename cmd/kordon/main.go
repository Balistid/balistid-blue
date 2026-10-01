// Command kordon is the unprivileged command-line client.
package main

import (
	"fmt"
	"os"

	"github.com/Kordon-Sec/kordon/internal/buildinfo"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String())
		return
	}
	fmt.Fprintln(os.Stderr, "usage: kordon version")
	os.Exit(2)
}
