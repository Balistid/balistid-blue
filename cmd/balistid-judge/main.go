// Command balistid-judge will judge the host's recording days from the collector's sealed store (ADR 0074). Until
// it is built it answers UNKNOWN, so nothing reads its silence as a pass (R6).
package main

import (
	"fmt"
	"os"
)

func main() { os.Exit(run()) }

// run says why there is no verdict and returns the exit status 2.
func run() int {
	fmt.Fprintln(os.Stderr, "balistid-judge: UNKNOWN not built yet (ADR 0074)")
	return 2
}
