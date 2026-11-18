// Command balistid-lab is the detection judge's tool (ADR 0077): `job` writes a pair's run as a job directory,
// `import` copies a runner result into lab/windows, `table` judges lab/, `verify` compares lab/ with the runner's
// results. No privilege, no network; table and verify take no time or name and write nothing.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Balistid/balistid-blue/internal/detect"
)

func main() { os.Exit(run(os.Args[1:], detect.ResultsDir, os.Stdout, os.Stderr)) }

const usage = `usage:
  balistid-lab job <lab> <pair> <run> <target>   write the run's job directory under target
  balistid-lab import <lab> <result id>          copy the runner's result into lab/windows
  balistid-lab table <lab>                       judge lab/, as JSON on stdout
  balistid-lab verify <lab>                      lab/windows against the runner's results`

// run is main with its inputs passed in; results is the runner's results directory, fixed in main.
func run(args []string, results string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "balistid-lab:", err)
		return 1
	}
	switch {
	case len(args) == 5 && args[0] == "job":
		out, err := detect.Job(args[1], args[2], args[3], args[4])
		if err != nil {
			return fail(err)
		}
		fmt.Fprintln(stdout, out)
	case len(args) == 3 && args[0] == "import":
		n, err := detect.Import(args[1], results, args[2])
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "imported %s; lab/ holds %d bytes\n", args[2], n)
	case len(args) == 2 && args[0] == "table":
		lab, err := detect.Load(args[1])
		if err != nil {
			return fail(err)
		}
		_, _ = stdout.Write(lab.Table().Encode())
	case len(args) == 2 && args[0] == "verify":
		findings, err := detect.Verify(args[1], results)
		if err != nil {
			return fail(err)
		}
		if len(findings) > 0 {
			fmt.Fprintln(stderr, strings.Join(findings, "\n"))
			fmt.Fprintf(stderr, "balistid-lab: verify failed: %d findings\n", len(findings))
			return 1
		}
		fmt.Fprintln(stdout, "verify: every runner result after the anchor is in lab/windows, byte for byte")
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	return 0
}
