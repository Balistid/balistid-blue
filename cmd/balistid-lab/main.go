// Command balistid-lab is the detection judge's tool (ADR 0077): `job` writes a pair's run as a job directory,
// `import` copies a runner result into lab/windows, `table` judges lab/, `verify` compares lab/ with the runner's
// results. No privilege, no network; table and verify take no time or name and write nothing.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Balistid/balistid-blue/internal/detect"
)

func main() { os.Exit(entry(os.Args[1:], detect.ResultsDir, os.Stdout, os.Stderr)) }

// entry is main: verify and import first check that results is the runner's, not a copy an agent made (R13).
func entry(args []string, results string, stdout, stderr io.Writer) int {
	if (len(args) == 2 && args[0] == "verify") || (len(args) == 3 && args[0] == "import") {
		if err := detect.RunnerOwned(results); err != nil {
			_, _ = fmt.Fprintln(stderr, "balistid-lab:", printable(err.Error())) // the exit status carries it
			return 1
		}
	}
	return run(args, results, stdout, stderr)
}

const usage = `usage:
  balistid-lab job <lab> <pair> <run> <target>   write the run's job directory under target
  balistid-lab import <lab> <result id>          copy the runner's result into lab/windows
  balistid-lab table <lab>                       judge lab/, as JSON on stdout
  balistid-lab verify <lab>                      lab/windows against the runner's results`

// run is main with its inputs passed in; results is the runner's results directory, fixed in main. It returns
// 0 on success, 1 on a failure or a finding, 2 on a usage error; a write to stdout that fails is a failure.
func run(args []string, results string, stdout, stderr io.Writer) int {
	out, err := dispatch(args, results)
	var f findings
	switch {
	case errors.As(err, &f):
		lines := make([]string, 0, len(f))
		for _, l := range f {
			lines = append(lines, printable(l))
		}
		lines = append(lines, fmt.Sprintf("balistid-lab: verify failed, %d findings", len(f)))
		_, _ = io.WriteString(stderr, strings.Join(lines, "\n")+"\n") // the exit status carries it
		return 1
	case errors.Is(err, errUsage):
		_, _ = io.WriteString(stderr, usage+"\n") // the exit status carries it
		return 2
	case err != nil:
		_, _ = io.WriteString(stderr, "balistid-lab: "+args[0]+": "+printable(err.Error())+"\n") // the exit status carries it
		return 1
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		_, _ = fmt.Fprintln(stderr, "balistid-lab: write:", printable(err.Error()))
		return 1
	}
	return 0
}

// printable escapes every byte of s outside printable ASCII, LF too, so a name in lab/ can neither drive the
// terminal nor forge a line.
func printable(s string) string {
	var b bytes.Buffer
	for _, c := range []byte(s) {
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, `\x%02x`, c)
	}
	return b.String()
}

// findings are verify's, one per line when printed; a usage text is the only other multi-line message.
type findings []string

func (f findings) Error() string { return strings.Join(f, "; ") }

// dispatch runs one subcommand: its output, or why it failed (errUsage for a usage error).
func dispatch(args []string, results string) (string, error) {
	switch {
	case len(args) == 5 && args[0] == "job":
		out, err := detect.Job(args[1], args[2], args[3], args[4])
		return out + "\n", err //nolint:wrapcheck // run names the subcommand
	case len(args) == 3 && args[0] == "import":
		n, err := detect.Import(args[1], results, args[2])
		return fmt.Sprintf("imported %s; lab/ holds %d bytes of %d\n", args[2], n, detect.LabCap), err
	case len(args) == 2 && args[0] == "table":
		lab, err := detect.Load(args[1])
		if err != nil {
			return "", err //nolint:wrapcheck // run names the subcommand
		}
		return string(lab.Table().Encode()), nil
	case len(args) == 2 && args[0] == "verify":
		found, digest, err := detect.Verify(args[1], results)
		switch {
		case err != nil:
			return "", err //nolint:wrapcheck // run names the subcommand
		case len(found) > 0:
			return "", findings(found)
		}
		return fmt.Sprintf("verify (%s): every runner result after the anchor is in lab/windows, byte for byte; "+
			"sha256 %s\n", detect.Version, digest), nil
	}
	return "", errUsage
}

var errUsage = errors.New("usage")
