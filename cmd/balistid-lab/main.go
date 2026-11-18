// Command balistid-lab is the detection judge's tool (ADR 0077): `job` writes a pair's run as a job directory,
// `import` copies a runner result into lab/windows, `table` judges lab/, `verify` compares lab/ with the runner's
// results. No privilege, no network; table and verify take no time or name and write nothing.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Balistid/balistid-blue/internal/detect"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "verify" || os.Args[1] == "import") {
		if err := detect.RunnerOwned(detect.ResultsDir); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "balistid-lab:", printable(err.Error())) // the exit status carries it
			os.Exit(1)
		}
	}
	os.Exit(run(os.Args[1:], detect.ResultsDir, os.Stdout, os.Stderr))
}

const usage = `usage:
  balistid-lab job <lab> <pair> <run> <target>   write the run's job directory under target
  balistid-lab import <lab> <result id>          copy the runner's result into lab/windows
  balistid-lab table <lab>                       judge lab/, as JSON on stdout
  balistid-lab verify <lab>                      lab/windows against the runner's results`

// run is main with its inputs passed in; results is the runner's results directory, fixed in main. It returns
// 0 on success, 1 on a failure or a finding, 2 on a usage error; a write to stdout that fails is a failure.
func run(args []string, results string, stdout, stderr io.Writer) int {
	out, code, err := dispatch(args, results)
	if err != nil {
		_, _ = io.WriteString(stderr, printable("balistid-lab: "+err.Error())+"\n") // the exit status carries it
		return code
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		_, _ = fmt.Fprintln(stderr, "balistid-lab: write:", printable(err.Error()))
		return 1
	}
	return 0
}

// printable escapes every byte of s outside printable ASCII, line by line, so a name in lab/ cannot drive the
// terminal.
func printable(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		var b bytes.Buffer
		for _, c := range []byte(l) {
			if c >= 0x20 && c <= 0x7e {
				b.WriteByte(c)
				continue
			}
			fmt.Fprintf(&b, `\x%02x`, c)
		}
		lines[i] = b.String()
	}
	return strings.Join(lines, "\n")
}

// dispatch runs one subcommand: its output, and the exit status with the error when it fails.
func dispatch(args []string, results string) (string, int, error) {
	cmd, rest := "", []string(nil)
	if len(args) > 0 {
		cmd, rest = args[0], args[1:]
	}
	switch {
	case cmd == "job" && len(rest) == 4:
		lab, pair, runName, target := rest[0], rest[1], rest[2], rest[3]
		out, err := detect.Job(lab, pair, runName, target)
		if err != nil {
			return "", 1, fmt.Errorf("job: %w", err)
		}
		return out + "\n", 0, nil
	case cmd == "import" && len(rest) == 2:
		lab, id := rest[0], rest[1]
		n, err := detect.Import(lab, results, id)
		if err != nil {
			return "", 1, fmt.Errorf("import: %w", err)
		}
		return fmt.Sprintf("imported %s; lab/ holds %d bytes of %d\n", id, n, detect.LabCap), 0, nil
	case cmd == "table" && len(rest) == 1:
		lab, err := detect.Load(rest[0])
		if err != nil {
			return "", 1, fmt.Errorf("table: %w", err)
		}
		return string(lab.Table().Encode()), 0, nil
	case cmd == "verify" && len(rest) == 1:
		findings, digest, err := detect.Verify(rest[0], results)
		if err != nil {
			return "", 1, fmt.Errorf("verify: %w", err)
		}
		if len(findings) > 0 {
			return "", 1, fmt.Errorf("verify failed, %d findings:\n%s", len(findings), strings.Join(findings, "\n"))
		}
		return fmt.Sprintf("verify (%s): every runner result after the anchor is in lab/windows, byte for byte; "+
			"sha256 %s\n", detect.Version, digest), 0, nil
	}
	return "", 2, fmt.Errorf("%s", usage)
}
