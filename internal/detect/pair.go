package detect

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// RunNames are a pair's four runs (ADR 0079 point 6): technique and twin, two variants each.
var RunNames = []string{"tech-a", "tech-b", "twin-a", "twin-b"}

// MaxPairRun bounds pair and run together in a job name (ADR 0077 point 2).
const MaxPairRun = 30

var (
	pairName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	hex32    = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Run is one of a pair's programs.
type Run struct {
	Program  string // the program's file name in the job directory
	TimeoutS int64
	Text     []byte // the program, a `#!/bin/sh` script
}

// Pair is a technique and its legitimate twin (ADR 0077 point 1).
type Pair struct {
	Name      string
	Attack    string
	Author    string
	Brief     string
	Reference Rule
	Runs      map[string]Run
}

// Rule is one rule's file: the rule and who wrote it.
type RuleFile struct {
	Path        string // relative to lab/
	Rule        Rule
	Model       string
	Sample      int64
	BriefSHA256 string
}

// technique reports whether a run is one of the technique's.
func technique(run string) bool { return strings.HasPrefix(run, "tech-") }

func decodePair(name string, data []byte) (Pair, error) {
	if !plainText(data) {
		return Pair{}, errors.New("not printable ASCII and LF")
	}
	if !pairName.MatchString(name) || len(name)+len("-twin-a") > MaxPairRun {
		return Pair{}, fmt.Errorf("pair name %q", name)
	}
	v, err := decode(data, false)
	if err != nil {
		return Pair{}, err
	}
	o, err := fields(v, []string{"attack", "author", "brief", "reference", "runs"}, nil)
	if err != nil {
		return Pair{}, err
	}
	p := Pair{Name: name, Runs: map[string]Run{}}
	var ok [3]bool
	p.Attack, ok[0] = str(o, "attack")
	p.Author, ok[1] = str(o, "author")
	p.Brief, ok[2] = str(o, "brief")
	if !ok[0] || !ok[1] || !ok[2] {
		return Pair{}, errors.New("attack, author and brief are strings")
	}
	if p.Reference, err = decodeRule(o["reference"]); err != nil {
		return Pair{}, fmt.Errorf("reference: %w", err)
	}
	runs, err := fields(o["runs"], RunNames, nil)
	if err != nil {
		return Pair{}, fmt.Errorf("runs: %w", err)
	}
	for _, rn := range RunNames {
		ro, err := fields(runs[rn], []string{"program", "timeout_s", "text"}, nil)
		if err != nil {
			return Pair{}, fmt.Errorf("run %s: %w", rn, err)
		}
		prog, pok := str(ro, "program")
		timeout, tok := integer(ro, "timeout_s")
		text, xok := str(ro, "text")
		switch {
		case !pok || !programName.MatchString(prog) || prog == "job.json":
			return Pair{}, fmt.Errorf("run %s: program name", rn)
		case !tok || timeout < 1 || timeout > 300:
			return Pair{}, fmt.Errorf("run %s: timeout_s must be 1 to 300", rn)
		case !xok || !strings.HasPrefix(text, "#!/bin/sh\n") || len(text) > 1<<20:
			return Pair{}, fmt.Errorf("run %s: text must be a #!/bin/sh program of at most 1 MiB", rn)
		}
		p.Runs[rn] = Run{Program: prog, TimeoutS: timeout, Text: []byte(text)}
	}
	return p, nil
}

func decodeRuleFile(path string, data []byte) (RuleFile, error) {
	if !plainText(data) {
		return RuleFile{}, errors.New("not printable ASCII and LF")
	}
	v, err := decode(data, false)
	if err != nil {
		return RuleFile{}, err
	}
	o, err := fields(v, []string{"rule", "model", "sample", "params", "brief_sha256"}, nil)
	if err != nil {
		return RuleFile{}, err
	}
	rf := RuleFile{Path: path}
	var ok [3]bool
	rf.Model, ok[0] = str(o, "model")
	rf.Sample, ok[1] = integer(o, "sample")
	rf.BriefSHA256, ok[2] = str(o, "brief_sha256")
	if !ok[0] || !ok[1] || !ok[2] || !hex64.MatchString(rf.BriefSHA256) {
		return RuleFile{}, errors.New("model, sample and brief_sha256")
	}
	if _, isObject := o["params"].(object); !isObject {
		return RuleFile{}, errors.New("params is an object")
	}
	if rf.Rule, err = decodeRule(o["rule"]); err != nil {
		return RuleFile{}, err
	}
	return rf, nil
}

// contentHash binds a pair's and its rules' files (ADR 0079 point 6): paths relative to lab/ in byte order, each
// path and its bytes prefixed by their length, sha256, the first 32 hex digits.
func contentHash(files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	h := sha256.New()
	for _, p := range paths {
		for _, part := range [][]byte{[]byte(p), files[p]} {
			h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(part))))
			h.Write(part)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// jobName is the name a run's job must carry: `<pair>-<run>-<32 hex>` (ADR 0077 point 2).
func jobName(pair, run, hash string) string { return pair + "-" + run + "-" + hash }

// splitJobName parses a job name into pair, run and hash, or fails.
func splitJobName(name string) (pair, run, hash string, ok bool) {
	if len(name) < 34 || name[len(name)-33] != '-' {
		return "", "", "", false
	}
	hash, rest := name[len(name)-32:], name[:len(name)-33]
	if !hex32.MatchString(hash) {
		return "", "", "", false
	}
	for _, rn := range RunNames {
		if p, found := strings.CutSuffix(rest, "-"+rn); found && pairName.MatchString(p) {
			return p, rn, hash, true
		}
	}
	return "", "", "", false
}
