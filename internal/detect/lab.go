package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// Read caps (R5): a result is small; any other window file is the runner's escape of at most LaurelCap bytes.
const (
	resultCap = 64 << 10
	textCap   = 4 * LaurelCap
	pairCap   = 5 << 20
	ruleCap   = 64 << 10
)

// Lab is lab/ as the judge reads it.
type Lab struct {
	pairs   map[string]pairEntry
	rules   map[string][]RuleFile
	Windows []Window
}

// Load reads lab/ under dir: every pair, its rules, every window, and checks each window.
func Load(dir string) (*Lab, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	lab := &Lab{pairs: map[string]pairEntry{}, rules: map[string][]RuleFile{}}
	pairFiles, err := list(root, "pairs", false)
	if err != nil {
		return nil, err
	}
	for _, name := range pairFiles {
		pair, ok := strings.CutSuffix(name, ".json")
		if !ok {
			return nil, fmt.Errorf("lab: pairs/%s is not a pair's file", name)
		}
		if err := lab.loadPair(root, pair); err != nil {
			return nil, err
		}
	}
	ruleDirs, err := list(root, "rules", true)
	if err != nil {
		return nil, err
	}
	for _, d := range ruleDirs {
		if _, ok := lab.pairs[d]; !ok {
			return nil, fmt.Errorf("lab: rules/%s has no pair", d)
		}
	}
	dirs, err := list(root, "windows", true)
	if err != nil {
		return nil, err
	}
	files := map[string]map[string][]byte{}
	programs := map[string]int{}
	for _, d := range dirs {
		if files[d], err = readDir(root, path.Join("windows", d)); err != nil {
			return nil, err
		}
		if r, err := decodeResult(files[d][ResultFile]); err == nil && r.HasProgramFields {
			programs[r.ProgramSHA]++
		}
	}
	for _, d := range dirs {
		lab.Windows = append(lab.Windows, checkWindow(windowInput{dir: d, files: files[d], pairs: lab.pairs, programs: programs}))
	}
	return lab, nil
}

func (lab *Lab) loadPair(root *os.Root, pair string) error {
	pairPath := "pairs/" + pair + ".json"
	data, err := wholefile.ReadIn(root, pairPath, pairCap)
	if err != nil {
		return fmt.Errorf("lab: %s: %w", pairPath, err)
	}
	content := map[string][]byte{pairPath: data}
	entry := pairEntry{}
	entry.pair, entry.pairErr = decodePair(pair, data)
	ruleFiles, err := list(root, "rules/"+pair, false)
	if err != nil {
		return err
	}
	for _, name := range ruleFiles {
		rulePath := "rules/" + pair + "/" + name
		data, err := wholefile.ReadIn(root, rulePath, ruleCap)
		if err != nil {
			return fmt.Errorf("lab: %s: %w", rulePath, err)
		}
		content[rulePath] = data
		if !strings.HasSuffix(name, ".json") {
			entry.ruleErr = errors.Join(entry.ruleErr, fmt.Errorf("%s is not a rule's file", rulePath))
			continue
		}
		rf, err := decodeRuleFile(rulePath, data)
		if err != nil {
			entry.ruleErr = errors.Join(entry.ruleErr, fmt.Errorf("%s: %w", rulePath, err))
			continue
		}
		lab.rules[pair] = append(lab.rules[pair], rf)
	}
	entry.hash = contentHash(content)
	lab.pairs[pair] = entry
	return nil
}

// list returns the names in dir under root, sorted, each a directory (dirs) or a regular file; a missing dir
// is empty. Anything else (a link, a FIFO) fails the read.
func list(root *os.Root, dir string, dirs bool) ([]string, error) {
	f, err := root.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lab: %s: %w", dir, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("lab: %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if (dirs && !e.IsDir()) || (!dirs && !e.Type().IsRegular()) {
			return nil, fmt.Errorf("lab: %s/%s is not a %s", dir, e.Name(), map[bool]string{true: "directory", false: "regular file"}[dirs])
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names, nil
}

// readDir reads every regular file of dir under root, result.json under its cap, others under textCap.
func readDir(root *os.Root, dir string) (map[string][]byte, error) {
	names, err := list(root, dir, false)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, n := range names {
		limit := int64(textCap)
		if n == ResultFile {
			limit = resultCap
		} else if !textName.MatchString(n) {
			return nil, fmt.Errorf("%s/%s is not a runner's file name", dir, n)
		}
		if files[n], err = wholefile.ReadIn(root, path.Join(dir, n), limit); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", dir, n, err)
		}
	}
	return files, nil
}

// Verify compares lab/ with the runner's results (ADR 0077 point 6, 0078, 0079 point 2): the anchor must be
// kept, and the results after it must be lab/windows exactly, every file and its bytes. It returns the findings.
func Verify(labDir, resultsDir string) ([]string, error) {
	results, err := os.OpenRoot(resultsDir)
	if err != nil {
		return nil, fmt.Errorf("results: %w", err)
	}
	defer results.Close() //nolint:errcheck // read-only
	lab, err := os.OpenRoot(labDir)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	defer lab.Close() //nolint:errcheck // read-only
	ids, err := list(results, ".", true)
	if err != nil {
		return nil, err
	}
	var findings []string
	want := map[string]bool{}
	anchor := false
	for _, id := range ids {
		switch {
		case !resultID.MatchString(id):
			findings = append(findings, fmt.Sprintf("%s is not a result's name", id))
		case id == Anchor:
			anchor = true
		case id > Anchor:
			want[strings.ToLower(id)] = true
			findings = append(findings, compareWindow(results, lab, id)...)
		}
	}
	if !anchor {
		findings = append(findings, "the anchor "+Anchor+" is no longer kept")
	}
	have, err := list(lab, "windows", true)
	if err != nil {
		return nil, err
	}
	for _, d := range have {
		if !want[d] {
			findings = append(findings, fmt.Sprintf("windows/%s matches no runner result after the anchor", d))
		}
	}
	return findings, nil
}

func compareWindow(results, lab *os.Root, id string) []string {
	orig, err := readDir(results, id)
	if err != nil {
		return []string{fmt.Sprintf("result %s: %v", id, err)}
	}
	dir := path.Join("windows", strings.ToLower(id))
	copied, err := readDir(lab, dir)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", dir, err)}
	}
	var findings []string
	for name, data := range orig {
		if c, ok := copied[name]; !ok || !bytes.Equal(c, data) {
			findings = append(findings, fmt.Sprintf("%s/%s is not the runner's %s/%s", dir, name, id, name))
		}
	}
	for name := range copied {
		if _, ok := orig[name]; !ok {
			findings = append(findings, fmt.Sprintf("%s/%s is not in the runner's result", dir, name))
		}
	}
	slices.Sort(findings)
	return findings
}

// Import copies the runner's result id into lab/windows/<id in lower case>/, every file as it is, and returns
// the bytes lab/ then holds (ADR 0079 point 8).
func Import(labDir, resultsDir, id string) (int64, error) {
	if !resultID.MatchString(id) || id <= Anchor {
		return 0, fmt.Errorf("import: %s is not a result after the anchor", id)
	}
	results, err := os.OpenRoot(resultsDir)
	if err != nil {
		return 0, fmt.Errorf("results: %w", err)
	}
	defer results.Close() //nolint:errcheck // read-only
	files, err := readDir(results, id)
	if err != nil {
		return 0, err
	}
	lab, err := os.OpenRoot(labDir)
	if err != nil {
		return 0, fmt.Errorf("lab: %w", err)
	}
	defer lab.Close() //nolint:errcheck // nothing written through the handle itself
	dir := path.Join("windows", strings.ToLower(id))
	if err := lab.MkdirAll("windows", 0o755); err != nil {
		return 0, fmt.Errorf("import: %w", err)
	}
	if err := lab.Mkdir(dir, 0o755); err != nil {
		return 0, fmt.Errorf("import: %s: %w", dir, err)
	}
	for name, data := range files {
		if err := wholefile.WriteIn(lab, path.Join(dir, name), data, 0o644); err != nil {
			return 0, fmt.Errorf("import: %w", err)
		}
	}
	return size(lab, ".")
}

func size(root *os.Root, dir string) (int64, error) {
	var total int64
	err := fs.WalkDir(root.FS(), dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// Job writes the job directory of a pair's run under target: `<job name>/job.json` and the program. It refuses
// a pair or rule that does not decode, so a broken one never spends a job of the runner's quota.
func Job(labDir, pair, run, target string) (string, error) {
	lab, err := Load(labDir)
	if err != nil {
		return "", err
	}
	entry, ok := lab.pairs[pair]
	switch {
	case !ok:
		return "", fmt.Errorf("job: no pair %q", pair)
	case entry.pairErr != nil:
		return "", fmt.Errorf("job: pair: %w", entry.pairErr)
	case entry.ruleErr != nil:
		return "", fmt.Errorf("job: rules: %w", entry.ruleErr)
	case !slices.Contains(RunNames, run):
		return "", fmt.Errorf("job: run %q is not one of %v", run, RunNames)
	}
	r := entry.pair.Runs[run]
	name := jobName(pair, run, entry.hash)
	root, err := os.OpenRoot(target)
	if err != nil {
		return "", fmt.Errorf("job: %w", err)
	}
	defer root.Close() //nolint:errcheck // nothing written through the handle itself
	if err := root.Mkdir(name, 0o750); err != nil {
		return "", fmt.Errorf("job: %w", err)
	}
	if err := wholefile.WriteIn(root, name+"/job.json", execRequest(r.Program, r.TimeoutS), 0o640); err != nil {
		return "", fmt.Errorf("job: %w", err)
	}
	if err := wholefile.WriteIn(root, name+"/"+r.Program, r.Text, 0o640); err != nil {
		return "", fmt.Errorf("job: %w", err)
	}
	sum := sha256.Sum256(r.Text)
	return name + " " + contentKey(execRequest(r.Program, r.TimeoutS), r.Text) + " " + hex.EncodeToString(sum[:]), nil
}
