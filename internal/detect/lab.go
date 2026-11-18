package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// Per-file read caps (R5): a result is small; a pair holds four programs; any other window file is the runner's
// escape, bounded by lab/ itself.
const (
	resultCap = 64 << 10
	pairCap   = 5 << 20
	ruleCap   = 64 << 10
	textCap   = LabCap
)

// Lab is lab/ as the judge reads it.
type Lab struct {
	pairs   map[string]pairEntry
	rules   map[string][]RuleFile
	Windows []Window
}

// Load reads lab/ under dir: every pair, its rules, every window, and checks each window. A link, a FIFO, a
// name outside the layout or lab/ over LabCap fails the whole read; a file over its own cap makes its window,
// pair or rule INVALID with its closed reason.
func Load(dir string) (*Lab, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	b := &budget{left: LabCap}
	lab := &Lab{pairs: map[string]pairEntry{}, rules: map[string][]RuleFile{}}
	pairs, err := optionalDir(root, "pairs")
	if err != nil {
		return nil, err
	}
	rules, err := optionalDir(root, "rules")
	if err != nil {
		return nil, err
	}
	if err := lab.loadPairs(pairs, rules, b, ""); err != nil {
		return nil, err
	}
	windows, err := optionalDir(root, "windows")
	if err != nil {
		return nil, err
	}
	if windows == nil {
		return lab, nil
	}
	defer windows.Close() //nolint:errcheck // read-only
	dirs, err := entries(windows, true)
	if err != nil {
		return nil, fmt.Errorf("lab: windows: %w", err)
	}
	inputs := make([]windowInput, 0, len(dirs))
	programs := map[string]int{}
	for _, d := range dirs {
		in, err := readWindow(windows, d, b)
		if err != nil {
			return nil, err
		}
		if r, _ := decodeResult(in.files[ResultFile]); r.HasExec { // one that does not decode is the zero result
			programs[r.ProgramSHA]++
		}
		inputs = append(inputs, in)
	}
	for _, in := range inputs {
		in.pairs, in.programs = lab.pairs, programs
		lab.Windows = append(lab.Windows, checkWindow(in))
	}
	return lab, nil
}

// optionalDir opens one of lab/'s collections; a missing one is empty.
func optionalDir(root *os.Root, name string) (*os.Root, error) {
	d, err := openDir(root, name)
	if errors.Is(err, errMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	return d, nil
}

// readWindow reads every file of a window; a file over its own cap is left out, which its closed reason names as
// missing (ADR 0079 point 9), and any other that does not read fails the whole read.
func readWindow(windows *os.Root, d string, b *budget) (windowInput, error) {
	in := windowInput{dir: d, files: map[string][]byte{}}
	w, err := openDir(windows, d)
	if err != nil {
		return windowInput{}, fmt.Errorf("lab: windows/%w", err)
	}
	defer w.Close() //nolint:errcheck // read-only
	names, err := entries(w, false)
	if err != nil {
		return windowInput{}, fmt.Errorf("lab: windows/%s: %w", d, err)
	}
	for _, n := range names {
		if !textName.MatchString(n) { // result.json is one too
			return windowInput{}, fmt.Errorf("lab: windows/%s/%s is not a runner's file name", d, n)
		}
		limit := int64(textCap)
		if n == ResultFile {
			limit = resultCap
		}
		data, err := b.read(w, n, limit)
		switch {
		case err == nil:
			in.files[n] = data
		case errors.Is(err, errOverBudget):
			return windowInput{}, fmt.Errorf("lab: over %d bytes", LabCap)
		case !errors.Is(err, errOverCap): // a file over its own cap is left out: its window's reason names it missing
			return windowInput{}, fmt.Errorf("lab: windows/%s: %w", d, err) // a link or a file that changed
		}
	}
	return in, nil
}

// loadPairs reads every pair (or only the one named) and its rules. A rules directory without its pair fails.
func (lab *Lab) loadPairs(pairs, rules *os.Root, b *budget, only string) error {
	var names []string
	if pairs != nil {
		files, err := entries(pairs, false)
		if err != nil {
			return fmt.Errorf("lab: pairs: %w", err)
		}
		for _, f := range files {
			name, ok := strings.CutSuffix(f, ".json")
			if !ok {
				return fmt.Errorf("lab: pairs/%s is not a pair's file", f)
			}
			names = append(names, name)
		}
	}
	if rules != nil {
		dirs, err := entries(rules, true)
		if err != nil {
			return fmt.Errorf("lab: rules: %w", err)
		}
		for _, d := range dirs {
			if only == "" && !slices.Contains(names, d) {
				return fmt.Errorf("lab: rules/%s has no pair", d)
			}
		}
	}
	for _, name := range names {
		if only != "" && name != only {
			continue
		}
		if err := lab.loadPair(pairs, rules, b, name); err != nil {
			return err
		}
	}
	return nil
}

func (lab *Lab) loadPair(pairs, rules *os.Root, b *budget, pair string) error {
	pairPath := "pairs/" + pair + ".json"
	content := map[string][]byte{}
	entry := pairEntry{}
	data, err := b.read(pairs, pair+".json", pairCap)
	switch {
	case errors.Is(err, errOverBudget):
		return fmt.Errorf("lab: over %d bytes", LabCap)
	case err != nil:
		entry.pairErr = err
	default:
		content[pairPath] = data
		entry.pair, entry.pairErr = decodePair(pair, data)
	}
	if rules != nil {
		if err := lab.loadRules(rules, b, pair, &entry, content); err != nil {
			return err
		}
	}
	entry.hash = contentHash(content)
	lab.pairs[pair] = entry
	return nil
}

func (lab *Lab) loadRules(rules *os.Root, b *budget, pair string, entry *pairEntry, content map[string][]byte) error {
	dir, err := openDir(rules, pair)
	if errors.Is(err, errMissing) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lab: rules/%w", err)
	}
	defer dir.Close() //nolint:errcheck // read-only
	names, err := entries(dir, false)
	if err != nil {
		return fmt.Errorf("lab: rules/%s: %w", pair, err)
	}
	brief := sha256.Sum256([]byte(entry.pair.Brief))
	for _, name := range names {
		rulePath := "rules/" + pair + "/" + name
		data, err := b.read(dir, name, ruleCap)
		if errors.Is(err, errOverBudget) {
			return fmt.Errorf("lab: over %d bytes", LabCap)
		}
		if err != nil {
			entry.ruleErr = errors.Join(entry.ruleErr, fmt.Errorf("%s: %w", rulePath, err))
			continue
		}
		content[rulePath] = data
		rf, err := decodeRuleFile(rulePath, data)
		switch {
		case !strings.HasSuffix(name, ".json"):
			err = errors.New("not a rule's file")
		case err == nil && entry.pairErr == nil && rf.BriefSHA256 != hex.EncodeToString(brief[:]):
			err = errors.New("brief_sha256 is not the pair's brief")
		}
		if err != nil {
			entry.ruleErr = errors.Join(entry.ruleErr, fmt.Errorf("%s: %w", rulePath, err))
			continue
		}
		lab.rules[pair] = append(lab.rules[pair], rf)
	}
	return nil
}

// RunnerOwned checks the runner's side before verify or import reads it (R13): a directory, not a link, that
// the caller does not own and that neither its group nor others can write, so what they read is the runner's,
// not a copy an agent made. main calls it on ResultsDir.
func RunnerOwned(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("results: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("results: %s is not a directory", path)
	case !ok || int(st.Uid) == os.Getuid():
		return fmt.Errorf("results: %s is the caller's, not the runner's", path)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("results: %s is writable by its group or others", path)
	}
	return nil
}

// Verify compares lab/ with the runner's results (ADR 0077 point 6, 0078, 0079 point 2): the anchor must be
// kept, and the results after it must be lab/windows exactly, both ways, every file and its bytes; the runner's
// list must be the same before and after. It returns the findings and a sha256 over what it compared.
func Verify(labDir, resultsDir string) ([]string, string, error) {
	results, err := os.OpenRoot(resultsDir)
	if err != nil {
		return nil, "", fmt.Errorf("results: %w", err)
	}
	defer results.Close() //nolint:errcheck // read-only
	lab, err := os.OpenRoot(labDir)
	if err != nil {
		return nil, "", fmt.Errorf("lab: %w", err)
	}
	defer lab.Close() //nolint:errcheck // read-only
	ids, err := entries(results, true)
	if err != nil {
		return nil, "", fmt.Errorf("results: %w", err)
	}
	windows, err := optionalDir(lab, "windows")
	if err != nil {
		return nil, "", err
	}
	var have []string
	if windows != nil {
		defer windows.Close() //nolint:errcheck // read-only
		if have, err = entries(windows, true); err != nil {
			return nil, "", fmt.Errorf("lab: windows: %w", err)
		}
	}
	var findings []string
	want := map[string]bool{}
	anchor := false
	digest := sha256.New()
	// results after the anchor must all be in lab/, so more than lab/ can hold is a finding, not more reading
	rb, lb := &budget{left: LabCap}, &budget{left: LabCap}
	for _, id := range ids {
		switch {
		case !resultID.MatchString(id):
			findings = append(findings, id+" is not a result's name")
		case id < Anchor: // not the pilot's (ADR 0078 point 1)
		case id == Anchor:
			anchor = true
		default:
			want[strings.ToLower(id)] = true
			findings = append(findings, compareWindow(results, windows, id, rb, lb, digest)...)
		}
	}
	if !anchor {
		findings = append(findings, "the anchor "+Anchor+" is no longer kept")
	}
	for _, d := range have {
		if !want[d] {
			findings = append(findings, "windows/"+d+" matches no runner result after the anchor")
		}
	}
	if again, err := relist(results); err != nil || !slices.Equal(ids, again) {
		findings = append(findings, "the runner's results changed while verify read them")
	}
	if windows != nil {
		if again, err := relist(windows); err != nil || !slices.Equal(have, again) {
			findings = append(findings, "lab/windows changed while verify read it")
		}
	}
	return findings, hex.EncodeToString(digest.Sum(nil)), nil
}

// placeholderReason is the reason of the result the runner writes before a run and replaces after it
// (rangerun begin and finish at 2c09799).
const placeholderReason = "the runner stopped before the run ended"

// unfinished reports whether a result is still the runner's placeholder: its one run INVALID with that reason.
func unfinished(files map[string][]byte) bool {
	v, err := decode(files[ResultFile], false)
	top, _ := v.(object)
	runs, _ := top["runs"].([]any)
	if err != nil || len(runs) != 1 {
		return false
	}
	run, _ := runs[0].(object)
	verdict, _ := str(run, "verdict")
	reason, _ := str(run, "reason")
	return verdict == "INVALID" && reason == placeholderReason
}

// relist lists a directory of windows again after verify compared it; a test replaces it to stand for a writer
// racing verify, which no test can time.
var relist = func(dir *os.Root) ([]string, error) { return entries(dir, true) }

// relistFiles lists a result's files again after they were read; a test replaces it the same way.
var relistFiles = func(dir *os.Root) ([]string, error) { return entries(dir, false) }

func compareWindow(results, windows *os.Root, id string, rb, lb *budget, digest interface{ Write([]byte) (int, error) }) []string {
	orig, err := readAll(results, id, rb)
	if err != nil {
		return []string{fmt.Sprintf("result %s: %v", id, err)}
	}
	if unfinished(orig) {
		return []string{"result " + id + " is the runner's placeholder: its job runs still, or the runner stopped in it; " +
			"verify when the runner is idle"}
	}
	dir := strings.ToLower(id)
	_, _ = digest.Write(fmt.Appendf(nil, "window %d:%s\n", len(dir), dir)) // the compared set, empty windows too
	if windows == nil {
		return []string{"windows/" + dir + " is missing"}
	}
	copied, err := readAll(windows, dir, lb)
	if errors.Is(err, errMissing) {
		return []string{"windows/" + dir + " is missing"}
	}
	if err != nil {
		return []string{fmt.Sprintf("windows/%s: %v", dir, err)}
	}
	var findings []string
	for _, name := range sortedKeys(orig) {
		c, ok := copied[name]
		if !ok || !bytes.Equal(c, orig[name]) {
			findings = append(findings, fmt.Sprintf("windows/%s/%s is not the runner's %s/%s", dir, name, id, name))
		}
		for _, part := range [][]byte{[]byte(dir + "/" + name), orig[name]} {
			_, _ = digest.Write(fmt.Appendf(nil, "%d:", len(part))) // a hash never fails to write
			_, _ = digest.Write(part)
		}
	}
	for _, name := range sortedKeys(copied) {
		if _, ok := orig[name]; !ok {
			findings = append(findings, fmt.Sprintf("windows/%s/%s is not in the runner's result", dir, name))
		}
	}
	return findings
}

// readAll reads every file of the directory name under dir; a missing directory is errMissing.
func readAll(dir *os.Root, name string, b *budget) (map[string][]byte, error) {
	d, err := openDir(dir, name)
	if err != nil {
		return nil, err
	}
	defer d.Close() //nolint:errcheck // read-only
	names, err := entries(d, false)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, n := range names {
		if !textName.MatchString(n) { // result.json is one too
			return nil, fmt.Errorf("%s is not a runner's file name", n)
		}
		if files[n], err = b.read(d, n, textCap); err != nil {
			return nil, err
		}
	}
	// the runner writes a result's files, then its result.json, in the result's own directory (rangerun finish):
	// a list that changed while they were read is not one result
	again, err := relistFiles(d)
	if err != nil {
		return nil, fmt.Errorf("%s: list again: %w", name, err)
	}
	if !slices.Equal(names, again) {
		return nil, fmt.Errorf("%s changed while it was read", name)
	}
	return files, nil
}

// Import copies the runner's result id into lab/windows/<id in lower case>/, every file as it is, all of them
// or none, and returns the bytes lab/ then holds; it refuses before writing when lab/ would pass LabCap.
func Import(labDir, resultsDir, id string) (int64, error) {
	if !resultID.MatchString(id) || id <= Anchor {
		return 0, fmt.Errorf("%s is not a result after the anchor", id)
	}
	results, err := os.OpenRoot(resultsDir)
	if err != nil {
		return 0, fmt.Errorf("results: %w", err)
	}
	defer results.Close() //nolint:errcheck // read-only
	files, err := readAll(results, id, &budget{left: LabCap})
	if errors.Is(err, errMissing) {
		return 0, fmt.Errorf("no result %s", id)
	}
	if err != nil {
		return 0, fmt.Errorf("result %s: %w", id, err)
	}
	lab, err := os.OpenRoot(labDir)
	if err != nil {
		return 0, fmt.Errorf("lab: %w", err)
	}
	defer lab.Close() //nolint:errcheck // nothing written through the handle itself
	size, err := labSize(lab)
	if err != nil {
		return 0, err
	}
	for _, d := range files {
		size += int64(len(d))
	}
	if size > LabCap {
		return 0, fmt.Errorf("lab/ would hold %d bytes, over %d", size, LabCap)
	}
	if err := lab.Mkdir("windows", 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return 0, fmt.Errorf("windows: %w", err)
	}
	if err := syncDir(lab); err != nil { // windows/ itself must survive a crash, also when an earlier import made it
		return 0, err
	}
	windows, err := openDir(lab, "windows")
	if err != nil {
		return 0, err
	}
	defer windows.Close() //nolint:errcheck // every write is synced by WriteIn
	if err := publish(windows, strings.ToLower(id), files, 0o755, 0o644); err != nil {
		return 0, err
	}
	return size, nil
}

// labSize is the bytes of every regular file under lab/: pairs, rules/<pair>, windows/<id>, results (R5).
func labSize(lab *os.Root) (int64, error) { return treeBytes(lab, 2) }

// Job writes the job directory of a pair's run under target, `<job name>/job.json` and the program, all or
// nothing. It reads only that pair and its rules, refuses one that does not decode, so a broken one never spends
// a job of the runner's quota, and refuses the runner's inbox: a job is built outside it and renamed in.
func Job(labDir, pair, run, target string) (string, error) {
	return jobIn(labDir, pair, run, target, InboxDir)
}

func jobIn(labDir, pair, run, target, inboxDir string) (string, error) {
	root, err := os.OpenRoot(labDir)
	if err != nil {
		return "", fmt.Errorf("lab: %w", err)
	}
	defer root.Close() //nolint:errcheck // read-only
	pairs, err := optionalDir(root, "pairs")
	if err != nil {
		return "", err
	}
	rules, err := optionalDir(root, "rules")
	if err != nil {
		return "", err
	}
	lab := &Lab{pairs: map[string]pairEntry{}, rules: map[string][]RuleFile{}}
	if err := lab.loadPairs(pairs, rules, &budget{left: LabCap}, pair); err != nil {
		return "", err
	}
	entry, ok := lab.pairs[pair]
	switch {
	case !ok:
		return "", fmt.Errorf("no pair %q", pair)
	case entry.pairErr != nil:
		return "", fmt.Errorf("pair: %w", entry.pairErr)
	case entry.ruleErr != nil:
		return "", fmt.Errorf("rules: %w", entry.ruleErr)
	case !slices.Contains(RunNames, run):
		return "", fmt.Errorf("run %q is not one of %v", run, RunNames)
	}
	r := entry.pair.Runs[run]
	name := jobName(pair, run, entry.hash)
	out, err := os.OpenRoot(target)
	if err != nil {
		return "", fmt.Errorf("target: %w", err)
	}
	defer out.Close() //nolint:errcheck // every write is synced by WriteIn
	opened, err := statOpened(out)
	if err != nil {
		return "", fmt.Errorf("target: %w", err)
	}
	inbox, err := os.Stat(inboxDir) // nil without an inbox on this machine: nothing to refuse
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("inbox: %w", err)
	}
	if err := outsideInbox(target, opened, inbox); err != nil {
		return "", err
	}
	request := execRequest(r.Program, r.TimeoutS)
	// Readable by others: a rename into the inbox keeps the caller's group, the runner reads as its own, and the
	// inbox (2750) lets no other user reach the job.
	if err := publish(out, name, map[string][]byte{"job.json": request, r.Program: r.Text}, 0o755, 0o644); err != nil {
		return "", err
	}
	sum := sha256.Sum256(r.Text)
	return name + " " + contentKey(request, r.Text) + " " + hex.EncodeToString(sum[:]), nil
}

// outsideInbox refuses a target in the runner's inbox, at any depth: the opened directory must be the one the path
// names, and neither it nor any directory above it, its links resolved, the inbox.
func outsideInbox(target string, opened, inbox os.FileInfo) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs) // a link to a directory in the inbox is in the inbox
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if named, err := os.Stat(resolved); err != nil || !os.SameFile(named, opened) {
		return errors.New("target changed while it was opened")
	}
	// inbox is nil when this machine has none, which os.SameFile matches to nothing
	for dir := resolved; ; dir = filepath.Dir(dir) {
		if d, err := os.Stat(dir); err == nil && os.SameFile(inbox, d) {
			return errors.New("target is in the runner's inbox; build outside it and rename the job in")
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}
