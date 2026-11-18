package detect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// Reason is why a window is INVALID, from a closed list (ADR 0077 point 5); each has a fixture breaking only it.
type Reason string

// The closed list, in the order a window is checked.
const (
	ReasonResultDecode    Reason = "result.json does not decode as a runner result"
	ReasonSchema          Reason = "result schema is not 1"
	ReasonLabel           Reason = "result is not an agent job's"
	ReasonKind            Reason = "job is not an exec job"
	ReasonRuns            Reason = "result does not hold exactly one run"
	ReasonNotRan          Reason = "result or its run is not RAN"
	ReasonJobFailed       Reason = "the program did not succeed with exit 0"
	ReasonImage           Reason = "runner or image is not a known one"
	ReasonDirectory       Reason = "directory is not the result id in lower case"
	ReasonBeforeAnchor    Reason = "result is not after the anchor"
	ReasonPair            Reason = "the job's pair does not decode"
	ReasonRule            Reason = "one of the pair's rules does not decode"
	ReasonName            Reason = "job name does not bind the pair's and rules' content"
	ReasonContentKey      Reason = "content key is not the run's request and program"
	ReasonProgram         Reason = "program sha256 is not the run's"
	ReasonProgramRepeated Reason = "another window in lab/ holds the same program"
	ReasonLaurelFile      Reason = "job-laurel.txt is missing or not a plain file"
	ReasonLaurelEscape    Reason = "job-laurel.txt does not escape back to itself"
	ReasonLaurelCap       Reason = "records are over 6 MiB"
	ReasonLaurelBytes     Reason = "records are not laurel_bytes long"
	ReasonLaurelLine      Reason = "a record line is not one JSON object"
	ReasonDuplicateKey    Reason = "a record repeats a key with another value"
	ReasonNoProgramExec   Reason = "no successful exec of the program under the job's user and uid"
	ReasonJobUID          Reason = "the job's user and its uid disagree"
	ReasonNoCanary        Reason = "no successful canary exec under root after the program"
)

// Reasons is the closed list; a test checks each has exactly one fixture.
var Reasons = []Reason{
	ReasonResultDecode, ReasonSchema, ReasonLabel, ReasonKind, ReasonRuns, ReasonNotRan, ReasonJobFailed,
	ReasonImage, ReasonDirectory, ReasonBeforeAnchor, ReasonPair, ReasonRule, ReasonName, ReasonContentKey,
	ReasonProgram, ReasonProgramRepeated, ReasonLaurelFile, ReasonLaurelEscape, ReasonLaurelCap,
	ReasonLaurelBytes, ReasonLaurelLine, ReasonDuplicateKey, ReasonNoProgramExec, ReasonJobUID, ReasonNoCanary,
}

// Window is one directory of lab/windows as the judge reads it.
type Window struct {
	Dir             string
	Pair, Run, Hash string // set once the job name parses
	Reason          Reason // empty when valid
	events          []object
}

// Valid reports whether the window passed every check.
func (w Window) Valid() bool { return w.Reason == "" }

// windowInput is what checkWindow needs from lab/.
type windowInput struct {
	dir      string
	files    map[string][]byte // the window's files it could read, by name
	pairs    map[string]pairEntry
	programs map[string]int // windows in lab/ per program sha256
}

type pairEntry struct {
	pair    Pair
	pairErr error
	ruleErr error
	hash    string
}

// checkWindow runs the checks of ADR 0077 point 3, 0078 and 0079 in a fixed order and stops at the first.
func checkWindow(in windowInput) Window {
	w := Window{Dir: in.dir}
	data, present := in.files[ResultFile]
	r, err := decodeResult(data)
	if !present || err != nil {
		w.Reason = ReasonResultDecode
		return w
	}
	if pair, run, hash, ok := splitJobName(r.Name); ok {
		w.Pair, w.Run, w.Hash = pair, run, hash
	}
	w.Reason, w.events = check(in, r) // events only when valid
	return w
}

func check(in windowInput, r result) (Reason, []object) {
	img, known := images[r.ImageCommit]
	switch {
	case r.Schema != 1:
		return ReasonSchema, nil
	case r.Label != "agent":
		return ReasonLabel, nil
	case r.Kind != "exec" || !r.HasExec: // no job: no kind
		return ReasonKind, nil
	case r.Runs != 1:
		return ReasonRuns, nil
	case r.Verdict != "RAN" || r.RunVerdict != "RAN":
		return ReasonNotRan, nil
	case r.JobResult != "success" || !r.HasExit || r.JobExit != 0:
		return ReasonJobFailed, nil
	case !known || img.sha256 != r.ImageSHA || !runners[r.RunnerCommit]:
		return ReasonImage, nil
	case !resultID.MatchString(r.ID) || in.dir != strings.ToLower(r.ID):
		return ReasonDirectory, nil
	case r.ID <= Anchor:
		return ReasonBeforeAnchor, nil
	}
	pairName, runName, hash, _ := splitJobName(r.Name) // a name that does not parse gives "", which names no pair
	entry, isPair := in.pairs[pairName]
	switch {
	case !isPair:
		return ReasonName, nil
	case entry.pairErr != nil:
		return ReasonPair, nil
	case entry.ruleErr != nil:
		return ReasonRule, nil
	case hash != entry.hash:
		return ReasonName, nil
	}
	run := entry.pair.Runs[runName]
	sum := sha256.Sum256(run.Text)
	switch {
	case r.Program != run.Program || r.TimeoutS != run.TimeoutS ||
		r.ContentKey != contentKey(execRequest(run.Program, run.TimeoutS), run.Text):
		return ReasonContentKey, nil
	case r.ProgramSHA != hex.EncodeToString(sum[:]):
		return ReasonProgram, nil
	case in.programs[r.ProgramSHA] != 1:
		return ReasonProgramRepeated, nil
	}
	return checkRecords(in, r, img.jobUID)
}

func checkRecords(in windowInput, r result, jobUID string) (Reason, []object) {
	// A records file over its read cap passes lab/'s too, which fails the whole read; any other read error and
	// a missing file are the same reason.
	file, present := in.files[LaurelFile]
	if !present {
		return ReasonLaurelFile, nil
	}
	raw, ok := unescape(file)
	switch {
	case !ok:
		return ReasonLaurelEscape, nil
	case len(raw) > LaurelCap:
		return ReasonLaurelCap, nil
	case int64(len(raw)) != r.LaurelBytes:
		return ReasonLaurelBytes, nil
	case len(raw) == 0 || raw[len(raw)-1] != '\n':
		return ReasonLaurelLine, nil
	}
	var events []object
	for _, line := range bytes.Split(raw[:len(raw)-1], []byte("\n")) {
		v, err := decode(line, true)
		if errors.Is(err, errRepeated) {
			return ReasonDuplicateKey, nil
		}
		ev, isObject := v.(object) // a line that does not decode is nil
		if !isObject {
			return ReasonLaurelLine, nil
		}
		events = append(events, ev)
	}
	return checkExecs(events, jobUID)
}

// checkExecs finds the program's successful exec under the job's user and the image's uid for it, checks the
// user's name and uid agree on every event (ADR 0079 point 5), and a successful canary exec under root after
// the program; it returns the job's events.
func checkExecs(events []object, jobUID string) (Reason, []object) {
	var job []object
	program, canaryAfter, uidsAgree := false, false, true
	for _, ev := range events {
		name, number := user(ev), numericUID(ev)
		uidsAgree = uidsAgree && (name == JobUser) == (number == jobUID)
		if name == JobUser {
			job = append(job, ev)
		}
		if name == JobUser && number == jobUID && execOK(ev) && argvIs(ev, "/bin/sh", JobProgram) {
			program = true
		}
		if program && name == "root" && number == "0" && execOK(ev) && canary(ev) {
			canaryAfter = true
		}
	}
	switch {
	case !program:
		return ReasonNoProgramExec, nil
	case !uidsAgree:
		return ReasonJobUID, nil
	case !canaryAfter:
		return ReasonNoCanary, nil
	}
	return "", job
}

func syscallOf(ev object) object {
	sc, _ := ev["SYSCALL"].(object)
	return sc
}

// execOK reports whether ev's syscall is an execve that succeeded with exit 0, as Laurel writes it on x86_64.
func execOK(ev object) bool {
	sc := syscallOf(ev)
	nr, _ := integer(sc, "syscall")
	exit, hasExit := integer(sc, "exit")
	name, _ := str(sc, "SYSCALL")
	success, _ := str(sc, "success")
	return nr == 59 && name == "execve" && success == "yes" && hasExit && exit == 0
}

// user is SYSCALL.UID, Laurel's name for the uid, or "".
func user(ev object) string {
	s, _ := str(syscallOf(ev), "UID")
	return s
}

// numericUID is SYSCALL.uid as its decimal literal, or "".
func numericUID(ev object) string {
	n, ok := integer(syscallOf(ev), "uid")
	if !ok {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

func argv(ev object) []any {
	ex, _ := ev["EXECVE"].(object)
	list, _ := ex["ARGV"].([]any)
	return list
}

func argvIs(ev object, want ...string) bool {
	got := argv(ev)
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if s, ok := got[i].(string); !ok || s != want[i] {
			return false
		}
	}
	return true
}

// canary reports whether ev execs the guest's canary: /usr/bin/true, as its executable too, with its argument.
func canary(ev object) bool {
	got := argv(ev)
	if len(got) != 2 {
		return false
	}
	arg, _ := got[1].(string)
	exe, _ := str(syscallOf(ev), "exe")
	return exe == "/usr/bin/true" && argvIs(ev, "/usr/bin/true", arg) && canaryArg.MatchString(arg)
}
