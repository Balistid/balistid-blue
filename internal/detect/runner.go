package detect

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The runner's contract at 2c09799, re-implemented (ADR 0079 point 1) and pinned by tests to real bytes.
const (
	// Anchor is the runner's result the pilot counts from (ADR 0078 point 1).
	Anchor = "20261117T222824Z-cf92a4e6-pr13-run-d4"
	// ResultsDir holds the runner's agent results on the host; verify and import read it, nothing names another.
	ResultsDir = "/var/lib/balistid/results/agent"
	// InboxDir is the runner's inbox; job never writes into it (a half-written job spends quota).
	InboxDir = "/var/lib/balistid/inbox"
	// LaurelCap bounds a window's decoded records (ADR 0077 point 3).
	LaurelCap = 6 << 20
	// LabCap bounds lab/ as a whole (ADR 0079 point 8).
	LabCap = 16 << 20
	// JobUser is the user the runner's guest runs a job's program as.
	JobUser = "balistid-job"
	// JobProgram is the path the guest runs a job's program from.
	JobProgram = "/run/balistid-job/program"
	// LaurelFile and ResultFile are the window files the judge reads.
	LaurelFile = "job-laurel.txt"
	ResultFile = "result.json"
	// Version names the rules a table or a verify was made under (ENGINEERING.md, evidence).
	Version = "ADR 0077-0079"
)

// image is a known range image: its sha256 and the uid its image gives the job's user.
type image struct{ sha256, jobUID string }

// images are the known images by commit, and runners the known runner commits (ADR 0079 point 6): a result is
// judged only under the runner semantics re-implemented here.
var (
	images = map[string]image{
		"2c09799a44e766ea3b3f0597bd8c9ab32db9d31e": {"693e28f3e561f5959dd1bcda486fe8ed1bbc11a6c3b120263b9634e262e933a7", "970"},
	}
	runners = map[string]bool{"2c09799a44e766ea3b3f0597bd8c9ab32db9d31e": true}
)

var (
	resultID    = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}(-[a-z0-9][a-z0-9-]{0,63})?$`)
	textName    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	programName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	jobNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	canaryArg   = regexp.MustCompile(`^balistid-canary-[0-9a-f]{32}$`)
	hex40       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// escape is the runner's rangevm.Printable without a limit: bytes 0x20-0x7e but `\` and `"` as they are, every
// other byte as `\x` and two lower-case hex digits.
func escape(raw []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c >= 0x20 && c <= 0x7e && c != '\\' && c != '"' {
			out = append(out, c)
			continue
		}
		out = append(out, '\\', 'x', digits[c>>4], digits[c&0xf])
	}
	return out
}

// unescape inverts escape; ok only if escaping the result gives file back, byte for byte (ADR 0079 point 3).
func unescape(file []byte) (raw []byte, ok bool) {
	raw = make([]byte, 0, len(file))
	for i := 0; i < len(file); i++ {
		if file[i] == '\\' && i+3 < len(file) && file[i+1] == 'x' {
			if v, err := strconv.ParseUint(string(file[i+2:i+4]), 16, 8); err == nil {
				raw = append(raw, byte(v))
				i += 3
				continue
			}
		}
		raw = append(raw, file[i])
	}
	return raw, string(escape(raw)) == string(file)
}

// contentKey is the runner's key of a job: sha256 over the request and the program, each prefixed by its length
// as a big-endian 64-bit integer.
func contentKey(request, program []byte) string {
	h := sha256.New()
	for _, part := range [][]byte{request, program} {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(part))))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// execRequest is the request bytes the runner keys an exec job by: its own encoding of the request it parsed.
// The program name's grammar holds nothing JSON or HTML escaping would change.
func execRequest(program string, timeoutS int64) []byte {
	return fmt.Appendf(nil, `{"schema_version":1,"kind":"exec","program":"%s","timeout_s":%d}`, program, timeoutS)
}

// result is what the judge reads from a runner's result.json.
type result struct {
	Schema, Runs                             int64
	ID, Label, RunnerCommit, ImageCommit     string
	ImageSHA, Verdict                        string
	Kind, Name, ContentKey, Program          string
	ProgramSHA                               string
	TimeoutS                                 int64
	RunVerdict, JobResult                    string
	JobExit, LaurelBytes                     int64
	HasJob, HasExit, HasLaurelBytes, HasExec bool
}

// The runner's result shape at 2c09799: each key's type, required or optional. A key outside it, or of
// another type, is not a runner result.
type kind int

const (
	kString kind = iota
	kInt
	kBool
	kCounts // an object of non-negative integers (a trial's measures)
	kHex40
	kHex64
)

var (
	resultShape = shape{
		required: map[string]kind{"schema_version": kInt, "id": kString, "label": kString, "runner_commit": kHex40,
			"image_commit": kHex40, "image_sha256": kHex64, "verdict": kString, "reason": kString},
	}
	jobShape = shape{
		required: map[string]kind{"name": kString, "kind": kString, "content_key": kHex64},
		optional: map[string]kind{"trials": kInt, "trial": kString, "program": kString, "timeout_s": kInt,
			"program_sha256": kHex64, "job_disk_sha256": kHex64},
	}
	limitsShape = shape{required: map[string]kind{"run_timeout_s": kInt, "serial_budget": kInt, "job_out_cap": kInt,
		"job_laurel_cap": kInt, "mem_reserve": kInt, "job_memory": kInt, "disk_reserve": kInt}}
	runShape = shape{
		required: map[string]kind{"verdict": kString, "reason": kString},
		optional: map[string]kind{"guest_kernel": kString, "job_result": kString, "job_exit": kInt, "out_bytes": kInt,
			"out_truncated": kBool, "laurel_bytes": kInt, "label": kString, "measures": kCounts},
	}
	errNotResult = errors.New("not a runner result")
)

type shape struct{ required, optional map[string]kind }

// check returns v as an object of this shape: every required key, no other than the optional ones, each typed.
func (s shape) check(v any, extra ...string) (object, error) {
	o, ok := v.(object)
	if !ok {
		return nil, errNotResult
	}
	for k := range s.required {
		if _, ok := o[k]; !ok {
			return nil, fmt.Errorf("%w: key %q missing", errNotResult, k)
		}
	}
	for k, val := range o {
		want, ok := s.required[k]
		if !ok {
			want, ok = s.optional[k]
		}
		if !ok {
			if isExtra(k, extra) {
				continue
			}
			return nil, fmt.Errorf("%w: key %q not allowed", errNotResult, k)
		}
		if !typed(val, want) {
			return nil, fmt.Errorf("%w: key %q has another type", errNotResult, k)
		}
	}
	return o, nil
}

func isExtra(k string, extra []string) bool {
	for _, e := range extra {
		if e == k {
			return true
		}
	}
	return false
}

func typed(v any, k kind) bool {
	switch k {
	case kString:
		_, ok := v.(string)
		return ok
	case kInt:
		_, ok := asInt(v)
		return ok
	case kBool:
		_, ok := v.(bool)
		return ok
	case kHex40:
		s, ok := v.(string)
		return ok && hex40.MatchString(s)
	case kHex64:
		s, ok := v.(string)
		return ok && hex64.MatchString(s)
	case kCounts:
		o, ok := v.(object)
		if !ok {
			return false
		}
		for _, n := range o {
			if i, ok := asInt(n); !ok || i < 0 {
				return false
			}
		}
		return true
	}
	return false
}

// decodeResult decodes a result.json strictly: exact keys, the runner's closed sets and types, an agent job's id
// ending in its name.
func decodeResult(data []byte) (result, error) {
	v, err := decode(data, false)
	if err != nil {
		return result{}, err
	}
	top, err := resultShape.check(v, "job", "limits", "runs")
	if err != nil {
		return result{}, err
	}
	var r result
	r.Schema, _ = integer(top, "schema_version")
	r.ID, _ = str(top, "id")
	r.Label, _ = str(top, "label")
	r.RunnerCommit, _ = str(top, "runner_commit")
	r.ImageCommit, _ = str(top, "image_commit")
	r.ImageSHA, _ = str(top, "image_sha256")
	r.Verdict, _ = str(top, "verdict")
	if _, err := limitsShape.check(top["limits"]); err != nil {
		return result{}, err
	}
	if job, present := top["job"]; present {
		if err := r.readJob(job); err != nil {
			return result{}, err
		}
		if !strings.HasSuffix(r.ID, "-"+r.Name) {
			return result{}, fmt.Errorf("%w: id does not end in the job's name", errNotResult)
		}
	}
	runs, isList := top["runs"].([]any)
	if !isList {
		return result{}, errNotResult
	}
	r.Runs = int64(len(runs))
	for i, run := range runs {
		o, err := runShape.check(run)
		if err != nil {
			return result{}, err
		}
		if i == 0 {
			r.RunVerdict, _ = str(o, "verdict")
			r.JobResult, _ = str(o, "job_result")
			r.JobExit, r.HasExit = integer(o, "job_exit")
			r.LaurelBytes, r.HasLaurelBytes = integer(o, "laurel_bytes")
		}
	}
	return r, nil
}

func (r *result) readJob(v any) error {
	job, err := jobShape.check(v)
	if err != nil {
		return err
	}
	r.HasJob = true
	r.Name, _ = str(job, "name")
	r.Kind, _ = str(job, "kind")
	r.ContentKey, _ = str(job, "content_key")
	if !jobNameRe.MatchString(r.Name) {
		return fmt.Errorf("%w: job name", errNotResult)
	}
	var ok [3]bool
	r.Program, ok[0] = str(job, "program")
	r.TimeoutS, ok[1] = integer(job, "timeout_s")
	r.ProgramSHA, ok[2] = str(job, "program_sha256")
	r.HasExec = ok[0] && ok[1] && ok[2]
	return nil
}
