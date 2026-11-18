package detect

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
)

// The runner's contract at 2c09799, re-implemented (ADR 0079 point 1) and pinned by tests to real bytes.
const (
	// Anchor is the runner's result the pilot counts from (ADR 0078 point 1).
	Anchor = "20261117T222824Z-cf92a4e6-pr13-run-d4"
	// ResultsDir holds the runner's agent results on the host; verify reads it, nothing names another.
	ResultsDir = "/var/lib/balistid/results/agent"
	// LaurelCap bounds a window's decoded records (ADR 0077 point 3).
	LaurelCap = 6 << 20
	// JobUser is the user the runner's guest runs a job's program as.
	JobUser = "balistid-job"
	// JobProgram is the path the guest runs a job's program from.
	JobProgram = "/run/balistid-job/program"
	// LaurelFile and ResultFile are the window files the judge reads.
	LaurelFile = "job-laurel.txt"
	ResultFile = "result.json"
)

// images are the known images: commit and image sha256 both (ADR 0079 point 6).
var images = map[string]string{
	"2c09799a44e766ea3b3f0597bd8c9ab32db9d31e": "693e28f3e561f5959dd1bcda486fe8ed1bbc11a6c3b120263b9634e262e933a7",
}

var (
	resultID    = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}(-[a-z0-9][a-z0-9-]{0,63})?$`)
	textName    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	programName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	canaryArg   = regexp.MustCompile(`^balistid-canary-[0-9a-f]{32}$`)
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

// result is what the judge reads from a runner's result.json; every key of 2c09799 decodes, no other.
type result struct {
	Schema, Runs                                      int64
	ID, Label, ImageCommit, ImageSHA, Verdict         string
	Kind, Name, ContentKey, Program, ProgramSHA       string
	TimeoutS                                          int64
	RunVerdict, JobResult                             string
	JobExit, LaurelBytes                              int64
	HasJob, HasExit, HasLaurelBytes, HasProgramFields bool
}

var (
	resultKeys = []string{"schema_version", "id", "label", "runner_commit", "image_commit", "image_sha256", "limits",
		"verdict", "reason", "runs"}
	jobKeys      = []string{"name", "kind", "content_key"}
	jobOptional  = []string{"trials", "trial", "program", "timeout_s", "program_sha256", "job_disk_sha256"}
	limitKeys    = []string{"run_timeout_s", "serial_budget", "job_out_cap", "job_laurel_cap", "mem_reserve", "job_memory", "disk_reserve"}
	runKeys      = []string{"verdict", "reason"}
	runOptional  = []string{"guest_kernel", "job_result", "job_exit", "out_bytes", "out_truncated", "laurel_bytes", "label", "measures"}
	errNotResult = fmt.Errorf("not a runner result")
)

// decodeResult decodes a result.json strictly: exact keys, the runner's closed sets, its types.
func decodeResult(data []byte) (result, error) {
	v, err := decode(data, false)
	if err != nil {
		return result{}, err
	}
	top, err := fields(v, resultKeys, []string{"job"})
	if err != nil {
		return result{}, err
	}
	var r result
	var ok [8]bool
	r.Schema, ok[0] = integer(top, "schema_version")
	r.ID, ok[1] = str(top, "id")
	r.Label, ok[2] = str(top, "label")
	r.ImageCommit, ok[3] = str(top, "image_commit")
	r.ImageSHA, ok[4] = str(top, "image_sha256")
	r.Verdict, ok[5] = str(top, "verdict")
	_, ok[6] = str(top, "runner_commit")
	_, ok[7] = str(top, "reason")
	for _, good := range ok {
		if !good {
			return result{}, errNotResult
		}
	}
	if _, err := fields(top["limits"], limitKeys, nil); err != nil {
		return result{}, err
	}
	if job, present := top["job"]; present {
		if err := r.readJob(job); err != nil {
			return result{}, err
		}
	}
	runs, isList := top["runs"].([]any)
	if !isList {
		return result{}, errNotResult
	}
	r.Runs = int64(len(runs))
	for i, run := range runs {
		o, err := fields(run, runKeys, runOptional)
		if err != nil {
			return result{}, err
		}
		verdict, vok := str(o, "verdict")
		if _, rok := str(o, "reason"); !vok || !rok {
			return result{}, errNotResult
		}
		if i == 0 {
			r.RunVerdict = verdict
			r.JobResult, _ = str(o, "job_result")
			r.JobExit, r.HasExit = integer(o, "job_exit")
			r.LaurelBytes, r.HasLaurelBytes = integer(o, "laurel_bytes")
		}
	}
	return r, nil
}

func (r *result) readJob(v any) error {
	job, err := fields(v, jobKeys, jobOptional)
	if err != nil {
		return err
	}
	var ok [3]bool
	r.Name, ok[0] = str(job, "name")
	r.Kind, ok[1] = str(job, "kind")
	r.ContentKey, ok[2] = str(job, "content_key")
	if !ok[0] || !ok[1] || !ok[2] {
		return errNotResult
	}
	r.HasJob = true
	var pok [3]bool
	r.Program, pok[0] = str(job, "program")
	r.TimeoutS, pok[1] = integer(job, "timeout_s")
	r.ProgramSHA, pok[2] = str(job, "program_sha256")
	r.HasProgramFields = pok[0] && pok[1] && pok[2]
	return nil
}
