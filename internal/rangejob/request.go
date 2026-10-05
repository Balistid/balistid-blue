// Package rangejob is the contract between agents and the range runner (ADR 0011), starting with
// the request an agent drops in the inbox. Every byte of it is written by an agent, so it is parsed
// as hostile input: anything unexpected is refused, never repaired, and error text never quotes it,
// because runner results are read by agents.
package rangejob

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
)

// RequestFile is the request's name in a job directory; a program cannot take it.
const RequestFile = "job.json"

// Limits of a request (ADR 0011, point 5).
const (
	MaxRequestBytes = 4 << 10
	MaxTrials       = 3
	MaxTimeoutS     = 300
)

// Job kinds (ADR 0011, point 4).
const (
	KindRun  = "run"
	KindExec = "exec"
)

const schemaVersion = 1

var errInvalidJSON = errors.New("request is not valid JSON")

var programName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Request is a validated job.json. A request names no source: everything in the inbox is an agent
// job, whatever it claims (ADR 0011, point 5).
type Request struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Trials        int    `json:"trials,omitempty"`
	Program       string `json:"program,omitempty"`
	TimeoutS      int    `json:"timeout_s,omitempty"`
}

// The exact keys of each kind: a key from the other kind is refused even at its zero value.
var kindKeys = map[string][]string{
	KindRun:  {"kind", "schema_version", "trials"},
	KindExec: {"kind", "program", "schema_version", "timeout_s"},
}

// ParseRequest reads at most MaxRequestBytes+1 bytes from r and returns the request only if it is
// one flat JSON object with exactly its kind's keys, each once, and values within their limits.
func ParseRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil {
		return Request{}, fmt.Errorf("read request: %w", err)
	}
	if len(data) > MaxRequestBytes {
		return Request{}, fmt.Errorf("request over %d bytes", MaxRequestBytes)
	}
	keys, err := flatKeys(data)
	if err != nil {
		return Request{}, err
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return Request{}, errors.New("request values have the wrong type")
	}
	if req.SchemaVersion != schemaVersion {
		return Request{}, errors.New("schema_version must be 1")
	}
	want, ok := kindKeys[req.Kind]
	if !ok {
		return Request{}, errors.New("kind must be run or exec")
	}
	slices.Sort(keys)
	if !slices.Equal(keys, want) {
		return Request{}, fmt.Errorf("a %s request has exactly the keys %v", req.Kind, want)
	}
	switch req.Kind {
	case KindRun:
		if req.Trials < 1 || req.Trials > MaxTrials {
			return Request{}, fmt.Errorf("trials must be 1 to %d", MaxTrials)
		}
	case KindExec:
		if !programName.MatchString(req.Program) || req.Program == RequestFile {
			return Request{}, errors.New("program must be a plain file name other than " + RequestFile)
		}
		if req.TimeoutS < 1 || req.TimeoutS > MaxTimeoutS {
			return Request{}, fmt.Errorf("timeout_s must be 1 to %d", MaxTimeoutS)
		}
	}
	return req, nil
}

// flatKeys returns every key of data, duplicates included, which must be a single JSON object whose
// values are strings or numbers. encoding/json keeps the last duplicate silently; comparing this
// list with the kind's keys refuses it.
func flatKeys(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("request is not a JSON object")
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errInvalidJSON
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("request key is not a string")
		}
		keys = append(keys, key)
		val, err := dec.Token()
		if err != nil {
			return nil, errInvalidJSON
		}
		switch val.(type) {
		case string, float64:
		default:
			return nil, errors.New("request values must be strings or numbers")
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, errInvalidJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON object")
	}
	return keys, nil
}
