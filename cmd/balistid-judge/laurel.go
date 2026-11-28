package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// agentBinaries are the executables of agents, as Laurel writes the path after decoding its quoting (ADR 0082
// point 4). Claude Code installs each version as a file named by its number, so the name alone says nothing.
var agentBinaries = []*regexp.Regexp{
	regexp.MustCompile(`^/home/[^/]+/\.local/share/claude/versions/[^/]+$`),
}

// nameAlphabet is what a program's base name may be in exec.jsonl; anything else is replaced (ADR 0082 point 4).
var nameAlphabet = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// Laurel's process keys: EVENT_ID is the exec event's id, START_TIME a process it read from /proc.
var (
	eventID   = regexp.MustCompile(`^[0-9]{1,20}\.[0-9]{3}:[0-9]{1,20}$`)
	startTime = regexp.MustCompile(`^[0-9]{1,20}\.[0-9]{3}$`)
	unsigned  = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})$`)
)

// laurelLine is the part of one Laurel line the judge reads. Every field stays raw until it is checked, so a value
// of an unexpected type costs only that field; encoding/json matches keys without case, so each field that has a
// twin in another case (pid and PID) is declared beside it, and decodeExec refuses any other spelling.
type laurelLine struct {
	Syscall json.RawMessage `json:"SYSCALL"`
}

type laurelSyscall struct {
	Number    json.RawMessage `json:"syscall"`
	Name      json.RawMessage `json:"SYSCALL"`
	Success   json.RawMessage `json:"success"`
	Exit      json.RawMessage `json:"exit"`
	PID       json.RawMessage `json:"pid"`
	PPID      json.RawMessage `json:"ppid"`
	UID       json.RawMessage `json:"uid"`
	Exe       json.RawMessage `json:"exe"`
	Key       json.RawMessage `json:"key"`
	Proc      json.RawMessage `json:"PID"`
	Parent    json.RawMessage `json:"PPID"`
	UIDName   json.RawMessage `json:"UID"`
	SpawnedBy json.RawMessage `json:"SPAWNED_BY"`
	Arch      json.RawMessage `json:"arch"`
	ArchName  json.RawMessage `json:"ARCH"`
}

// level is an object of a line the judge decodes, by the names it may hold in exactly that spelling; another
// spelling of one of them is refused. Every other object is levelOther, whose keys the judge never reads.
type level int

const (
	levelOther level = iota
	levelLine
	levelSyscall
	levelProc
	levelSpawner
)

var levelNames = map[level][]string{
	levelLine: {"SYSCALL"},
	levelSyscall: {"syscall", "SYSCALL", "success", "exit", "pid", "ppid", "uid", "exe", "key", "PID", "PPID", "UID",
		"SPAWNED_BY", "arch", "ARCH"},
	levelProc:    {"EVENT_ID", "START_TIME"},
	levelSpawner: {"EVENT_ID", "START_TIME", "pid", "exe"},
}

// child is the level of the object under key in an object of level l.
func (l level) child(key string) level {
	switch {
	case l == levelLine && key == "SYSCALL":
		return levelSyscall
	case l == levelSyscall && key == "PID":
		return levelProc
	case l == levelSyscall && key == "SPAWNED_BY":
		return levelSpawner
	}
	return levelOther
}

// procKey is Laurel's key of a process: one of the two, as Laurel wrote it.
type procKey struct {
	EventID   string `json:"event_id,omitempty"`
	StartTime string `json:"start_time,omitempty"`
}

// spawner is SPAWNED_BY without its comm and exe: the process before this exec, or the parent.
type spawner struct {
	procKey
	PID uint32 `json:"pid"`
}

// record is what the decoder reads of one line: its rule key, whether it is a successful execve as internal/detect
// counts one, and for such an exec the fields exec.jsonl may hold.
type record struct {
	Key  string
	Exec bool
	Run  execRun
	// Whole is false for an exec whose pid, ppid, uid or keys do not decode: it is counted, not exported.
	Whole bool
	// Unlisted is a successful exec the judge counts but does not list, Refused one the strict reading refused.
	Unlisted, Refused string
}

// What a successful exec that exec.jsonl does not list is (ADR 0082 consequences), and why a line looking like an
// exec was refused.
const (
	unlistedExecveat  = "execveat"
	unlistedOtherArch = "other_arch"
	refusedUTF8       = "exec: not valid UTF-8"
	refusedKeys       = "exec: a key repeated with another value or spelled in another case"
	nativeArch        = "0xc000003e" // AUDIT_ARCH_X86_64, as Laurel writes the arch field
)

// execRun is one line of exec.jsonl (ADR 0082 point 4): no path, argument, environment or directory.
type execRun struct {
	Schema       int      `json:"schema_version"`
	Time         string   `json:"time"`
	Serial       uint64   `json:"serial"`
	PID          uint32   `json:"pid"`
	PPID         uint32   `json:"ppid"`
	UID          uint32   `json:"uid"`
	Process      procKey  `json:"process"`
	SpawnedBy    *spawner `json:"spawned_by"`
	Name         string   `json:"name"`
	Agent        bool     `json:"agent"`
	SpawnerAgent bool     `json:"spawner_agent"`
}

var errNotLaurel = errors.New("not a Laurel line")

// decodeLine reads one Laurel line. An error is a line it cannot read at all; a line that is no successful exec
// comes back with Exec false and only its rule key.
func decodeLine(data []byte) (record, error) {
	var l laurelLine
	if err := json.Unmarshal(data, &l); err != nil {
		return record{}, errNotLaurel
	}
	var sc laurelSyscall
	if len(l.Syscall) == 0 || l.Syscall[0] != '{' || json.Unmarshal(l.Syscall, &sc) != nil {
		return record{}, nil
	}
	rec := record{Key: ruleKey(sc.Key)}
	name, succeeded := text(sc.Name), text(sc.Success) == "yes" && bytes.Equal(sc.Exit, []byte("0"))
	// internal/detect's execOK: the syscall and exit as integer literals, the name and success as strings.
	switch {
	case !succeeded:
		return rec, nil
	case name == "execveat":
		rec.Unlisted = unlistedExecveat
		if text(sc.Arch) != nativeArch {
			rec.Unlisted = unlistedOtherArch
		}
		return rec, nil
	case name != "execve":
		return rec, nil
	case !bytes.Equal(sc.Number, []byte("59")): // execve under another number: a 32-bit process
		rec.Unlisted = unlistedOtherArch
		return rec, nil
	}
	// internal/detect reads only valid UTF-8 and refuses a key repeated with another value, which encoding/json
	// would take silently (the last one).
	switch {
	case !utf8.Valid(data):
		rec.Refused = refusedUTF8
		return rec, nil
	case !strictKeys(data):
		rec.Refused = refusedKeys
		return rec, nil
	}
	rec.Exec = true
	rec.Run, rec.Whole = exportOf(sc)
	return rec, nil
}

// exportOf is the line exec.jsonl may hold of an exec, but its time and serial, and whether every field decoded.
func exportOf(sc laurelSyscall) (execRun, bool) {
	r := execRun{Schema: 1}
	pid, okPID := uint32Of(sc.PID)
	ppid, okPPID := uint32Of(sc.PPID)
	uid, okUID := uint32Of(sc.UID)
	proc, okProc := procOf(sc.Proc)
	r.PID, r.PPID, r.UID, r.Process = pid, ppid, uid, proc
	exe := laurelText(text(sc.Exe))
	r.Name, r.Agent = programName(exe), isAgent(exe)
	var sp struct {
		EventID   json.RawMessage `json:"EVENT_ID"`
		StartTime json.RawMessage `json:"START_TIME"`
		PID       json.RawMessage `json:"pid"`
		Exe       json.RawMessage `json:"exe"`
	}
	if len(sc.SpawnedBy) > 0 && sc.SpawnedBy[0] == '{' && json.Unmarshal(sc.SpawnedBy, &sp) == nil {
		key, okKey := keyOf(sp.EventID, sp.StartTime)
		spid, okSPID := uint32Of(sp.PID)
		if okKey && okSPID {
			r.SpawnedBy = &spawner{procKey: key, PID: spid}
			r.SpawnerAgent = isAgent(laurelText(text(sp.Exe)))
		}
	}
	return r, okPID && okPPID && okUID && okProc && exe != ""
}

func procOf(raw json.RawMessage) (procKey, bool) {
	var p struct {
		EventID   json.RawMessage `json:"EVENT_ID"`
		StartTime json.RawMessage `json:"START_TIME"`
	}
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &p) != nil {
		return procKey{}, false
	}
	return keyOf(p.EventID, p.StartTime)
}

// keyOf is exactly one of the two keys in Laurel's grammar.
func keyOf(event, start json.RawMessage) (procKey, bool) {
	e, s := text(event), text(start)
	switch {
	case e != "" && s == "" && eventID.MatchString(e):
		return procKey{EventID: e}, true
	case s != "" && e == "" && startTime.MatchString(s):
		return procKey{StartTime: s}, true
	}
	return procKey{}, false
}

// text is raw as a JSON string, or "" when it is anything else.
func text(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// uint32Of is raw as an unsigned integer literal within 32 bits: a pid or a uid.
func uint32Of(raw json.RawMessage) (uint32, bool) {
	if !unsigned.Match(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw), 10, 32)
	return uint32(n), err == nil
}

// ruleKey is the audit rule's key of a record, through the name alphabet; "" for none.
func ruleKey(raw json.RawMessage) string {
	if s := laurelText(text(raw)); s != "" {
		return safeName(s)
	}
	return ""
}

// programName is the base name of the executable through the alphabet: no directory leaves the judge.
func programName(exe string) string {
	return safeName(exe[strings.LastIndexByte(exe, '/')+1:])
}

// safeName is s when it is in the alphabet, else x- and the first 8 hex digits of its SHA-256.
func safeName(s string) string {
	if nameAlphabet.MatchString(s) {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	return "x-" + hex.EncodeToString(sum[:4])
}

func isAgent(exe string) bool {
	for _, re := range agentBinaries {
		if re.MatchString(exe) {
			return true
		}
	}
	return false
}

// strictKeys reports whether no object of the line repeats a key with other bytes as its value, and whether the
// objects the judge decodes spell their keys only as declared. Equal values are allowed: Laurel 0.8.2 writes
// SPAWNED_BY's pid twice. Values are compared as bytes, where internal/detect compares decoded values.
func strictKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	return err == nil && tok == json.Delim('{') && walkObject(dec, data, levelLine) == nil
}

var errKeys = errors.New("keys")

// walkObject reads the members of an object whose '{' was read, up to its '}'.
func walkObject(dec *json.Decoder, data []byte, l level) error {
	seen := map[string][]byte{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return errKeys
		}
		if declaredOtherwise(key, levelNames[l]) {
			return errKeys
		}
		start := dec.InputOffset()
		if err := walkValue(dec, data, l.child(key)); err != nil {
			return err
		}
		value := bytes.TrimLeft(data[start:dec.InputOffset()], " \t\r\n:")
		if old, dup := seen[key]; dup && !bytes.Equal(old, value) {
			return errKeys
		}
		seen[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return errKeys
	}
	return nil
}

func walkValue(dec *json.Decoder, data []byte, l level) error {
	tok, err := dec.Token()
	if err != nil {
		return errKeys
	}
	switch tok {
	case json.Delim('{'):
		return walkObject(dec, data, l)
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec, data, levelOther); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errKeys
		}
	}
	return nil
}

// declaredOtherwise reports a key that encoding/json would take for a declared name it does not spell.
func declaredOtherwise(key string, names []string) bool {
	exact := false
	for _, n := range names {
		if n == key {
			exact = true
		}
	}
	if exact {
		return false
	}
	for _, n := range names {
		if strings.EqualFold(n, key) {
			return true
		}
	}
	return false
}

// laurelText is internal/detect's laurelText (ADR 0080): Laurel 0.8.2 writes `%`, `+`, control bytes, 0x7f,
// invalid UTF-8 and the BOM as %xx; a string that is not exactly Laurel's quoting of its decoding stays as it is.
func laurelText(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if raw := laurelUnquote(s); laurelQuote(raw) == s {
		return string(raw)
	}
	return s
}

func laurelUnquote(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				out = append(out, v[0])
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

func laurelQuote(b []byte) string {
	const lowerHex = "0123456789abcdef"
	var out strings.Builder
	for i := 0; i < len(b); {
		if c := b[i]; c >= 0x20 && c <= 0x7e && c != '%' && c != '+' {
			out.WriteByte(c)
			i++
			continue
		}
		if r, size := utf8.DecodeRune(b[i:]); size > 1 && r != 0xfeff {
			out.Write(b[i : i+size])
			i += size
			continue
		}
		out.WriteByte('%')
		out.WriteByte(lowerHex[b[i]>>4])
		out.WriteByte(lowerHex[b[i]&0x0f])
		i++
	}
	return out.String()
}

// strictDecode decodes one JSON object into v, refusing unknown fields and trailing data: the judge's own files
// and the collector's records are read as the program that wrote them spelled them.
func strictDecode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err //nolint:wrapcheck // the callers say what they decoded
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the object")
	}
	return nil
}
