// Package rangeguest parses what the range guest reads about its own sensor (ADR 0004 smoke test):
// auditctl status, process capabilities, Laurel's JSON lines and auditd's state report. The parsers
// are strict on purpose; anything they do not recognise reads as "missing", never as a pass.
package rangeguest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
)

// maxLine caps one Laurel line; a longer line ends the scan, so a check that needs a later line fails.
const maxLine = 4 << 20

// AuditStatus returns the fields of `auditctl -s` as name → value ("enabled" → "2").
func AuditStatus(out string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && name != "" {
			fields[name] = strings.TrimSpace(value)
		}
	}
	return fields
}

// Caps returns CapPrm, CapEff and CapAmb from a /proc/<pid>/status file, or "missing".
func Caps(status string) (prm, eff, amb string) {
	prm, eff, amb = "missing", "missing", "missing"
	for _, line := range strings.Split(status, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch name {
		case "CapPrm":
			prm = strings.TrimSpace(value)
		case "CapEff":
			eff = strings.TrimSpace(value)
		case "CapAmb":
			amb = strings.TrimSpace(value)
		}
	}
	return prm, eff, amb
}

// StatusField returns one field of a /proc/<pid>/status file ("PPid", "Uid"), or "".
func StatusField(status, field string) string {
	for _, line := range strings.Split(status, "\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && name == field {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// CmdlineValue returns the value of key in a /proc/cmdline, all values comma-joined when the key
// repeats (which never matches an expected single value), or "missing".
func CmdlineValue(cmdline, key string) string {
	var values []string
	for _, tok := range strings.Fields(cmdline) {
		if k, v, ok := strings.Cut(tok, "="); ok && k == key {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return "missing"
	}
	return strings.Join(values, ",")
}

// UserName returns the name of uid in an /etc/passwd file, or "".
func UserName(passwd, uid string) string {
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[2] == uid {
			return f[0]
		}
	}
	return ""
}

// HasExecArg reports whether a Laurel log holds an EXECVE record whose argv contains token.
func HasExecArg(log io.Reader, token string) bool {
	return eachEvent(log, func(ev map[string]json.RawMessage) bool {
		var execve struct {
			ARGV []string `json:"ARGV"`
		}
		raw, ok := ev["EXECVE"]
		return ok && json.Unmarshal(raw, &execve) == nil && slices.Contains(execve.ARGV, token)
	})
}

// HasRefusedDisable reports whether a Laurel log holds a CONFIG_CHANGE record of an attempt to set
// audit_enabled to 0 that the kernel refused (res=0). Laurel writes CONFIG_CHANGE as a list of records.
func HasRefusedDisable(log io.Reader) bool {
	return eachEvent(log, func(ev map[string]json.RawMessage) bool {
		var changes []map[string]json.RawMessage
		if json.Unmarshal(ev["CONFIG_CHANGE"], &changes) != nil {
			return false
		}
		return slices.ContainsFunc(changes, func(c map[string]json.RawMessage) bool {
			return scalar(c["audit_enabled"]) == "0" && scalar(c["res"]) == "0"
		})
	})
}

// eachEvent calls match on every JSON object line of log until it returns true.
func eachEvent(log io.Reader, match func(map[string]json.RawMessage) bool) bool {
	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var ev map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &ev) == nil && match(ev) {
			return true
		}
	}
	return false
}

// scalar renders a JSON number or string without quotes, so 0 and "0" compare equal.
func scalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(bytes.TrimSpace(raw))
}

// OverflowDetected returns the value of "plugin queue overflow detected" in /run/audit/auditd.state,
// or "missing".
func OverflowDetected(state string) string {
	for _, line := range strings.Split(state, "\n") {
		if name, value, ok := strings.Cut(line, "="); ok && strings.TrimSpace(name) == "plugin queue overflow detected" {
			return strings.TrimSpace(value)
		}
	}
	return "missing"
}
