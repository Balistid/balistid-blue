package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// The functions below are internal/detect's, copied as they are: internal/detect is locked (ADR 0077 point 7) and
// exports no count of execs. TestDetectCopyIsDetectsSource fails as soon as either side differs from the other.

type object = map[string]any

var integerLiteral = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

var errRepeated = errors.New("repeated key")

func decode(data []byte, sameDup bool) (any, error) {
	if !utf8.Valid(data) || !json.Valid(data) {
		return nil, errors.New("not one valid JSON value")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walk(dec, nextToken(dec), sameDup)
}

func nextToken(dec *json.Decoder) json.Token {
	t, _ := dec.Token() // json.Valid held: no token can fail
	return t
}

func walk(dec *json.Decoder, tok json.Token, sameDup bool) (any, error) {
	switch tok {
	case json.Delim('{'):
		o := object{}
		for dec.More() {
			key, _ := nextToken(dec).(string) // an object's token here is its key
			v, err := walk(dec, nextToken(dec), sameDup)
			if err != nil {
				return nil, err
			}
			if old, seen := o[key]; seen && (!sameDup || !same(old, v)) {
				return nil, fmt.Errorf("key %q: %w", key, errRepeated)
			}
			o[key] = v
		}
		nextToken(dec) // '}'
		return o, nil
	case json.Delim('['):
		list := []any{}
		for dec.More() {
			v, err := walk(dec, nextToken(dec), sameDup)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		nextToken(dec) // ']'
		return list, nil
	}
	return tok, nil // string, json.Number, bool or nil
}

func same(a, b any) bool {
	switch x := a.(type) {
	case object:
		y, ok := b.(object)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !same(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !same(x[i], y[i]) {
				return false
			}
		}
		return true
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	return false
}

func str(o object, key string) (string, bool) {
	s, ok := o[key].(string)
	return s, ok
}

func integer(o object, key string) (int64, bool) { return asInt(o[key]) }

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !integerLiteral.MatchString(string(n)) {
		return 0, false
	}
	return parseInt(string(n))
}

func parseInt(s string) (int64, bool) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return i, true
}

func syscallOf(ev object) object {
	sc, _ := ev["SYSCALL"].(object)
	return sc
}

func execOK(ev object) bool {
	sc := syscallOf(ev)
	nr, _ := integer(sc, "syscall")
	exit, hasExit := integer(sc, "exit")
	name, _ := str(sc, "SYSCALL")
	success, _ := str(sc, "success")
	return nr == 59 && name == "execve" && success == "yes" && hasExit && exit == 0
}

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

func unescape(file []byte) (raw []byte, ok bool) {
	for i := 0; i < len(file); i++ {
		if file[i] == '\\' && i+3 < len(file) {
			if v, err := hex.DecodeString(string(file[i+2 : i+4])); err == nil {
				raw = append(raw, v...)
				i += 3
				continue
			}
		}
		raw = append(raw, file[i])
	}
	return raw, string(escape(raw)) == string(file)
}

// copied are the declarations above, by name, as internal/detect has them.
var copied = []string{"object", "integerLiteral", "errRepeated", "decode", "nextToken", "walk", "same", "str",
	"integer", "asInt", "parseInt", "syscallOf", "execOK", "escape", "unescape"}

func repoRoot(t testing.TB) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	return filepath.Join(filepath.Dir(self), "..", "..")
}

// declarations prints each top-level declaration of the non-test Go files in dir by its name, without comments.
func declarations(t *testing.T, files []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		show := func(key string, node any) {
			var b strings.Builder
			if err := printer.Fprint(&b, fset, node); err != nil {
				t.Fatal(err)
			}
			out[key] = b.String()
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					d.Doc = nil
					show(d.Name.Name, d)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						s.Doc, s.Comment = nil, nil
						show(s.Name.Name, s)
					case *ast.ValueSpec:
						s.Doc, s.Comment = nil, nil
						for i, n := range s.Names {
							if i < len(s.Values) {
								show(n.Name, s.Values[i])
							}
						}
					}
				}
			}
		}
	}
	return out
}

func TestDetectCopyIsDetectsSource(t *testing.T) {
	root := repoRoot(t)
	detectFiles, err := filepath.Glob(filepath.Join(root, "internal", "detect", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, f := range detectFiles {
		if !strings.HasSuffix(f, "_test.go") {
			sources = append(sources, f)
		}
	}
	detect := declarations(t, sources)
	mine := declarations(t, []string{filepath.Join(root, "cmd", "balistid-judge", "detect_test.go")})
	for _, name := range copied {
		if detect[name] == "" || detect[name] != mine[name] {
			t.Errorf("%s differs from internal/detect's:\n%s\n----\n%s", name, mine[name], detect[name])
		}
	}
}

// windowCounts is, for every window of lab/windows, its records and successful execs as internal/detect's own
// functions count them and as decodeLine does.
func windowCounts(t *testing.T) (names []string, records, detects, mine map[string]int) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "lab", "windows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	records, detects, mine = map[string]int{}, map[string]int{}, map[string]int{}
	for _, e := range entries {
		file, err := os.ReadFile(filepath.Join(dir, e.Name(), "job-laurel.txt")) //nolint:gosec // the repository's windows
		if err != nil {
			t.Fatal(err)
		}
		raw, ok := unescape(file)
		if !ok || len(raw) == 0 || raw[len(raw)-1] != '\n' {
			t.Fatalf("%s does not unescape", e.Name())
		}
		for _, line := range bytes.Split(raw[:len(raw)-1], []byte("\n")) {
			records[e.Name()]++
			if v, err := decode(line, true); err == nil {
				if ev, isObject := v.(object); isObject && execOK(ev) {
					detects[e.Name()]++
				}
			}
			if rec, err := decodeLine(line); err == nil && rec.Exec {
				mine[e.Name()]++
			}
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, records, detects, mine
}

// TestDecoderAgreesWithDetect is acceptance decoder_disagrees over lab/windows.
func TestDecoderAgreesWithDetect(t *testing.T) {
	names, records, detects, mine := windowCounts(t)
	disagree, total, execs := 0, 0, 0
	for _, n := range names {
		total += records[n]
		execs += detects[n]
		if detects[n] != mine[n] {
			disagree++
			t.Errorf("%s: internal/detect counts %d successful execs, the judge %d", n, detects[n], mine[n])
		}
	}
	t.Logf("%d windows, %d records, %d successful execs, %d windows disagree", len(names), total, execs, disagree)
	if len(names) == 0 || execs == 0 {
		t.Fatal("no window or no exec: the comparison shows nothing")
	}
}
