// Package detect is the detection judge of ADR 0077, 0078 and 0079: it reads the runner's results and windows,
// pairs and rules as data, and gives each rule a verdict on each valid window. It uses the standard library only
// and imports no runner package (ADR 0079 point 1).
package detect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

// object is a decoded JSON object; arrays decode to []any, numbers to json.Number.
type object = map[string]any

var integerLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// errRepeated marks a key repeated in one object (with another value, where same values are allowed).
var errRepeated = errors.New("repeated key")

// decode reads data as exactly one JSON value of valid UTF-8. A key repeated in one object is refused, or, when
// sameDup is set (Laurel's records, ADR 0079 point 3), kept once if both values are the same.
func decode(data []byte, sameDup bool) (any, error) {
	if !utf8.Valid(data) || !json.Valid(data) {
		return nil, errors.New("not one valid JSON value")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	v, err := walk(dec, tok, sameDup)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

func walk(dec *json.Decoder, tok json.Token, sameDup bool) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := object{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				key, _ := kt.(string) // json.Valid held: an object's token here is its key
				vt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				v, err := walk(dec, vt, sameDup)
				if err != nil {
					return nil, err
				}
				if old, seen := o[key]; seen && (!sameDup || !same(old, v)) {
					return nil, fmt.Errorf("key %q: %w", key, errRepeated)
				}
				o[key] = v
			}
			_, err := dec.Token() // '}'
			return o, err
		case '[':
			list := []any{}
			for dec.More() {
				vt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("decode: %w", err)
				}
				v, err := walk(dec, vt, sameDup)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token() // ']'
			return list, err
		}
		return nil, errors.New("unexpected delimiter")
	default:
		return tok, nil // string, json.Number, bool or nil
	}
}

// same reports whether two decoded values are equal, without reflection on untrusted data (ENGINEERING.md 7).
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

// fields returns v as an object that has every required key and no key outside required and optional.
func fields(v any, required, optional []string) (object, error) {
	o, ok := v.(object)
	if !ok {
		return nil, errors.New("not an object")
	}
	for _, k := range required {
		if _, ok := o[k]; !ok {
			return nil, fmt.Errorf("key %q missing", k)
		}
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, k := range append(append([]string{}, required...), optional...) {
		allowed[k] = true
	}
	for k := range o {
		if !allowed[k] {
			return nil, fmt.Errorf("key %q not allowed", k)
		}
	}
	return o, nil
}

// str returns o[key] if it is a string.
func str(o object, key string) (string, bool) {
	s, ok := o[key].(string)
	return s, ok
}

// integer returns o[key] if it is a JSON number without fraction or exponent that fits an int64.
func integer(o object, key string) (int64, bool) {
	n, ok := o[key].(json.Number)
	if !ok || !integerLiteral.MatchString(string(n)) {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

// plainText reports whether b holds only printable ASCII and LF, as pairs and rules must (ADR 0079 point 3).
func plainText(b []byte) bool {
	for _, c := range b {
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}
