// Package detect is the detection judge of ADR 0077, 0078 and 0079: it reads the runner's results and windows,
// pairs and rules as data, and gives each rule a verdict on each valid window. It uses the standard library only
// and imports no runner package (ADR 0079 point 1).
package detect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// object is a decoded JSON object; arrays decode to []any, numbers to json.Number.
type object = map[string]any

// integerLiteral is an integer as the judge's own data and the runner's results spell it: no fraction, no
// exponent, no "-0". eventInteger is any integer a record may spell, "-0" included; JSON forbids leading zeros.
var (
	integerLiteral = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	eventInteger   = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

// errRepeated marks a key repeated in one object (with another value, where same values are allowed).
var errRepeated = errors.New("repeated key")

// decode reads data as exactly one JSON value of valid UTF-8. A key repeated in one object is refused, or, when
// sameDup is set (Laurel's records, ADR 0079 point 3), kept once if both values are the same. json.Valid is the one
// syntax check: after it the decoder's tokens cannot fail, so walk reads them without checking.
func decode(data []byte, sameDup bool) (any, error) {
	if !utf8.Valid(data) || !json.Valid(data) {
		return nil, errors.New("not one valid JSON value")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walk(dec, nextToken(dec), sameDup)
}

// nextToken is the decoder's next token; json.Valid held, so it has one.
func nextToken(dec *json.Decoder) json.Token {
	t, _ := dec.Token() //nolint:errcheck // json.Valid held: no token can fail
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
	allowed := map[string]bool{}
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

// integer returns o[key] if it is an integer spelled as integerLiteral that fits an int64.
func integer(o object, key string) (int64, bool) { return asInt(o[key]) }

// asInt returns v if it is an integer spelled as integerLiteral that fits an int64.
func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !integerLiteral.MatchString(string(n)) {
		return 0, false
	}
	return parseInt(string(n))
}

// eventInt returns v if it is an integer of a record, in any spelling JSON allows, that fits an int64.
func eventInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || !eventInteger.MatchString(string(n)) {
		return 0, false
	}
	return parseInt(string(n))
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

// parseInt is a decimal int64, or 0 and false when it does not fit (ParseInt alone would give the bound).
func parseInt(s string) (int64, bool) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return i, true
}
