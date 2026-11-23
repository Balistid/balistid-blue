package detect

import (
	"strings"
	"unicode/utf8"
)

// recordString is a record's string value as the program saw it, the one way a rule reads a string of a record:
// decoded once here, so no op compares Laurel's quoting or decodes twice (`%2525` is `%25`, not `%`).
func recordString(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return laurelText(s), true
}

// laurelText is s as the program saw it: Laurel 0.8.2 writes a byte string with `%`, `+`, control bytes, 0x7f,
// invalid UTF-8 and the BOM as %xx (src/quote.rs, URIEscapeWriter), so `%Y` arrives as `%25Y` (ADR 0080). A string
// that is not exactly Laurel's quoting of its decoding comes back unchanged, as the judge read it before 0080.
func laurelText(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	raw, ok := laurelUnquote(s)
	if !ok || laurelQuote(raw) != s {
		return s
	}
	return string(raw)
}

// laurelUnquote decodes every %xx; false on a `%` not followed by two lower-case hex digits.
func laurelUnquote(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return nil, false
		}
		hi, ok1 := hexValue(s[i+1])
		lo, ok2 := hexValue(s[i+2])
		if !ok1 || !ok2 {
			return nil, false
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, true
}

func hexValue(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f': // Laurel writes lower-case hex only
		return c - 'a' + 10, true
	}
	return 0, false
}

// laurelQuote is URIEscapeWriter on one write: printable ASCII other than `%` and `+` as it is, a complete valid
// UTF-8 sequence other than the BOM as it is, every other byte as lowercase %xx; a sequence broken by a byte that
// is not a continuation byte is quoted and that byte read again.
func laurelQuote(b []byte) string {
	const hexDigits = "0123456789abcdef"
	var out strings.Builder
	quote := func(bs []byte) {
		for _, c := range bs {
			out.WriteByte('%')
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0x0f])
		}
	}
	for i := 0; i < len(b); {
		c := b[i]
		if c >= 32 && c < 127 && c != '%' && c != '+' {
			out.WriteByte(c)
			i++
			continue
		}
		var need int
		switch {
		case c&0b11100000 == 0b11000000:
			need = 1
		case c&0b11110000 == 0b11100000:
			need = 2
		case c&0b11111000 == 0b11110000:
			need = 3
		default:
			quote(b[i : i+1])
			i++
			continue
		}
		j := i + 1
		for ; need > 0 && j < len(b) && b[j]&0b11000000 == 0b10000000; j++ {
			need--
		}
		if seq := b[i:j]; need == 0 && utf8.Valid(seq) && string(seq) != "\xef\xbb\xbf" {
			out.Write(seq)
		} else {
			quote(seq)
		}
		i = j
	}
	return out.String()
}
