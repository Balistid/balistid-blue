package detect

import (
	"encoding/hex"
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
// that is not exactly Laurel's quoting of its decoding comes back unchanged, as the judge read it before 0080: that
// one check decides, so the decoding itself need not tell a bad `%` from a good one.
func laurelText(s string) string {
	if !strings.Contains(s, "%") {
		return s // nothing to decode, and no allocation on the common string
	}
	if raw := laurelUnquote(s); laurelQuote(raw) == s {
		return string(raw)
	}
	return s
}

const lowerHex = "0123456789abcdef"

// laurelUnquote decodes each `%` and two hex digits; any other `%` stays a byte. Only laurelText's round trip gives
// the result a meaning, so upper-case digits decode here and fail it there.
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

// laurelQuote is URIEscapeWriter on one write: printable ASCII other than `%` and `+` as it is, a valid UTF-8
// sequence other than the BOM as it is, every other byte as lowercase %xx. Laurel quotes a broken or invalid
// sequence byte by byte and a lone continuation byte as well, so reading one rune at a time gives its output.
func laurelQuote(b []byte) string {
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
