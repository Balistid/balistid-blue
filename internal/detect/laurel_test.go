package detect

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// Laurel 0.8.2's 20 uri_escape cases (src/quote.rs), two of json_serialize's surrogates (src/json.rs), then ours.
var laurelCases = []struct{ raw, quoted string }{
	{"\xc3\xa4\xc3\xb6\xc3\xbc", "äöü"}, {"\xf0\xf0\x9f\x92\x96asdf", "%f0💖asdf"},
	{"\xf0\x9f\x84\xbb\xf0\x9f\x84\xb0\xf0\x9f\x85\x84\xf0\x9f\x85\x81\xf0\x9f\x84\xb4\xf0\x9f\x84\xbb", "🄻🄰🅄🅁🄴🄻"},
	{" ", " "}, {"asdf", "asdf"}, {"+", "%2b"}, {"%", "%25"}, {"+++", "%2b%2b%2b"}, {"%%%", "%25%25%25"},
	{"%+%", "%25%2b%25"}, {"\xc3\xa4", "ä"}, {"\xe2\x82\xac", "€"}, {"\xf0\x9f\x92\x96", "💖"},
	{"abcd\xc3\xa4\xc3\xb6\xc3\xbcefgh", "abcdäöüefgh"}, {"\xc3\xc3\xa4", "%c3ä"},
	{"\xf0\xf0\x9f\x92\x96", "%f0💖"}, {"\xf0\xf0\x9f\x92\x96\xf0", "%f0💖%f0"},
	{"\xf0\x9f\xf0\x9f\x92\x96", "%f0%9f💖"}, {"\xf0\x9f\x92\xf0\x9f\x92\x96", "%f0%9f%92💖"},
	{"\xEF\xBB\xBF", "%ef%bb%bf"}, {"\xed\xa0\x80", "%ed%a0%80"}, {"\xed\xbf\xbf", "%ed%bf%bf"},
	{"a\nb\tc\x7f", "a%0ab%09c%7f"}, {"~\x1f", "~%1f"}, {"\xc3\xa4\x80", "ä%80"}, {"\xe2\x82\xac\x80", "€%80"}, {"\xf0\x9f\x92\x96\x80", "💖%80"},
	{"\xc2\x80\xdf\xbf", "\u0080\u07ff"}, {"\xc1\xbf", "%c1%bf"}, {"\xe0\xa0\x80\xe1\x80\x80", "\u0800\u1000"},
	{"\xef\xbf\xbd", "\ufffd"}, {"\xe0\x80\x80", "%e0%80%80"}, {"\xf0\x90\x80\x80", "\U00010000"},
	{"\xf1\x80\x80\x80", "\U00040000"}, {"\xf4\x8f\xbf\xbf", "\U0010ffff"}, {"\xf4\x90\x80\x80", "%f4%90%80%80"},
	{"\xf5\x80\x80\x80", "%f5%80%80%80"}, {"\xc3", "%c3"},
}

// laurelQuote is Laurel 0.8.2's quoting: a Laurel upgrade must re-check it against src/quote.rs (ADR 0080).
func TestLaurelQuoteIsForThePackagedLaurel(t *testing.T) {
	pkg, err := os.ReadFile("../../packaging/laurel/PKGBUILD")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pkg), "\npkgver=0.8.2\n") {
		t.Fatal("Laurel is no longer 0.8.2: check laurelQuote against its src/quote.rs URIEscapeWriter (ADR 0080)")
	}
}

func TestLaurelQuoteMatchesLaurel(t *testing.T) {
	for _, c := range laurelCases {
		if got := laurelQuote([]byte(c.raw)); got != c.quoted {
			t.Errorf("laurelQuote(%q) = %q, Laurel writes %q", c.raw, got, c.quoted)
		}
		if got := laurelText(c.quoted); got != c.raw {
			t.Errorf("laurelText(%q) = %q, want %q", c.quoted, got, c.raw)
		}
	}
}

// A string without `%` is the common case on every leaf: it costs no allocation.
func TestLaurelTextWithoutPercentAllocatesNothing(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() { _ = laurelText("/usr/bin/date --date=now") }); n != 0 {
		t.Fatalf("laurelText allocates %v times on a string without %%", n)
	}
}

// What Laurel cannot have written stays as the judge read it before ADR 0080.
func TestLaurelTextKeepsWhatLaurelDidNotWrite(t *testing.T) {
	for _, s := range []string{
		"%2B", "%2b%2F", "%2", "%", "a%zz", "%25+", "1+%25", "%41", "%e2%82%ac", "no escapes + here", "",
	} {
		if got := laurelText(s); got != s {
			t.Errorf("laurelText(%q) = %q, want it unchanged", s, got)
		}
	}
}

// T2's time-now tech-b and tech-a: ARGV as job-laurel.txt holds them (after the runner's \x quoting).
func TestLeafMatchesArgvAsTyped(t *testing.T) {
	awk := `BEGIN { print strftime("%25Y-%25m-%25d %25H:%25M:%25S %25Z", systime()) }`
	date := "%2b%25Y-%25m-%25d %25H:%25M:%25S %25Z"
	cases := []struct {
		leaf Leaf
		v    string
		want bool
	}{
		{Leaf{[]string{"EXECVE", "ARGV"}, OpEq, `BEGIN { print strftime("%Y-%m-%d %H:%M:%S %Z", systime()) }`}, awk, true},
		{Leaf{[]string{"EXECVE", "ARGV"}, OpEq, awk}, awk, false},
		{Leaf{[]string{"EXECVE", "ARGV"}, OpEq, "+%Y-%m-%d %H:%M:%S %Z"}, date, true},
		{Leaf{[]string{"EXECVE", "ARGV"}, OpContains, "strftime(\"%Y"}, awk, true},
		{Leaf{[]string{"EXECVE", "ARGV"}, OpContains, "%25Y"}, awk, false},
		{Leaf{[]string{"EXECVE", "ARGV"}, OpEq, "--date=now"}, "--date=now", true},
		{Leaf{[]string{"EXECVE", "ARGV"}, OpEq, "%25"}, "%2525", true}, // decoded once, not twice
		{Leaf{[]string{"EXECVE", "ARGV"}, OpEq, "%"}, "%2525", false},
	}
	for _, c := range cases {
		if got := c.leaf.test(c.v); got != c.want {
			t.Errorf("%s %q on %q = %v, want %v", c.leaf.Op, c.leaf.Value, c.v, got, c.want)
		}
	}
}

func FuzzLaurelRoundTrip(f *testing.F) {
	for _, c := range laurelCases {
		f.Add([]byte(c.raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		q := laurelQuote(raw)
		if got := laurelText(q); !bytes.Equal([]byte(got), raw) {
			t.Fatalf("laurelText(laurelQuote(%q)) = %q", raw, got)
		}
		// whatever string a record holds, decoding never changes one Laurel could not have written
		if s := string(raw); laurelText(s) != s && laurelQuote([]byte(laurelText(s))) != s {
			t.Fatalf("laurelText(%q) changed a string Laurel did not write", s)
		}
	})
}
