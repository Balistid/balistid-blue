package rangejob

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode"
)

func TestParseRequestAccepts(t *testing.T) {
	cases := map[string]Request{
		`{"schema_version":1,"kind":"run","trials":1}`: {SchemaVersion: 1, Kind: KindRun, Trials: 1},
		`{"kind":"run","trials":3,"schema_version":1}`: {SchemaVersion: 1, Kind: KindRun, Trials: 3},
		` {"schema_version":1,"kind":"exec","program":"probe-1.sh","timeout_s":300} ` + "\n": {
			SchemaVersion: 1, Kind: KindExec, Program: "probe-1.sh", TimeoutS: 300,
		},
	}
	full := `{"schema_version":1,"kind":"run","trials":1}`
	cases[full+strings.Repeat(" ", MaxRequestBytes-len(full))] = Request{SchemaVersion: 1, Kind: KindRun, Trials: 1}
	for in, want := range cases {
		got, err := ParseRequest(strings.NewReader(in))
		if err != nil || got != want {
			t.Errorf("ParseRequest(%s) = %+v, %v; want %+v", in, got, err, want)
		}
	}
}

func TestParseRequestRejects(t *testing.T) {
	cases := []string{
		``,
		`[]`,
		`"run"`,
		`{}`,
		`{"schema_version":2,"kind":"run","trials":1}`,
		`{"schema_version":1,"kind":"scenario","trials":1}`,
		`{"schema_version":1,"kind":"run","trials":0}`,
		`{"schema_version":1,"kind":"run","trials":4}`,
		`{"schema_version":1,"kind":"run","trials":-1}`,
		`{"schema_version":1,"kind":"run","trials":1.5}`,
		`{"schema_version":1,"kind":"run","trials":"1"}`,
		`{"schema_version":1,"kind":"run","trials":null}`,
		`{"schema_version":1,"kind":"run","trials":true}`,
		`{"schema_version":1,"kind":"run"}`,
		`{"schema_version":1,"kind":"run","trials":1,"source":"maintainer"}`,
		`{"schema_version":1,"kind":"run","trials":1,"source":"timer"}`,
		`{"schema_version":1,"kind":"run","trials":1,"timeout_s":0}`,
		`{"schema_version":1,"kind":"run","trials":1,"program":""}`,
		`{"schema_version":1,"kind":"run","trials":1,"trials":2}`,
		`{"schema_version":1,"kind":"run","kind":"run","trials":1}`,
		`{"schema_version":1,"kind":"run","trials":1}{}`,
		`{"schema_version":1,"kind":"run","trials":1}x`,
		`{"schema_version":1,"kind":"run","trials":1,"x":{}}`,
		`{"schema_version":1,"kind":"run","trials":[1]}`,
		`{"schema_version":1,"kind":"exec","program":"p","timeout_s":0}`,
		`{"schema_version":1,"kind":"exec","program":"p","timeout_s":301}`,
		`{"schema_version":1,"kind":"exec","program":"p"}`,
		`{"schema_version":1,"kind":"exec","program":"p","timeout_s":10,"trials":1}`,
		`{"schema_version":1,"kind":"exec","program":"job.json","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":"../p","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":"a/b","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":".p","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":"-p","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":"p\u0000","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":"p\n","timeout_s":10}`,
		`{"schema_version":1,"kind":"exec","program":"` + strings.Repeat("p", 65) + `","timeout_s":10}`,
		`{"schema_version":1,"kind":"run","trials":1,"pad":"` + strings.Repeat(" ", MaxRequestBytes) + `"}`,
	}
	for _, in := range cases {
		if got, err := ParseRequest(strings.NewReader(in)); err == nil {
			t.Errorf("ParseRequest(%.80s) = %+v, want an error", in, got)
		}
	}
}

func TestParseRequestReadsAtMostTheCap(t *testing.T) {
	in := `{"schema_version":1,"kind":"run","trials":1}` + strings.Repeat(" ", 2*MaxRequestBytes)
	r := strings.NewReader(in)
	if _, err := ParseRequest(r); err == nil {
		t.Fatal("an over-cap request was accepted")
	}
	if read := len(in) - r.Len(); read != MaxRequestBytes+1 {
		t.Fatalf("ParseRequest read %d bytes, want exactly %d", read, MaxRequestBytes+1)
	}
}

func TestParseRequestErrorsDoNotQuoteTheRequest(t *testing.T) {
	marker := "IGNOREPREVIOUS"
	for _, in := range []string{
		`{"schema_version":1,"kind":"` + marker + `","trials":1}`,
		`{"schema_version":1,"kind":"run","trials":1,"` + marker + `":1}`,
		`{"schema_version":1,"kind":"run","trials":1,"x":{"` + marker + `":1}}`,
		`{"schema_version":1,"kind":"run","trials":"` + marker + `"}`,
		`{"schema_version":1,"kind":"run","trials":1}` + marker,
		`{"schema_version":1,"kind":"exec","program":"` + marker + `/x","timeout_s":1}`,
		`{"schema_version":1,"kind":"run","trials":1e` + marker + `}`,
		`{"schema_version":4242,"kind":"run","trials":1}`,
		`{"schema_version":1,"kind":"run","trials":4242.5}`,
	} {
		_, err := ParseRequest(strings.NewReader(in))
		if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "4242") {
			t.Errorf("ParseRequest(%s) error %v; want an error that does not quote the request", in, err)
		}
	}
}

func FuzzParseRequest(f *testing.F) {
	for _, s := range []string{
		`{"schema_version":1,"kind":"run","trials":2}`,
		`{"schema_version":1,"kind":"exec","program":"p","timeout_s":5}`,
		`{"schema_version":1,"kind":"run","trials":1,"trials":1}`,
		`{"schema_version":1,"kind":"exec","program":"job.json","timeout_s":5}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		req, err := ParseRequest(strings.NewReader(in))
		if err != nil {
			if strings.ContainsFunc(err.Error(), func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) }) {
				t.Fatalf("error text is not printable: %q", err.Error())
			}
			return
		}
		data, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseRequest(strings.NewReader(string(data)))
		if err != nil || again != req {
			t.Fatalf("accepted %q, but its re-encoding %s gives %+v, %v", in, data, again, err)
		}
	})
}
