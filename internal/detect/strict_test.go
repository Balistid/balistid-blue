package detect

import (
	"encoding/json"
	"testing"
)

func TestStrictDecode(t *testing.T) {
	for _, c := range []struct {
		in      string
		sameDup bool
		ok      bool
	}{
		{`{"a":1}`, false, true},
		{` {"a":1} `, false, true},
		{`{"a":1}{"b":2}`, false, false},
		{`{"a":1} 2`, false, false},
		{`{"a":1,"a":1}`, false, false},
		{`{"a":1,"a":1}`, true, true},
		{`{"a":1,"a":2}`, true, false},
		{`{"a":{"b":[1,"x"]},"a":{"b":[1,"x"]}}`, true, true},
		{`{"a":{"b":[1,"x"]},"a":{"b":[1,"y"]}}`, true, false},
		{`{"a":{"b":1},"a":{"c":1}}`, true, false},
		{`{"a":{"b":1},"a":{"b":1,"c":1}}`, true, false},
		{`{"a":[1],"a":[1,2]}`, true, false},
		{`{"a":[1],"a":{"0":1}}`, true, false},
		{`{"a":null,"a":false}`, true, false},
		{`{"a":true,"a":false}`, true, false},
		{`{"a":true,"a":true}`, true, true},
		{`{"a":null,"a":null}`, true, true},
		{`{"a":"x","a":1}`, true, false},
		{`{"a":1,"a":"1"}`, true, false},
		{"{\"a\":\"\xff\"}", false, false},
		{`[1,`, false, false},
		{``, false, false},
	} {
		_, err := decode([]byte(c.in), c.sameDup)
		if (err == nil) != c.ok {
			t.Errorf("decode(%q, %v): err %v, want ok %v", c.in, c.sameDup, err, c.ok)
		}
	}
	v, err := decode([]byte(`{"a":[1,"x",true,null,{"b":2}]}`), false)
	if err != nil {
		t.Fatal(err)
	}
	list := v.(object)["a"].([]any)
	if list[0].(json.Number) != "1" || list[1].(string) != "x" || list[2].(bool) != true || list[3] != nil || list[4].(object)["b"].(json.Number) != "2" {
		t.Fatalf("decoded %#v", v)
	}
}

func TestIntegers(t *testing.T) {
	for _, c := range []struct {
		in       string
		own, rec bool
		want     int64
	}{
		{"0", true, true, 0},
		{"-0", false, true, 0},
		{"970", true, true, 970},
		{"-5", true, true, -5},
		{"1.0", false, false, 0},
		{"1e3", false, false, 0},
		{"9223372036854775808", false, false, 0},
	} {
		got, ok := asInt(json.Number(c.in))
		if ok != c.own || (ok && got != c.want) {
			t.Errorf("asInt(%s) = %d %v", c.in, got, ok)
		}
		got, ok = eventInt(json.Number(c.in))
		if ok != c.rec || (ok && got != c.want) {
			t.Errorf("eventInt(%s) = %d %v", c.in, got, ok)
		}
	}
	if _, ok := asInt("1"); ok {
		t.Error("a string is an integer")
	}
	if _, ok := eventInt("1"); ok {
		t.Error("a string is a record's integer")
	}
}

func TestFieldsAndPlainText(t *testing.T) {
	o := object{"a": "x", "b": json.Number("1")}
	if _, err := fields(o, []string{"a"}, []string{"b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fields(o, []string{"a", "c"}, []string{"b"}); err == nil {
		t.Error("a missing key passed")
	}
	if _, err := fields(o, []string{"a"}, nil); err == nil {
		t.Error("a key outside the set passed")
	}
	if _, err := fields([]any{}, nil, nil); err == nil {
		t.Error("a list passed as an object")
	}
	if s, ok := str(o, "a"); !ok || s != "x" {
		t.Error("str")
	}
	if _, ok := str(o, "b"); ok {
		t.Error("a number passed as a string")
	}
	for in, want := range map[string]bool{"a b\n~": true, "\r\n": false, "\t": false, "\x7f": false, "é": false, "": true} {
		if plainText([]byte(in)) != want {
			t.Errorf("plainText(%q) != %v", in, want)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"a":1,"a":1}`), true)
	f.Add([]byte(`{"a":[1,{"b":null}]}`), false)
	f.Add(baseRecords(f), true)
	f.Fuzz(func(t *testing.T, data []byte, sameDup bool) {
		v, err := decode(data, sameDup)
		if err != nil {
			return
		}
		if !json.Valid(data) {
			t.Fatal("decoded what is not valid JSON")
		}
		if !same(v, v) {
			t.Fatal("a decoded value is not the same as itself")
		}
	})
}
