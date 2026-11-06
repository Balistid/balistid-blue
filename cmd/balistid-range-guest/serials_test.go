package main

import (
	"slices"
	"testing"
)

// A scan counts the kernel's serials apart from auditd's own, names each gap with the events around it and
// bounds what it shows.
func TestSerialScanFindsGaps(t *testing.T) {
	lines := []byte(`{"ID":"1730000000.123:10","SYSCALL":{},"EXECVE":{},"PROCTITLE":{}}
{"ID":"1730000000.124:11","SYSCALL":{},"PATH":[]}
{"ID":"1730000000.125:14","CONFIG_CHANGE":{}}
{"ID":"1730000000.125:14","CONFIG_CHANGE":{}}
{"ID":"1730000000.126:3","DAEMON_START":{}}
not json
{"ID":"1730000000.5:20","SYSCALL":{}}
{"ID":"1730000000.127:17","SYSCALL":{}}
`)
	got := scanLines(lines).report("t", 1)
	want := []string{
		"serials: t: lines=8 events=4 daemon=1 unparsed=2 repeated=1 first=10 last=17 missing=4",
		"serials: t: gap 12-13 (2) after PATH+SYSCALL before CONFIG_CHANGE",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("report:\n%q\nwant\n%q", got, want)
	}
	if n := len(scanLines(lines).report("t", 30)); n != 3 {
		t.Fatalf("%d lines with every gap, want the summary and 2", n)
	}
	if got := newSerialScan().report("empty", 30); !slices.Equal(got, []string{
		"serials: empty: lines=0 events=0 daemon=0 unparsed=0 repeated=0 first=0 last=0 missing=0"}) {
		t.Fatalf("empty: %q", got)
	}
}
