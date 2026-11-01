package main

import "testing"

// Laurel's CPU is utime plus stime at USER_HZ 100 and its start time names the process; a name with
// spaces or a parenthesis cannot shift the fields, and a line that is not a stat line is refused.
func TestProcCPU(t *testing.T) {
	tail := " S 1 2 2 0 -1 4194560 100 0 0 0 1234 567 0 0 20 0 3 0 8812 0 0"
	for _, name := range []string{"(laurel)", "(a b) ) c)"} {
		usec, start, err := procCPU("4242 " + name + tail)
		if err != nil || usec != (1234+567)*10_000 || start != "8812" {
			t.Errorf("%s: %d %q %v", name, usec, start, err)
		}
	}
	for _, bad := range []string{
		"", "4242 laurel" + tail, "4242 (laurel) S 1 2", "4242 (laurel)" + " S 1 2 2 0 -1 4194560 100 0 0 0 x 567 0 0 20 0 3 0 8812",
		"4242 (laurel)" + " S 1 2 2 0 -1 4194560 100 0 0 0 922337203685478 567 0 0 20 0 3 0 8812",
		"4242 (laurel)" + " S 1 2 2 0 -1 4194560 100 0 0 0 -1 567 0 0 20 0 3 0 8812",
	} {
		if _, _, err := procCPU(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}
