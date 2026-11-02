package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The queue trial's burst overfills the queue the range's drop-in sets at least twice and, an argument per record
// at most, fits auditd's plugin queue: only the collector's stage can lose. The crash trial's flood passes it at a
// record per execveChunk bytes at least (ADR 0039, points 2 and 5).
func TestBurstsAgainstTheQueues(t *testing.T) {
	number := func(path, pattern string) int {
		data, err := os.ReadFile(path) //nolint:gosec // the repo's own files, named below
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(pattern).FindSubmatch(data)
		if m == nil {
			t.Fatalf("no %s in %s", pattern, path)
		}
		n, err := strconv.Atoi(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	queue := number("../../range/balistid-collector-range.conf", `(?m)^ExecStart=/\S+ .*-queue-bytes (\d+)`)
	qDepth := number("../../deploy/auditd/auditd.conf", `(?m)^q_depth = (\d+)$`)
	// the arguments' records, and at most SYSCALL, EXECVE's argc, CWD, two PATH, PROCTITLE and EOE beside them
	most, least := bigArgs+7, (bigArgs*bigArg+execveChunk-1)/execveChunk
	switch {
	case bigArg >= execveChunk:
		t.Errorf("an argument of %d bytes, the kernel splits it from %d", bigArg, execveChunk)
	case queueExecs*bigArgs*bigArg < 2*queue:
		t.Errorf("%d execs carry %d bytes, under twice the range's queue of %d", queueExecs, queueExecs*bigArgs*bigArg, queue)
	case queueExecs*most >= qDepth:
		t.Errorf("%d execs make up to %d kernel records, auditd's plugin queue holds %d", queueExecs, queueExecs*most, qDepth)
	case crashExecs*least <= qDepth:
		t.Errorf("%d execs make at least %d kernel records, not past auditd's plugin queue of %d", crashExecs, crashExecs*least, qDepth)
	}
}
