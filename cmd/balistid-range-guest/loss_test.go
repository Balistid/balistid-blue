package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The queue trial's burst overfills the queue the range's drop-in sets at least twice, and in its worst case of
// kernel records still fits auditd's plugin queue: only the collector's stage can lose (ADR 0039, point 2).
func TestQueueBurstFillsOnlyTheCollectorsQueue(t *testing.T) {
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
	// every chunk of every argument in a record of its own, and a SYSCALL, CWD, two PATH, PROCTITLE and EOE
	perExec := bigArgs*(bigArg/execveChunk+1) + 6
	if got := queueExecs * bigArgs * bigArg; got < 2*queue {
		t.Errorf("%d execs carry %d bytes, under twice the range's queue of %d", queueExecs, got, queue)
	}
	if got := queueExecs * perExec; got >= qDepth {
		t.Errorf("%d execs make up to %d kernel records, auditd's plugin queue holds %d", queueExecs, got, qDepth)
	}
}
