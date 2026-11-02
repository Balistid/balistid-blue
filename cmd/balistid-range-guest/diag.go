package main

// Exp only, never merged: DIAG lines on the serial console for the queue trial's diagnosis.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

func diagClean(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("+/=_. -;:", c) >= 0) {
			b[i] = '_'
		}
	}
	return string(b[:min(len(b), 600)])
}

func diag(kind, s string) {
	at, _ := uptime()
	fmt.Printf("DIAG %s %d %s\n", kind, at.Milliseconds(), diagClean(s)) //nolint:forbidigo // exp only
}

// diagState prints auditd's plugin-queue lines and Laurel's state every 500 ms until the returned stop.
func diagState(ctx context.Context) func() {
	dctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for pause(dctx, 500*time.Millisecond) {
			data, _ := os.ReadFile(auditdState)
			var parts []string
			for line := range strings.Lines(string(data)) {
				if strings.Contains(line, "plugin queue") || strings.Contains(line, "plugin") {
					parts = append(parts, strings.TrimSpace(line))
				}
			}
			stat, _ := os.ReadFile("/proc/" + laurelPID() + "/stat")
			diag("state", strings.Join(parts, "; ")+" | laurel "+strings.TrimSpace(string(stat)))
		}
	}()
	return func() { stop(); <-done }
}

func diagFacts(facts []fact) {
	for _, f := range facts {
		diag("fact", f.name+"="+f.value)
	}
}
