package main

import (
	"context"
	"testing"
	"time"
)

// The Pi fact's waits end with the self-test's context, not only with their own deadline.
func TestPauseEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	if pause(ctx, time.Minute) || time.Since(start) > time.Second {
		t.Fatal("a cancelled pause waited")
	}
	if !pause(t.Context(), time.Millisecond) {
		t.Fatal("a pause that ran out reported cancelled")
	}
}
