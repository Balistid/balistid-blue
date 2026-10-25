package main

import (
	"testing"
)

func TestFailedOpenIsANilStore(t *testing.T) {
	st, err := openStore("/nonexistent/balistid/store", headroom)(t.Context())
	if err == nil || st != nil {
		t.Fatalf("Open of a missing directory = %v, %v; want a nil Store and an error", st, err)
	}
}

func TestOpenStoreOnAFreshDirectory(t *testing.T) {
	st, err := openStore(t.TempDir(), headroom)(t.Context())
	if err != nil || st == nil || st.Health() != "" {
		t.Fatalf("Open = %v, %v", st, err)
	}
	if _, err := st.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The range image's -headroom (ADR 0022) opens a store, and one too small for a loss record does not.
func TestOpenStoreWithTheRangeHeadroom(t *testing.T) {
	st, err := openStore(t.TempDir(), 64<<20)(t.Context())
	if err != nil || st == nil || st.Health() != "" {
		t.Fatalf("Open with 64 MiB = %v, %v", st, err)
	}
	if _, err := st.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if st, err := openStore(t.TempDir(), 1<<20)(t.Context()); err == nil || st != nil {
		t.Fatalf("Open with 1 MiB = %v, %v; want a refusal", st, err)
	}
}
