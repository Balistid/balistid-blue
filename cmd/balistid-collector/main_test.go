package main

import (
	"testing"
)

func TestFailedOpenIsANilStore(t *testing.T) {
	st, err := openStore("/nonexistent/balistid/store")(t.Context())
	if err == nil || st != nil {
		t.Fatalf("Open of a missing directory = %v, %v; want a nil Store and an error", st, err)
	}
}

func TestOpenStoreOnAFreshDirectory(t *testing.T) {
	st, err := openStore(t.TempDir())(t.Context())
	if err != nil || st == nil || st.Health() != "" {
		t.Fatalf("Open = %v, %v", st, err)
	}
	if _, err := st.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
