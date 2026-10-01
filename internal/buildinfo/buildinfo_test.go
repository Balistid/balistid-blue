package buildinfo

import "testing"

func TestStringNamesTheVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v0.1.0"
	if got, want := String(), "kordon v0.1.0"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
