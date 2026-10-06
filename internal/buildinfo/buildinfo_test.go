package buildinfo

import "testing"

func TestStringNamesTheVersion(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v0.1.0"
	if got, want := String(), "balistid v0.1.0"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestCommitIsOnlyAFullCommitID(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	id := "0123456789abcdef0123456789abcdef01234567"
	for _, v := range []string{"dev", "", "v0.1.0", id[:39], id + "0", "0123456789ABCDEF0123456789abcdef01234567", " " + id[1:]} {
		Version = v
		if got, err := Commit(); err == nil {
			t.Errorf("Commit() with Version %q = %q", v, got)
		}
	}
	Version = id
	if got, err := Commit(); err != nil || got != id {
		t.Fatalf("Commit() = %q, %v", got, err)
	}
}
