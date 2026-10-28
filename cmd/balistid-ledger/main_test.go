package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func keyFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	skey, _, err := note.GenerateKey(rand.Reader, "balistid.test/log")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ledger-key")
	if err := os.WriteFile(path, []byte(skey+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // past the umask
		t.Fatal(err)
	}
	return path
}

func TestReadSignerTakesAKeyOnlyItsOwnerReads(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		s, err := readSigner(keyFile(t, mode), "")
		if err != nil || s.Name() != "balistid.test/log" {
			t.Fatalf("mode %v: %v, %v", mode, s, err)
		}
	}
}

// 0440 is how a systemd credential looks: 0400 with an ACL for the service's uid, its mask in the group
// bits. Only there does group read pass.
func TestReadSignerTakesGroupReadOnlyAsACredential(t *testing.T) {
	path := keyFile(t, 0o440)
	if s, err := readSigner(path, filepath.Dir(path)); err != nil || s.Name() != "balistid.test/log" {
		t.Fatalf("credential: %v, %v", s, err)
	}
	if s, err := readSigner(path, ""); err == nil {
		t.Fatalf("group-readable key outside the credentials directory: %v", s.Name())
	}
	if s, err := readSigner(path, t.TempDir()); err == nil {
		t.Fatalf("group-readable key outside another credentials directory: %v", s.Name())
	}
}

func TestReadSignerRefuses(t *testing.T) {
	good := keyFile(t, 0o600)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(garbage, []byte("PRIVATE+KEY+not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	huge := filepath.Join(t.TempDir(), "huge")
	if err := os.WriteFile(huge, make([]byte, maxKeyBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"group-writable": keyFile(t, 0o660), "world-readable": keyFile(t, 0o604), "a symlink": link,
		"a directory": t.TempDir(), "missing": filepath.Join(t.TempDir(), "none"), "not a key": garbage, "too large": huge,
	} {
		if s, err := readSigner(path, filepath.Dir(path)); err == nil {
			t.Errorf("%s: signer %v", name, s.Name())
		} else if strings.Contains(err.Error(), "PRIVATE+KEY") {
			t.Errorf("%s: error quotes the key: %v", name, err)
		}
	}
}

func TestNoticesNameTheMPLModuleAndItsSource(t *testing.T) {
	for _, want := range []string{"github.com/hashicorp/golang-lru/v2 v2.0.7", "Mozilla Public License 2.0",
		"https://github.com/hashicorp/golang-lru/tree/v2.0.7"} {
		if !strings.Contains(notices, want) {
			t.Errorf("notices lack %q", want)
		}
	}
}

func TestServeWithoutAKeyFails(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if err := serve(t.TempDir(), filepath.Join(t.TempDir(), "s"), "", nil); err == nil {
		t.Fatal("served without a key")
	}
}
