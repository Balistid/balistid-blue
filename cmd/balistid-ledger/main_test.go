package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/anchor"
	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/cosign/cosigntest"
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
	if err := serve(t.TempDir(), filepath.Join(t.TempDir(), "s"), filepath.Join(t.TempDir(), "c"), "", anchor.Relay{}, nil); err == nil {
		t.Fatal("served without a key")
	}
}

func TestAskRefusesItsFlags(t *testing.T) {
	for _, c := range [][2]string{{"shutdown", "balistid.test/next"}, {"reboot", ""}} {
		if err := ask(filepath.Join(t.TempDir(), "c"), c[0], c[1], t.TempDir(), "", anchor.Relay{}); err == nil {
			t.Errorf("-announce %q -final %q asked", c[0], c[1])
		}
	}
}

// ask ends the log, waits for the witness and saves the cosigned final with the key beside the log.
func TestAskSavesTheCosignedFinal(t *testing.T) {
	f := cosigntest.New(t)
	dir, run := t.TempDir(), t.TempDir()
	l, err := anchor.Open(t.Context(), anchor.Config{Dir: dir, Signer: f.Log, CapBytes: 1 << 30,
		CheckpointInterval: 100 * time.Millisecond, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close(t.Context()) //nolint:errcheck // test end
	ln, err := listen(filepath.Join(run, "ledger.sock"), 0o666)
	if errors.Is(err, syscall.EPERM) && os.Getenv("CI") != "true" {
		t.Skipf("unix sockets denied here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(run, "control.sock")
	ctl, err := listen(control, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- anchor.Serve(ctx, ln, anchor.Control{Listener: ctl, UID: os.Getuid()}, l, -1, anchor.Relay{}, slog.New(slog.DiscardHandler))
	}()
	defer func() { cancel(); <-done }()
	relay := anchor.Relay{Path: filepath.Join(run, cosign.Name), Keys: f.Keys}
	note := f.Cosigned(t, 1, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)) // the final is the empty log's first entry
	logKey := filepath.Join(run, "ledger-key.pub")
	if err := errors.Join(os.WriteFile(relay.Path, note, 0o600), os.WriteFile(logKey, []byte("the verifier key\n"), 0o600)); err != nil {
		t.Fatal(err)
	}
	if err := ask(control, "", "balistid.test/next", dir, logKey, relay); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{finalCosignedName: note, finalKeyName: []byte("the verifier key\n")} {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(got, want) { //nolint:gosec // the test's own directory
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	if !l.Ended() {
		t.Fatal("the log did not end")
	}
}
