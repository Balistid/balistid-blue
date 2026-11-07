package install

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sshKeygen = "/usr/bin/ssh-keygen"

// key is a software sk-ssh-ed25519 key made at test runtime (nothing secret is committed). It signs with the touch and
// PIN flags set, and the real ssh-keygen verifies and fingerprints it; a missing ssh-keygen fails the test.
type key struct {
	sk      skKey
	signers []byte
}

func newKey(t *testing.T) key {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	k := skKeyFromSeed(seed)
	return key{sk: k, signers: k.signers()}
}

// fingerprint is the key's fingerprint as ssh-keygen prints it.
func (k key) fingerprint(t *testing.T) string {
	t.Helper()
	pub := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(pub, []byte(SKKeyType+" "+base64.StdEncoding.EncodeToString(k.sk.blob)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), sshKeygen, "-l", "-f", pub).Output() //nolint:gosec // fixed binary, test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))[1]
}

// plainSigners is the allowed_signers line of a plain ssh-ed25519 key ssh-keygen made: not the token's type.
func plainSigners(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k")
	if out, err := exec.CommandContext(t.Context(), sshKeygen, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path).CombinedOutput(); err != nil { //nolint:gosec // fixed binary, test temp dir
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	pub, err := os.ReadFile(path + ".pub") //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(pub))
	return []byte(Principal + ` namespaces="` + Namespace + `" ` + f[0] + " " + f[1] + "\n")
}

type entry struct {
	name, data, link string
	typeflag         byte
}

// tarOf writes entries as a tar; a zero typeflag is a regular file.
func tarOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: e.typeflag, Linkname: e.link}
		if e.typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		} else {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.data)); hdr.Typeflag == tar.TypeReg && err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
