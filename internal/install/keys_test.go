package install

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sshKeygen = "/usr/bin/ssh-keygen"

// key is a software signing key made at test runtime in a temp directory; nothing secret is committed. A
// missing ssh-keygen fails the test: the refusals it proves must not turn into skips.
type key struct {
	path    string
	signers []byte // its allowed_signers line, of the type the tests' config accepts
}

func newKey(t *testing.T) key {
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
	return key{path: path, signers: []byte(Principal + ` namespaces="` + Namespace + `" ` + f[0] + " " + f[1] + "\n")}
}

// fingerprint is the key's fingerprint as ssh-keygen prints it.
func (k key) fingerprint(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), sshKeygen, "-l", "-f", k.path+".pub").Output() //nolint:gosec // fixed binary, test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))[1]
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
