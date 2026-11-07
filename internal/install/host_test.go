package install

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

// fakeHost is a root directory standing in for "/", owned by the test's uid, with an installed allowed_signers of
// a runtime key, and a release directory the maintainer downloaded into.
type fakeHost struct {
	cfg    Config
	dir    string
	key    key
	bundle string // the bundle's file name, the runner's unless a test sets another
}

func newHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{dir: t.TempDir(), key: newKey(t), bundle: runnerComponent.bundle()}
	h.cfg = Config{Root: t.TempDir(), UID: os.Getuid(), GID: os.Getgid(), SSHKeygen: sshKeygen,
		VerifyTimeout: 10 * time.Second}
	h.mkdir(t, "etc/balistid", 0o755)
	h.put(t, "etc/balistid/allowed_signers", h.key.signers, 0o644)
	return h
}

// mkdir makes name, with mode whatever the umask, and its missing parents in the fake root.
func (h *fakeHost) mkdir(t *testing.T, name string, mode fs.FileMode) {
	t.Helper()
	p := filepath.Join(h.cfg.Root, name)
	if err := os.MkdirAll(p, 0o755); err != nil { //nolint:gosec // root's directories are 0755
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func (h *fakeHost) put(t *testing.T, name string, data []byte, mode fs.FileMode) {
	t.Helper()
	p := filepath.Join(h.cfg.Root, name)
	if err := os.WriteFile(p, data, mode); err != nil { //nolint:gosec,nolintlint // test temp dir; nolintlint misses gosec's G703 taint finding here
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// sign signs data in namespace as `ssh-keygen -Y sign` does for the maintainer, touch and PIN given.
func (k key) sign(t *testing.T, data []byte, namespace string) []byte {
	t.Helper()
	return k.sk.sign(data, namespace, skPresence|skVerified)
}

// manifestOf is the MANIFEST CI writes for files of the runner.
func manifestOf(files map[string][]byte) []byte { return manifestFor("runner", files) }

// manifestFor is the MANIFEST CI writes for files of the named component.
func manifestFor(component string, files map[string][]byte) []byte {
	m := Manifest{Component: component, Commit: testCommit}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		m.Files = append(m.Files, File{Name: name, SHA256: sha256.Sum256(files[name])})
	}
	return manifestText(m)
}

// runnerFiles is a release of the runner component as release.py bundles it, with signers as its allowed_signers.
func runnerFiles(signers []byte) map[string][]byte {
	files := map[string][]byte{"allowed_signers": signers, "tmpfiles.conf": deployTmpfiles}
	for _, name := range []string{"balistid-runner", "balistid-install", "balistid-runner-build.service",
		"balistid-runner-tick.service", "balistid-runner-tick.timer", "sysusers.conf"} {
		files[name] = []byte(name + " of the release\n")
	}
	return files
}

// deployTmpfiles is the runner's real tmpfiles.conf: the installer checks the directories it names.
var deployTmpfiles = func() []byte {
	b, err := os.ReadFile("../../deploy/runner/tmpfiles.conf")
	if err != nil {
		panic(err)
	}
	return b
}()

// publish writes the bundle of files with manifest, and sig unless it is nil, into the release directory.
func (h *fakeHost) publish(t *testing.T, files map[string][]byte, manifest, sig []byte) {
	t.Helper()
	entries := []entry{{name: "MANIFEST", data: string(manifest)}}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		entries = append(entries, entry{name: name, data: string(files[name])})
	}
	if err := os.WriteFile(filepath.Join(h.dir, h.bundle), tarOf(t, entries...), 0o600); err != nil {
		t.Fatal(err)
	}
	if sig != nil {
		if err := os.WriteFile(filepath.Join(h.dir, sigName), sig, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// release publishes the runner's files signed by the installed key and returns them.
func (h *fakeHost) release(t *testing.T) map[string][]byte {
	t.Helper()
	files := runnerFiles(h.key.signers)
	m := manifestOf(files)
	h.publish(t, files, m, h.key.sign(t, m, Namespace))
	return files
}

// snapshot is every path under root, link or not, with its type, mode, owner and sha256 or link target.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil && d != nil && d.IsDir() {
			return fs.SkipDir // a directory a test made unreadable: its own entry is already recorded
		}
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		what := ""
		switch {
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p) //nolint:gosec // test temp dir
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			what = hex.EncodeToString(sum[:])
		case fi.Mode()&fs.ModeSymlink != 0:
			if what, err = os.Readlink(p); err != nil {
				return err
			}
		}
		out[p] = fmt.Sprintf("%v %d:%d %s", fi.Mode(), st.Uid, st.Gid, what)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// unchanged fails the test unless root is exactly as before.
func unchanged(t *testing.T, label, root string, before map[string]string) {
	t.Helper()
	if after := snapshot(t, root); !maps.Equal(before, after) {
		t.Errorf("%s: the root changed:\nbefore %v\nafter  %v", label, before, after)
	}
}
