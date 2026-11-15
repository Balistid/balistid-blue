package install

import (
	"crypto/sha256"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// publishRelease replaces the host's bundle with a v2 release of the named component, signed by the installed key.
func publishRelease(t *testing.T, h *fakeHost, c component, files map[string][]byte, n uint64) []byte {
	t.Helper()
	_ = os.Remove(filepath.Join(h.dir, h.bundle))
	h.bundle = c.bundle()
	m := Manifest{Component: c.name, Commit: testCommit, Release: n}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		m.Files = append(m.Files, File{Name: name, SHA256: sha256.Sum256(files[name])})
	}
	text := manifestText(m)
	h.publish(t, files, text, h.key.sign(t, text, Namespace))
	return text
}

func keptText(n uint64, manifest []byte) string {
	return fmt.Sprintf("release %d\nmanifest %x\n", n, sha256.Sum256(manifest))
}

// A v2 release is kept after the installer is written; an older one, a v1 one and the same number from another
// MANIFEST are refused, by the dry run too; the same release again and a newer one install.
func TestAnInstalledReleaseRefusesAnOlderOne(t *testing.T) {
	h, s := newRunnerHost(t)
	files := judgeFiles(h.key.signers)
	m := publishRelease(t, h, judgeComponent, files, 900)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, h, "etc/balistid/judge.release"); string(got) != keptText(900, m) {
		t.Fatalf("kept %q", got)
	}
	if fi, err := os.Lstat(filepath.Join(h.cfg.Root, "etc/balistid/judge.release")); err != nil || fi.Mode() != 0o644 {
		t.Fatalf("%v, %v", fi, err)
	}

	publishRelease(t, h, judgeComponent, files, 899)
	if _, err := Check(t.Context(), h.cfg, "judge", h.dir, ""); err == nil {
		t.Error("the dry run verified an older release")
	}
	h.refusedJudge(t, s, "older", "release 899 is older than the judge's installed release 900")
	publishJudge(t, h)
	h.refusedJudge(t, s, "v1", "release 0 is older than the judge's installed release 900")
	other := judgeFiles(h.key.signers)
	other["balistid-judge"] = []byte("another judge\n")
	publishRelease(t, h, judgeComponent, other, 900)
	h.refusedJudge(t, s, "same number, other manifest", "release 900 is installed from another MANIFEST")

	publishRelease(t, h, judgeComponent, files, 900)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatalf("the same release again: %v", err)
	}
	m = publishRelease(t, h, judgeComponent, other, 901)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatalf("a newer release: %v", err)
	}
	if got := readFile(t, h, "etc/balistid/judge.release"); string(got) != keptText(901, m) {
		t.Fatalf("kept %q", got)
	}
}

// Every component writes the shared installer, so a release older than another component's kept one is refused.
func TestAReleaseOlderThanAnotherComponentsIsRefused(t *testing.T) {
	h, s := newRunnerHost(t)
	h.put(t, "etc/balistid/recorder.release", []byte(keptText(900, []byte("the recorder's manifest"))), 0o644)
	publishRelease(t, h, judgeComponent, judgeFiles(h.key.signers), 899)
	h.refusedJudge(t, s, "older than the recorder", "release 899 is older than the recorder's installed release 900")
	publishRelease(t, h, judgeComponent, judgeFiles(h.key.signers), 900)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatalf("the recorder's release number: %v", err)
	}
}

// A kept release that is not root's plain 0644 file in the exact form refuses: missing is not healthy (R6).
func TestAKeptReleaseNotInItsFormRefuses(t *testing.T) {
	good := keptText(900, []byte("m"))
	for label, c := range map[string]struct {
		data string
		mode os.FileMode
		link bool
		want string
	}{
		"group writable": {good, 0o664, false, "judge.release"},
		"a symlink":      {good, 0o644, true, "judge.release"},
		"no newline":     {good[:len(good)-1], 0o644, false, "not a release and a manifest sha256"},
		"release 0":      {keptText(0, []byte("m")), 0o644, false, "not a release and a manifest sha256"},
		"a short sha256": {good[:len(good)-3] + "\n", 0o644, false, "not a release and a manifest sha256"},
		"empty":          {"", 0o644, false, "not a release and a manifest sha256"},
	} {
		h, s := newRunnerHost(t)
		if c.link {
			h.put(t, "etc/balistid/elsewhere", []byte(c.data), c.mode)
			h.symlink(t, "elsewhere", "etc/balistid/judge.release")
		} else {
			h.put(t, "etc/balistid/judge.release", []byte(c.data), c.mode)
		}
		publishRelease(t, h, judgeComponent, judgeFiles(h.key.signers), 901)
		h.refusedJudge(t, s, label, c.want)
	}
}

// A stop before the installer is written keeps the old number, so the same release installs again.
func TestAStoppedInstallKeepsTheOldRelease(t *testing.T) {
	h, s := newRunnerHost(t)
	files := judgeFiles(h.key.signers)
	m := publishRelease(t, h, judgeComponent, files, 900)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatal(err)
	}
	publishRelease(t, h, judgeComponent, files, 901)
	s.failCmd = "systemctl"
	if err := h.installJudge(t, s, ""); err == nil {
		t.Fatal("the install did not stop")
	}
	if got := readFile(t, h, "etc/balistid/judge.release"); string(got) != keptText(900, m) {
		t.Fatalf("kept %q after a stop", got)
	}
	s.failCmd = ""
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatalf("the stopped release again: %v", err)
	}
}
