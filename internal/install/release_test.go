package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// What tools/ci/release.py writes is what the installer reads: a release it makes and the maintainer signs installs.
func TestRunnerInstallsWhatReleasePyWrites(t *testing.T) {
	h, s := newRunnerHost(t)
	in := t.TempDir()
	deploy := filepath.Join(in, "deploy")
	must(t, os.Mkdir(deploy, 0o700))
	for _, f := range runnerTable {
		p := filepath.Join(deploy, f.name)
		switch f.name {
		case "balistid-runner", "balistid-install":
			p = filepath.Join(in, f.name)
		case signersName:
			p = filepath.Join(in, signersName)
			must(t, os.WriteFile(p, h.key.signers, 0o600))
			continue
		case "tmpfiles.conf":
			must(t, os.WriteFile(p, deployTmpfiles, 0o600))
			continue
		}
		must(t, os.WriteFile(p, []byte(f.name+" from release.py\n"), 0o600))
	}
	files := filepath.Join(t.TempDir(), "files")
	release := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "/usr/bin/python3", append([]string{"../../tools/ci/release.py"}, args...)...) //nolint:gosec // the repository's own script
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("release.py %v: %v: %s", args, err, out)
		}
	}
	release("manifest", "--binary", filepath.Join(in, "balistid-runner"), "--installer", filepath.Join(in, "balistid-install"),
		"--deploy", deploy, "--signers", filepath.Join(in, signersName), "--commit", testCommit, "--out", files)
	must(t, os.Remove(filepath.Join(h.dir, bundleName)))
	release("bundle", "--dir", files, "--out", filepath.Join(h.dir, bundleName))
	m, err := os.ReadFile(filepath.Join(files, manifestName)) //nolint:gosec // test temp dir
	must(t, err)
	must(t, os.WriteFile(filepath.Join(h.dir, sigName), h.key.sign(t, m, Namespace), 0o600)) //nolint:gosec // test temp dir
	if err := h.install(t, s, maint, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.cmds, wantCmds) {
		t.Fatalf("ran %q", s.cmds)
	}
	got, err := os.ReadFile(filepath.Join(h.cfg.Root, "etc/sysusers.d/balistid-runner.conf"))
	if err != nil || string(got) != "sysusers.conf from release.py\n" {
		t.Fatalf("%q, %v", got, err)
	}
}
