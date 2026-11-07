package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// publishFromReleasePy writes stand-ins for c's binaries and deploy files where tools/ci/release.py reads them,
// lets it write the MANIFEST and the bundle into the release directory and signs the MANIFEST with the installed key.
// sources are the repository paths release.py takes c's deploy files from, by table name.
func publishFromReleasePy(t *testing.T, h *fakeHost, c component, sources map[string]string, real map[string][]byte) {
	t.Helper()
	in := t.TempDir()
	bin, tree := filepath.Join(in, "bin"), filepath.Join(in, "tree")
	must(t, os.Mkdir(bin, 0o700))
	for _, f := range c.table {
		data := []byte(f.name + " from release.py\n")
		if b, ok := real[f.name]; ok {
			data = b
		}
		p := filepath.Join(bin, f.name)
		switch {
		case f.name == signersName:
			p, data = filepath.Join(in, signersName), h.key.signers
		case sources[f.name] != "":
			p = filepath.Join(tree, sources[f.name])
			must(t, os.MkdirAll(filepath.Dir(p), 0o700))
		}
		must(t, os.WriteFile(p, data, 0o600))
	}
	files := filepath.Join(t.TempDir(), "files")
	release := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "/usr/bin/python3", append([]string{"../../tools/ci/release.py"}, args...)...) //nolint:gosec // the repository's own script
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("release.py %v: %v: %s", args, err, out)
		}
	}
	release("manifest", "--component", c.name, "--bin", bin, "--tree", tree, "--signers", filepath.Join(in, signersName),
		"--commit", testCommit, "--out", files)
	_ = os.Remove(filepath.Join(h.dir, c.bundle()))
	release("bundle", "--dir", files, "--out", filepath.Join(h.dir, c.bundle()))
	m, err := os.ReadFile(filepath.Join(files, manifestName)) //nolint:gosec // test temp dir
	must(t, err)
	must(t, os.WriteFile(filepath.Join(h.dir, sigName), h.key.sign(t, m, Namespace), 0o600)) //nolint:gosec // test temp dir
}

// What tools/ci/release.py writes is what the installer reads: a release it makes and the maintainer signs installs.
func TestRunnerInstallsWhatReleasePyWrites(t *testing.T) {
	h, s := newRunnerHost(t)
	sources := map[string]string{}
	for _, name := range []string{"balistid-runner-build.service", "balistid-runner-tick.service",
		"balistid-runner-tick.timer", "sysusers.conf", "tmpfiles.conf"} {
		sources[name] = "deploy/runner/" + name
	}
	publishFromReleasePy(t, h, runnerComponent, sources, map[string][]byte{"tmpfiles.conf": deployTmpfiles})
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

func TestRecorderInstallsWhatReleasePyWrites(t *testing.T) {
	h, s, real := newRecorderHost(t)
	sources := map[string]string{
		"balistid-collector.service": "deploy/collector/balistid-collector.service",
		"balistid-collector.socket":  "deploy/collector/balistid-collector.socket",
		"balistid-ledger.service":    "deploy/ledger/balistid-ledger.service",
		"balistid-auditstat.service": "deploy/auditstat/balistid-auditstat.service",
		"collector-sysusers.conf":    "deploy/collector/sysusers.conf",
		"ledger-sysusers.conf":       "deploy/ledger/sysusers.conf",
		"auditstat-sysusers.conf":    "deploy/auditstat/sysusers.conf",
		"collector-tmpfiles.conf":    "deploy/collector/tmpfiles.conf",
		"ledger-tmpfiles.conf":       "deploy/ledger/tmpfiles.conf",
		"balistid.rules":             "deploy/audit/balistid.rules",
		"auditd.conf":                "deploy/auditd/auditd.conf",
		"laurel-plugin.conf":         "deploy/auditd/laurel-plugin.conf",
		"laurel-config.toml":         "deploy/laurel/config.toml",
		"sysctl.conf":                "deploy/sysctl/balistid.conf",
	}
	tmpfiles := map[string][]byte{"collector-tmpfiles.conf": real["collector-tmpfiles.conf"],
		"ledger-tmpfiles.conf": real["ledger-tmpfiles.conf"]}
	publishFromReleasePy(t, h, recorderComponent, sources, tmpfiles)
	if err := h.installRecorder(t, s, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.cmds, wantRecorderCmds) {
		t.Fatalf("ran %q", s.cmds)
	}
	got, err := os.ReadFile(filepath.Join(h.cfg.Root, "etc/sysctl.d/90-balistid.conf"))
	if err != nil || string(got) != "sysctl.conf from release.py\n" {
		t.Fatalf("%q, %v", got, err)
	}
}
