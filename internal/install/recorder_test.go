package install

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const (
	bootedCmdline = "root=/dev/vda rw audit=1 audit_backlog_limit=65536 quiet\n"
	distroAuditd  = "log_file = /var/log/audit/audit.log\n"
)

// newRecorderHost is a fake host ready for the sensor: the directories and programs a host with audit, gawk and
// Laurel's package has, booted for audit, the maintainer's key installed and a signed recorder release downloaded.
func newRecorderHost(t *testing.T) (*fakeHost, *fakeSystem, map[string][]byte) {
	t.Helper()
	h, s := newRunnerHost(t)
	h.bundle = recorderComponent.bundle()
	for _, dir := range append(slices.Clone(recorderComponent.trusted), "usr/bin", "proc") {
		h.mkdir(t, dir, 0o755)
	}
	for _, p := range hostPrograms {
		h.put(t, p, []byte("#!/bin/sh\n"), 0o755)
	}
	h.put(t, "proc/cmdline", []byte(bootedCmdline), 0o644)
	h.put(t, auditdConf, []byte(distroAuditd), 0o640)
	files := recorderFiles(h.key.signers)
	m := manifestFor("recorder", files)
	h.publish(t, files, m, h.key.sign(t, m, Namespace))
	return h, s, files
}

// recorderFiles is a release of the recorder as release.py bundles it, with the real tmpfiles.conf files.
func recorderFiles(signers []byte) map[string][]byte {
	files := map[string][]byte{signersName: signers}
	for _, f := range recorderTable {
		if f.name != signersName {
			files[f.name] = []byte(f.name + " of the release\n")
		}
	}
	for name, src := range map[string]string{"collector-tmpfiles.conf": "collector", "ledger-tmpfiles.conf": "ledger"} {
		b, err := os.ReadFile("../../deploy/" + src + "/tmpfiles.conf") //nolint:gosec // the repository's own file
		if err != nil {
			panic(err)
		}
		files[name] = b
	}
	return files
}

func (h *fakeHost) installRecorder(t *testing.T, s *fakeSystem, fingerprint string) error {
	t.Helper()
	s.cmds, s.logs, s.reloaded, s.untouched = nil, nil, false, snapshot(t, h.cfg.Root)
	return Recorder(t.Context(), h.cfg, h.dir, fingerprint)
}

// refusedRecorder fails the test unless the run refused for want, left the root as it was, ran no command and
// logged exactly one refusal.
func (h *fakeHost) refusedRecorder(t *testing.T, s *fakeSystem, label, want string) {
	t.Helper()
	before := snapshot(t, h.cfg.Root)
	err := h.installRecorder(t, s, "")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: %v, not a refusal for %q", label, err, want)
	}
	unchanged(t, label, h.cfg.Root, before)
	if len(s.cmds) != 0 {
		t.Errorf("%s: ran %q", label, s.cmds)
	}
	if len(s.logs) != 1 || !strings.HasPrefix(s.logs[0], "balistid-install schema_version=1 outcome=refused component=recorder") {
		t.Errorf("%s: logged %q", label, s.logs)
	}
}

var wantRecorderCmds = []string{
	"/usr/bin/systemd-sysusers /etc/sysusers.d/balistid-collector.conf /etc/sysusers.d/balistid-ledger.conf " +
		"/etc/sysusers.d/balistid-auditstat.conf",
	"/usr/bin/systemd-tmpfiles --create /etc/tmpfiles.d/balistid-collector.conf /etc/tmpfiles.d/balistid-ledger.conf",
	"/usr/bin/systemctl daemon-reload",
	"/usr/bin/systemctl enable -- auditd.service balistid-collector.socket balistid-collector.service " +
		"balistid-ledger.service balistid-auditstat.service",
}

// The success case: exactly the table, the created directories, a new ledger key pair and the distribution's
// auditd.conf kept, these four commands and one decision logged, every check before the first write.
func TestRecorderInstallsExactlyTheRecorder(t *testing.T) {
	h, s, files := newRecorderHost(t)
	before := snapshot(t, h.cfg.Root)
	if err := h.installRecorder(t, s, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.cmds, wantRecorderCmds) {
		t.Fatalf("commands %q", s.cmds)
	}
	if s.checkedLate {
		t.Fatal("a check ran after the first write")
	}
	skey, vkey := readFile(t, h, ledgerKey), readFile(t, h, ledgerPub)
	want := maps.Clone(before)
	for _, dir := range append(slices.Clone(recorderComponent.created), stateDir) {
		want[filepath.Join(h.cfg.Root, dir)] = entryOf(fs.ModeDir|0o755, s.uid, s.gid, nil)
	}
	for _, f := range recorderTable {
		want[filepath.Join(h.cfg.Root, f.dest)] = entryOf(f.mode, s.uid, s.gid, files[f.name])
	}
	want[filepath.Join(h.cfg.Root, auditdOrig)] = entryOf(0o640, s.uid, s.gid, []byte(distroAuditd))
	want[filepath.Join(h.cfg.Root, ledgerKey)] = entryOf(0o600, s.uid, s.gid, skey)
	want[filepath.Join(h.cfg.Root, ledgerPub)] = entryOf(0o644, s.uid, s.gid, vkey)
	if got := snapshot(t, h.cfg.Root); !maps.Equal(got, want) {
		t.Fatalf("root:\ngot  %v\nwant %v", got, want)
	}
	signer, err := note.NewSigner(strings.TrimSuffix(string(skey), "\n"))
	must(t, err)
	if !regexp.MustCompile(`^balistid\.dev/log/[0-9a-f]{16}$`).MatchString(signer.Name()) {
		t.Fatalf("origin %q", signer.Name())
	}
	if absent, err := installedLedgerKey(h.cfg, mustRoot(t, h)); absent || err != nil {
		t.Fatalf("the new key is not an installed pair: %v %v", absent, err)
	}
	m := manifestFor("recorder", files)
	sum := sha256.Sum256(m)
	if want := fmt.Sprintf("balistid-install schema_version=1 outcome=installed component=recorder commit=%s "+
		"manifest_sha256=%s signer=%s version=dev reason=\"\"", testCommit, hex.EncodeToString(sum[:]), h.key.fingerprint(t)); !slices.Equal(s.logs, []string{want}) {
		t.Fatalf("logged %q, want %q", s.logs, want)
	}
}

// A second install keeps the ledger's key and the first auditd.conf, now the recorder's, out of auditd.conf.orig.
func TestRecorderReinstallKeepsTheKeyAndTheFirstAuditdConf(t *testing.T) {
	h, s, _ := newRecorderHost(t)
	must(t, h.installRecorder(t, s, ""))
	skey, vkey := readFile(t, h, ledgerKey), readFile(t, h, ledgerPub)
	must(t, h.installRecorder(t, s, ""))
	if !slices.Equal(s.cmds, wantRecorderCmds) {
		t.Fatalf("commands %q", s.cmds)
	}
	if string(readFile(t, h, ledgerKey)) != string(skey) || string(readFile(t, h, ledgerPub)) != string(vkey) {
		t.Fatal("the reinstall replaced the ledger's key")
	}
	if got := string(readFile(t, h, auditdOrig)); got != distroAuditd {
		t.Fatalf("auditd.conf.orig is %q, not the distribution's", got)
	}
}

// The first install, by the bootstrap's typed fingerprint and with no /etc/balistid yet, places the maintainer's
// key and a new ledger key, and runs again after a stop as the printed command does.
func TestRecorderFirstInstallPlacesBothKeys(t *testing.T) {
	h, s, _ := newRecorderHost(t)
	must(t, os.RemoveAll(filepath.Join(h.cfg.Root, signersDir)))
	fp := h.key.fingerprint(t)
	s.failCmd = "systemd-tmpfiles"
	if err := h.installRecorder(t, s, fp); err == nil || len(s.logs) != 1 || !strings.Contains(s.logs[0], "outcome=stopped") {
		t.Fatalf("the failed step: %v, logged %q", err, s.logs)
	}
	skey := readFile(t, h, ledgerKey)
	s.failCmd = ""
	must(t, h.installRecorder(t, s, fp))
	if string(readFile(t, h, path.Join(signersDir, signersName))) != string(h.key.signers) {
		t.Fatal("the maintainer's key is not installed")
	}
	if string(readFile(t, h, ledgerKey)) != string(skey) {
		t.Fatal("the run after the stop made another ledger key")
	}
	if _, err := os.Lstat(filepath.Join(h.cfg.Root, "usr/local/lib/balistid/balistid-install")); err != nil {
		t.Fatalf("no installer: %v", err)
	}
}

// A host without auditd.conf has nothing to keep: no auditd.conf.orig is written.
func TestRecorderKeepsNoAuditdConfWhereThereWasNone(t *testing.T) {
	h, s, _ := newRecorderHost(t)
	must(t, os.Remove(filepath.Join(h.cfg.Root, auditdConf)))
	must(t, h.installRecorder(t, s, ""))
	if _, err := os.Lstat(filepath.Join(h.cfg.Root, auditdOrig)); err == nil {
		t.Fatal("an auditd.conf.orig was written with no auditd.conf before")
	}
}

// Each precondition of ADR 0068 point 2 refuses alone, before any write or command.
func TestRecorderRefusesAHostNotReadyForTheSensor(t *testing.T) {
	sk1, vk1, err := note.GenerateKey(rand.Reader, "balistid.dev/log/0000000000000001")
	must(t, err)
	_, vk2, err := note.GenerateKey(rand.Reader, "balistid.dev/log/0000000000000001")
	must(t, err)
	for label, c := range map[string]struct {
		change func(t *testing.T, h *fakeHost, s *fakeSystem)
		want   string
	}{
		"no audit=1": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, "proc/cmdline", []byte("rw audit_backlog_limit=65536\n"), 0o644)
		}, "not booted with audit=1"},
		"audit=1 then audit=0": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, "proc/cmdline", []byte("audit=1 audit_backlog_limit=65536 audit=0\n"), 0o644)
		}, "not booted with audit=1"},
		"a lower backlog limit": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, "proc/cmdline", []byte("audit=1 audit_backlog_limit=65535\n"), 0o644)
		}, "not booted with audit=1"},
		"no backlog limit": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, "proc/cmdline", []byte("audit=1\n"), 0o644)
		}, "not booted with audit=1"},
		"no gawk": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			must(t, os.Remove(filepath.Join(h.cfg.Root, "usr/bin/gawk")))
		}, "/usr/bin/gawk"},
		"laurel others may write": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.chmod(t, "usr/bin/laurel", 0o757)
		}, "only root may write"},
		"auditd its group may write": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.chmod(t, "usr/bin/auditd", 0o775)
		}, "only root may write"},
		"augenrules a link": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			must(t, os.Remove(filepath.Join(h.cfg.Root, "usr/bin/augenrules")))
			h.symlink(t, "gawk", "usr/bin/augenrules")
		}, "only root may write"},
		"usr/bin writable": {func(t *testing.T, h *fakeHost, _ *fakeSystem) { h.chmod(t, "usr/bin", 0o775) }, "writable by group or other"},
		"no _laurel":       {func(_ *testing.T, _ *fakeHost, s *fakeSystem) { s.noLaurel = true }, "no user _laurel"},
		"other rules": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, rulesDir+"/10-base-config.rules", []byte("-D\n"), 0o640)
			h.put(t, rulesDir+"/lab.rules", []byte("-w /etc\n"), 0o640)
		}, "move them out first: 10-base-config.rules lab.rules"},
		"a running unit": {func(_ *testing.T, _ *fakeHost, s *fakeSystem) {
			s.units["balistid-ledger.service"] = map[string]string{"ActiveState": "active"}
		}, "balistid-ledger.service is \"active\""},
		"auditd.conf a link": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			must(t, os.Remove(filepath.Join(h.cfg.Root, auditdConf)))
			h.symlink(t, "../../proc/cmdline", auditdConf)
		}, "not a regular file"},
		"only a private key": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, ledgerKey, []byte(sk1+"\n"), 0o600)
		}, "only one of the ledger's key pair"},
		"only a public key": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, ledgerPub, []byte(vk1+"\n"), 0o644)
		}, "only one of the ledger's key pair"},
		"a readable private key": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, ledgerKey, []byte(sk1+"\n"), 0o644)
			h.put(t, ledgerPub, []byte(vk1+"\n"), 0o644)
		}, "mode -rw-r--r--, not -rw-------"},
		"keys of two pairs": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, ledgerKey, []byte(sk1+"\n"), 0o600)
			h.put(t, ledgerPub, []byte(vk2+"\n"), 0o644)
		}, "not one pair"},
		"not a key": {func(t *testing.T, h *fakeHost, _ *fakeSystem) {
			h.put(t, ledgerKey, []byte("PRIVATE+KEY+x\n"), 0o600)
			h.put(t, ledgerPub, []byte(vk1+"\n"), 0o644)
		}, "not a note signing key"},
	} {
		t.Run(label, func(t *testing.T) {
			h, s, _ := newRecorderHost(t)
			c.change(t, h, s)
			h.refusedRecorder(t, s, label, c.want)
		})
	}
}

// What augenrules does not read, and the recorder's own rules, do not refuse: a directory beside them, an installed
// matching key pair.
func TestRecorderAcceptsWhatAugenrulesDoesNotRead(t *testing.T) {
	h, s, _ := newRecorderHost(t)
	h.mkdir(t, rulesDir+"/.backup", 0o755)
	h.put(t, rulesDir+"/balistid.rules", []byte("old\n"), 0o640)
	h.put(t, rulesDir+"/notes.txt", []byte("x\n"), 0o640)
	sk, vk, err := note.GenerateKey(rand.Reader, "balistid.dev/log/00000000000000ab")
	must(t, err)
	h.mkdir(t, signersDir, 0o755)
	h.put(t, ledgerKey, []byte(sk+"\n"), 0o600)
	h.put(t, ledgerPub, []byte(vk+"\n"), 0o644)
	must(t, h.installRecorder(t, s, ""))
	if string(readFile(t, h, ledgerKey)) != sk+"\n" {
		t.Fatal("an installed pair was replaced")
	}
}

// The recorder installs only its own release: the runner's manifest in the recorder's bundle, or another file set.
func TestRecorderRefusesAnotherComponentOrFileSet(t *testing.T) {
	h, s, _ := newRecorderHost(t)
	extra := recorderFiles(h.key.signers)
	extra["balistid-relay"] = []byte("x")
	short := recorderFiles(h.key.signers)
	delete(short, "auditd.conf")
	for label, c := range map[string]struct {
		files    map[string][]byte
		manifest []byte
		want     string
	}{
		"a file outside the table": {extra, manifestFor("recorder", extra), "not the recorder's"},
		"a table file missing":     {short, manifestFor("recorder", short), "not the recorder's"},
		"the runner's manifest":    {recorderFiles(h.key.signers), manifestFor("runner", recorderFiles(h.key.signers)), "not of the recorder component"},
	} {
		h.publish(t, c.files, c.manifest, h.key.sign(t, c.manifest, Namespace))
		h.refusedRecorder(t, s, label, c.want)
	}
	must(t, os.Remove(filepath.Join(h.dir, h.bundle)))
	h.bundle = runnerComponent.bundle()
	h.release(t)
	h.refusedRecorder(t, s, "only the runner's bundle", recorderComponent.bundle()+": missing")
}

// Every destination lies in a directory the component trusts or creates, so preflight has checked its parent.
func TestEveryDestinationIsInACheckedDirectory(t *testing.T) {
	for _, c := range components {
		dirs := slices.Concat(c.trusted, c.created)
		for _, f := range c.table {
			if !slices.Contains(dirs, path.Dir(f.dest)) {
				t.Errorf("%s: /%s is in no directory it checks", c.name, f.dest)
			}
		}
	}
}

// bootedForAudit reads the kernel's command line as the kernel does: the last of a repeated parameter wins.
func TestBootedForAudit(t *testing.T) {
	for cmdline, want := range map[string]bool{
		bootedCmdline: true, "audit=1 audit_backlog_limit=131072": true, "audit=0 audit=1 audit_backlog_limit=65536": true,
		"audit=1 audit_backlog_limit=65536 audit_backlog_limit=64": false, "audit=1 audit_backlog_limit=x": false,
		"audit=on audit_backlog_limit=65536": false, "xaudit=1 audit_backlog_limit=65536": false, "": false,
	} {
		if got := bootedForAudit(cmdline); got != want {
			t.Errorf("%q: %v", cmdline, got)
		}
	}
}

func readFile(t *testing.T, h *fakeHost, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.cfg.Root, name)) //nolint:gosec // test temp dir
	must(t, err)
	return b
}

func mustRoot(t *testing.T, h *fakeHost) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(h.cfg.Root)
	must(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}
