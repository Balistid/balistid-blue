package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var wantJudgeCmds = []string{"/usr/bin/systemctl daemon-reload"}

// judgeFiles is a release of the judge component as release.py bundles it.
func judgeFiles(signers []byte) map[string][]byte {
	files := map[string][]byte{signersName: signers}
	for _, f := range judgeTable {
		if f.name != signersName {
			files[f.name] = []byte(f.name + " of the judge release\n")
		}
	}
	return files
}

// publishJudge replaces the host's downloaded bundle with the judge's signed release.
func publishJudge(t *testing.T, h *fakeHost) map[string][]byte {
	t.Helper()
	_ = os.Remove(filepath.Join(h.dir, h.bundle))
	h.bundle = judgeComponent.bundle()
	files := judgeFiles(h.key.signers)
	m := manifestFor("judge", files)
	h.publish(t, files, m, h.key.sign(t, m, Namespace))
	return files
}

func (h *fakeHost) installJudge(t *testing.T, s *fakeSystem, fingerprint string) error {
	t.Helper()
	s.cmds, s.logs, s.reloaded, s.untouched = nil, nil, false, snapshot(t, h.cfg.Root)
	return Judge(t.Context(), h.cfg, h.dir, fingerprint)
}

// The success case on a host with no recorder: exactly the table and the one directory it creates, only a reload,
// nothing enabled, one decision logged, every check before the first write.
func TestJudgeInstallsExactlyTheJudge(t *testing.T) {
	h, s := newRunnerHost(t)
	files := publishJudge(t, h)
	before := snapshot(t, h.cfg.Root)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatal(err)
	}
	want := maps.Clone(before)
	want[filepath.Join(h.cfg.Root, "usr/local/lib/balistid")] = entryOf(fs.ModeDir|0o755, s.uid, s.gid, nil)
	for _, f := range judgeTable {
		want[filepath.Join(h.cfg.Root, f.dest)] = entryOf(f.mode, s.uid, s.gid, files[f.name])
	}
	if got := snapshot(t, h.cfg.Root); !maps.Equal(got, want) {
		t.Fatalf("root:\ngot  %v\nwant %v", got, want)
	}
	if !slices.Equal(s.cmds, wantJudgeCmds) {
		t.Fatalf("commands %q", s.cmds)
	}
	if s.checkedLate {
		t.Fatal("a check ran after the first write")
	}
	sum := sha256.Sum256(manifestFor("judge", files))
	if want := fmt.Sprintf("balistid-install schema_version=1 outcome=installed component=judge commit=%s "+
		"manifest_sha256=%s signer=%s version=dev reason=\"\"", testCommit, hex.EncodeToString(sum[:]), h.key.fingerprint(t)); !slices.Equal(s.logs, []string{want}) {
		t.Fatalf("logged %q, want %q", s.logs, want)
	}
}

// On an installed recorder the judge changes no file of the recorder's table but the shared installer, adds no
// user, directory under /var/lib or enabled unit, and leaves the installed allowed_signers as it was.
func TestJudgeInstallTouchesNoRecorderFileButTheInstaller(t *testing.T) {
	h, s, _ := newRecorderHost(t)
	if err := h.installRecorder(t, s, ""); err != nil {
		t.Fatal(err)
	}
	signers := readFile(t, h, signersDir+"/"+signersName)
	files := publishJudge(t, h)
	before := snapshot(t, h.cfg.Root)
	if err := h.installJudge(t, s, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.cmds, wantJudgeCmds) {
		t.Fatalf("commands %q", s.cmds)
	}
	after := snapshot(t, h.cfg.Root)
	changed := map[string]bool{}
	for p := range maps.Keys(after) {
		if after[p] != before[p] {
			changed[p] = true
		}
	}
	want := map[string]bool{}
	for _, f := range judgeTable {
		if f.name != signersName {
			want[filepath.Join(h.cfg.Root, f.dest)] = true
		}
	}
	if !maps.Equal(changed, want) {
		t.Fatalf("changed %v, want %v", slices.Sorted(maps.Keys(changed)), slices.Sorted(maps.Keys(want)))
	}
	for _, f := range recorderTable {
		if f.name != "balistid-install" && changed[filepath.Join(h.cfg.Root, f.dest)] {
			t.Errorf("/%s of the recorder changed", f.dest)
		}
	}
	if got := readFile(t, h, signersDir+"/"+signersName); string(got) != string(signers) {
		t.Errorf("the installed allowed_signers changed")
	}
	if got := readFile(t, h, "usr/local/lib/balistid/balistid-install"); string(got) != string(files["balistid-install"]) {
		t.Errorf("the installer is not the judge release's")
	}
}

// The judge's table shares with the recorder's and the runner's only the installer and allowed_signers, the
// two files every component carries, each with the same destination and mode there.
func TestJudgeTableSharesOnlyTheInstallerAndTheKey(t *testing.T) {
	shared := []string{"balistid-install", signersName}
	for _, other := range [][]target{recorderTable, runnerTable} {
		for _, f := range judgeTable {
			i := slices.IndexFunc(other, func(g target) bool { return g.dest == f.dest || g.name == f.name })
			switch {
			case i < 0 && slices.Contains(shared, f.name):
				t.Errorf("%s is in no other table", f.name)
			case i >= 0 && !slices.Contains(shared, f.name):
				t.Errorf("%s is in another component's table", f.name)
			case i >= 0 && other[i] != f:
				t.Errorf("%s: %v here, %v there", f.name, f, other[i])
			}
		}
	}
	if last := judgeTable[len(judgeTable)-1]; last.name != "balistid-install" {
		t.Errorf("the installer is not last: %s", last.name)
	}
}

// refusedJudge fails the test unless the run refused for want, left the root as it was, ran no command and logged
// exactly one refusal.
func (h *fakeHost) refusedJudge(t *testing.T, s *fakeSystem, label, want string) {
	t.Helper()
	before := snapshot(t, h.cfg.Root)
	err := h.installJudge(t, s, "")
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: %v, not a refusal for %q", label, err, want)
	}
	unchanged(t, label, h.cfg.Root, before)
	if len(s.cmds) != 0 || len(s.logs) != 1 ||
		!strings.HasPrefix(s.logs[0], "balistid-install schema_version=1 outcome=refused component=judge") {
		t.Errorf("%s: ran %q, logged %q", label, s.cmds, s.logs)
	}
}

// A refusal changes nothing and runs no command: the unit running, a bundle of another component, a file set that
// is not the judge's.
func TestJudgeRefusesWhatItDoesNotOwn(t *testing.T) {
	h, s := newRunnerHost(t)
	files := publishJudge(t, h)
	refuse := func(label, want string) { t.Helper(); h.refusedJudge(t, s, label, want) }
	s.units["balistid-judge.service"] = map[string]string{"ActiveState": "active"}
	refuse("the unit runs", "not stopped")
	delete(s.units, "balistid-judge.service")
	s.units["balistid-judge.service"] = map[string]string{"DropInPaths": "/etc/systemd/system/balistid-judge.service.d/x.conf"}
	refuse("a drop-in", "has drop-ins")
	delete(s.units, "balistid-judge.service")
	extra := maps.Clone(files)
	extra["balistid-collector"] = []byte("x")
	short := maps.Clone(files)
	delete(short, "balistid-judge")
	for label, c := range map[string]struct {
		files    map[string][]byte
		manifest []byte
		want     string
	}{
		"a file outside the table": {extra, manifestFor("judge", extra), "not the judge's"},
		"a table file missing":     {short, manifestFor("judge", short), "not the judge's"},
		"the recorder's manifest":  {files, manifestFor("recorder", files), "not of the judge component"},
	} {
		h.publish(t, c.files, c.manifest, h.key.sign(t, c.manifest, Namespace))
		refuse(label, c.want)
	}
	h.release(t) // the runner's bundle only
	must(t, os.Remove(filepath.Join(h.dir, h.bundle)))
	refuse("no judge bundle", judgeComponent.bundle()+": missing")
}

// The signature refusals ADR 0053 names, through the judge's whole run.
func TestJudgeRefusesABundleWhoseSignatureDoesNotVerify(t *testing.T) {
	h, s := newRunnerHost(t)
	files := publishJudge(t, h)
	m := manifestFor("judge", files)
	other := newKey(t)
	for label, c := range map[string]struct{ manifest, sig []byte }{
		"unsigned":        {m, nil},
		"altered":         {[]byte(strings.Replace(string(m), "component judge", "component judgf", 1)), h.key.sign(t, m, Namespace)},
		"other namespace": {m, h.key.sign(t, m, "file")},
		"other signer":    {m, other.sign(t, m, Namespace)},
	} {
		_ = os.Remove(filepath.Join(h.dir, sigName))
		h.publish(t, files, c.manifest, c.sig)
		want := "the signature does not verify"
		if c.sig == nil {
			want = sigName + ": missing"
		}
		h.refusedJudge(t, s, label, want)
	}
}

// Every path on the way to a destination is root's and not writable by others, and a destination is a regular
// file or absent: a refusal before the first write.
func TestJudgeRefusesARedirectedOrWritablePath(t *testing.T) {
	for label, c := range map[string]struct {
		spoil func(h *fakeHost)
		want  string
	}{
		"etc/systemd/system a link": {func(h *fakeHost) { h.relink(t, "etc/systemd/system") }, "/etc/systemd/system: not a directory"},
		"usr/local/lib a link":      {func(h *fakeHost) { h.relink(t, "usr/local/lib") }, "/usr/local/lib: not a directory"},
		"usr writable by group":     {func(h *fakeHost) { h.chmod(t, "usr", 0o775) }, "/usr: writable by group or other"},
		"lib/balistid writable":     {func(h *fakeHost) { h.mkdir(t, "usr/local/lib/balistid", 0o777) }, "/usr/local/lib/balistid: mode"},
		"state 0700":                {func(h *fakeHost) { h.mkdir(t, "var/lib/balistid", 0o700) }, "/var/lib/balistid: mode"},
		"the unit a link": {func(h *fakeHost) { h.symlink(t, "/dev/null", "etc/systemd/system/balistid-judge.service") },
			"not a regular file"},
		"the binary a directory": {func(h *fakeHost) {
			h.mkdir(t, "usr/local/lib/balistid", 0o755)
			h.mkdir(t, "usr/local/lib/balistid/balistid-judge", 0o755)
		},
			"not a regular file"},
	} {
		h, s := newRunnerHost(t)
		publishJudge(t, h)
		c.spoil(h)
		h.refusedJudge(t, s, label, c.want)
		h.chmod(t, "usr/local/lib", 0o755) // lets the temp directory's cleanup read it
	}
}

// A unit seen differently after the reload stops the run there, logged with its step, and the installer does not
// replace itself.
func TestJudgeStopsOnAUnitSeenOnlyAfterTheReload(t *testing.T) {
	for _, c := range [][2]string{{"DropInPaths", unitDir + "balistid-judge.service.d/old.conf"},
		{"FragmentPath", "/run/systemd/system/balistid-judge.service"}} {
		h, s := newRunnerHost(t)
		publishJudge(t, h)
		s.after = map[string]map[string]string{"balistid-judge.service": {c[0]: c[1]}}
		if err := h.installJudge(t, s, ""); err == nil || !strings.Contains(err.Error(), "step check after the reload") {
			t.Fatalf("%s: %v", c[0], err)
		}
		if !slices.Equal(s.cmds, wantJudgeCmds) || len(s.logs) != 1 ||
			!strings.HasPrefix(s.logs[0], "balistid-install schema_version=1 outcome=stopped component=judge") {
			t.Fatalf("%s: ran %q, logged %q", c[0], s.cmds, s.logs)
		}
		if _, err := os.Lstat(filepath.Join(h.cfg.Root, "usr/local/lib/balistid/balistid-install")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: the installer replaced itself: %v", c[0], err)
		}
	}
}
