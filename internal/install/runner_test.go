package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const maint = "maint"

// fakeSystem stands in for what the installer asks of the host besides its files: systemd's answers before and
// after the reload, users and groups, the commands it runs and the decision it logs.
type fakeSystem struct {
	root         string
	cmds, logs   []string
	units, after map[string]map[string]string // unit to properties overriding a unit not installed yet
	reloaded     bool
	showErr      error
	failCmd      string // the base name of a command that fails
	groupMade    bool
	untouched    map[string]string // the root before the run: no check may see it changed
	checkedLate  bool
	t            *testing.T
	uid, gid     int
}

// newRunnerHost is a fake host with the directories every Linux host has, the maintainer's key installed and a
// signed runner release downloaded.
func newRunnerHost(t *testing.T) (*fakeHost, *fakeSystem) {
	t.Helper()
	h := newHost(t)
	for _, dir := range []string{"etc/systemd/system", "usr/local/lib", "var/lib"} {
		h.mkdir(t, dir, 0o755)
	}
	h.release(t)
	s := &fakeSystem{root: h.cfg.Root, units: map[string]map[string]string{}, after: map[string]map[string]string{},
		t: t, uid: os.Getuid(), gid: os.Getgid()}
	if s.uid < 1000 || s.uid > 60000 {
		t.Fatalf("the tests chown inbox and objects to their own uid, %d, which is not a regular user's", s.uid)
	}
	h.cfg.Run, h.cfg.Show, h.cfg.LookupUser, h.cfg.LookupGroup, h.cfg.Log = s.run, s.show, s.lookupUser, s.lookupGroup, s.log
	return h, s
}

func (s *fakeSystem) run(_ context.Context, argv []string) error {
	s.cmds = append(s.cmds, strings.Join(argv, " "))
	switch path.Base(argv[0]) {
	case s.failCmd:
		return errors.New("exit status 1")
	case "systemd-sysusers":
		s.groupMade = true
	case "systemd-tmpfiles":
		p := filepath.Join(s.root, "var/lib/balistid")
		if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { //nolint:gosec // as tmpfiles.conf makes it
			return err
		}
		return os.Chmod(p, 0o755) //nolint:gosec // as tmpfiles.conf makes it
	case "systemctl":
		s.reloaded = true
	}
	return nil
}

// noWriteYet records a check that ran after the root had changed.
func (s *fakeSystem) noWriteYet() {
	if s.untouched != nil && !s.reloaded && !maps.Equal(snapshot(s.t, s.root), s.untouched) {
		s.checkedLate = true
	}
}

func (s *fakeSystem) show(_ context.Context, names, props []string) ([]map[string]string, error) {
	s.noWriteYet()
	if !slices.Equal(props, unitProps) {
		return nil, errors.New("asked for other properties")
	}
	if s.showErr != nil {
		return nil, s.showErr
	}
	out := []map[string]string{}
	for _, u := range names {
		b := map[string]string{"Id": u, "ActiveState": "inactive", "DropInPaths": "", "FragmentPath": ""}
		over := s.units[u]
		if s.reloaded {
			b["FragmentPath"], over = unitDir+u, s.after[u]
		}
		maps.Copy(b, over)
		out = append(out, b)
	}
	return out, nil
}

func (s *fakeSystem) lookupUser(name string) (int, error) {
	s.noWriteYet()
	uid, ok := map[string]int{maint: s.uid, "daemon": 2, "nobody": 65534, "balistid-runner": s.uid}[name]
	if !ok || name == "balistid-runner" && !s.groupMade {
		return 0, errors.New("unknown user")
	}
	return uid, nil
}

func (s *fakeSystem) lookupGroup(name string) (int, error) {
	if name != runnerGroup && name != agentsGroup || !s.groupMade {
		return 0, errors.New("unknown group")
	}
	return s.gid, nil
}

func (s *fakeSystem) log(_ context.Context, line string) { s.logs = append(s.logs, line) }

// install runs Runner on the fake host, the root first recorded so that a check seeing a write shows.
func (h *fakeHost) install(t *testing.T, s *fakeSystem, maintainer, fingerprint string) error {
	t.Helper()
	s.cmds, s.logs, s.reloaded, s.untouched = nil, nil, false, snapshot(t, h.cfg.Root)
	return Runner(t.Context(), h.cfg, h.dir, maintainer, fingerprint)
}

// refusedRun fails the test unless the run refused for want, left the root as it was, ran no command and logged
// exactly one refusal.
func (h *fakeHost) refusedRun(t *testing.T, s *fakeSystem, label, maintainer, fingerprint, want string) {
	t.Helper()
	before := snapshot(t, h.cfg.Root)
	err := h.install(t, s, maintainer, fingerprint)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: %v, not a refusal for %q", label, err, want)
	}
	unchanged(t, label, h.cfg.Root, before)
	if len(s.cmds) != 0 {
		t.Errorf("%s: ran %q", label, s.cmds)
	}
	if len(s.logs) != 1 || !strings.HasPrefix(s.logs[0], "balistid-install refused component=runner") {
		t.Errorf("%s: logged %q", label, s.logs)
	}
}

func entryOf(mode fs.FileMode, uid, gid int, data []byte) string {
	what := ""
	if data != nil {
		sum := sha256.Sum256(data)
		what = hex.EncodeToString(sum[:])
	}
	return fmt.Sprintf("%v %d:%d %s", mode, uid, gid, what)
}

// installed is the root after a first install: before, plus exactly the runner's files, directories and modes.
func (h *fakeHost) installed(t *testing.T, s *fakeSystem, before map[string]string, files map[string][]byte) map[string]string {
	t.Helper()
	want := maps.Clone(before)
	for _, dir := range append(slices.Clone(createdDirs), stateDir) {
		want[filepath.Join(h.cfg.Root, dir)] = entryOf(fs.ModeDir|0o755, s.uid, s.gid, nil)
	}
	for _, dir := range maintainerDirs {
		want[filepath.Join(h.cfg.Root, dir)] = entryOf(fs.ModeDir|fs.ModeSetgid|0o750, s.uid, s.gid, nil)
	}
	for _, f := range runnerTable {
		want[filepath.Join(h.cfg.Root, f.dest)] = entryOf(f.mode, s.uid, s.gid, files[f.name])
	}
	return want
}

var wantCmds = []string{"/usr/bin/systemd-sysusers /etc/sysusers.d/balistid-runner.conf",
	"/usr/bin/systemd-tmpfiles --create /etc/tmpfiles.d/balistid-runner.conf",
	"/usr/sbin/usermod -aG balistid-agents maint", "/usr/bin/systemctl daemon-reload"}

// The success case: exactly the expected files, modes and directories, these four commands, one decision logged.
func TestRunnerInstallsExactlyTheRunner(t *testing.T) {
	h, s := newRunnerHost(t)
	files := runnerFiles(h.key.signers)
	before := snapshot(t, h.cfg.Root)
	if err := h.install(t, s, maint, ""); err != nil {
		t.Fatal(err)
	}
	if got, want := snapshot(t, h.cfg.Root), h.installed(t, s, before, files); !maps.Equal(got, want) {
		t.Fatalf("root:\ngot  %v\nwant %v", got, want)
	}
	if !slices.Equal(s.cmds, wantCmds) {
		t.Fatalf("commands %q", s.cmds)
	}
	if s.checkedLate {
		t.Fatal("a check ran after the first write")
	}
	m := manifestOf(files)
	sum := sha256.Sum256(m)
	if want := fmt.Sprintf("balistid-install installed component=runner commit=%s manifest_sha256=%s signer=%s version=dev",
		testCommit, hex.EncodeToString(sum[:]), h.key.fingerprint(t)); !slices.Equal(s.logs, []string{want}) {
		t.Fatalf("logged %q, want %q", s.logs, want)
	}
}

// First install: the typed fingerprint, no key yet; the run installs /etc/balistid and the key.
func TestRunnerFirstInstallPlacesTheKey(t *testing.T) {
	h, s := newRunnerHost(t)
	must(t, os.RemoveAll(filepath.Join(h.cfg.Root, "etc/balistid")))
	files := runnerFiles(h.key.signers)
	before := snapshot(t, h.cfg.Root)
	if err := h.install(t, s, maint, h.key.fingerprint(t)); err != nil {
		t.Fatal(err)
	}
	if got, want := snapshot(t, h.cfg.Root), h.installed(t, s, before, files); !maps.Equal(got, want) {
		t.Fatalf("root:\ngot  %v\nwant %v", got, want)
	}
	h.refusedRun(t, s, "the key is now installed", maint, h.key.fingerprint(t), "already installed")
}

// A reinstall keeps inbox and objects and what agents left there, and replaces each file only by rename.
func TestRunnerReinstallKeepsInboxAndRenamesTargets(t *testing.T) {
	h, s := newRunnerHost(t)
	if err := h.install(t, s, maint, ""); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(h.cfg.Root, "var/lib/balistid/inbox/job"), []byte("x"), 0o600))
	inodes := map[string]uint64{}
	for _, f := range runnerTable {
		fi, err := os.Lstat(filepath.Join(h.cfg.Root, f.dest))
		must(t, err)
		inodes[f.dest] = fi.Sys().(*syscall.Stat_t).Ino
	}
	inbox, err := os.Lstat(filepath.Join(h.cfg.Root, "var/lib/balistid/inbox"))
	must(t, err)
	if err := h.install(t, s, maint, ""); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.cmds, wantCmds) {
		t.Fatalf("commands %q", s.cmds)
	}
	for _, f := range runnerTable {
		fi, err := os.Lstat(filepath.Join(h.cfg.Root, f.dest))
		must(t, err)
		if same := fi.Sys().(*syscall.Stat_t).Ino == inodes[f.dest]; same != (f.name == signersName) {
			t.Errorf("%s: same inode %v; a file changes only by rename, the installed key not at all", f.dest, same)
		}
	}
	if after, err := os.Lstat(filepath.Join(h.cfg.Root, "var/lib/balistid/inbox")); err != nil || !os.SameFile(inbox, after) {
		t.Fatalf("the inbox was replaced: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(h.cfg.Root, "var/lib/balistid/inbox/job")); err != nil {
		t.Fatalf("the agents' job is gone: %v", err)
	}
	for _, dir := range []string{"usr/local/lib/balistid", "etc/systemd/system", "etc/sysusers.d"} {
		entries, err := os.ReadDir(filepath.Join(h.cfg.Root, dir))
		must(t, err)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				t.Errorf("%s: a temp file %s is left", dir, e.Name())
			}
		}
	}
}

// The signature refusals ADR 0053 names, through the whole run: nothing changes and no command runs.
func TestRunnerRefusesWhatADR0053Names(t *testing.T) {
	h, s := newRunnerHost(t)
	files := runnerFiles(h.key.signers)
	m := manifestOf(files)
	other := newKey(t)
	for label, c := range map[string]struct{ manifest, sig []byte }{
		"unsigned":        {m, nil},
		"altered":         {bytes.Replace(m, []byte("runner\n"), []byte("runnes\n"), 1), h.key.sign(t, m, Namespace)},
		"other namespace": {m, h.key.sign(t, m, "file")},
		"other signer":    {m, other.sign(t, m, Namespace)},
	} {
		_ = os.Remove(filepath.Join(h.dir, sigName))
		h.publish(t, files, c.manifest, c.sig)
		want := "the signature does not verify"
		if c.sig == nil {
			want = sigName + ": missing"
		}
		h.refusedRun(t, s, label, maint, "", want)
	}
}

// The runner installs only its own table: another component or another set of files is refused.
func TestRunnerRefusesAnotherComponentOrFileSet(t *testing.T) {
	h, s := newRunnerHost(t)
	extra := runnerFiles(h.key.signers)
	extra["extra.conf"] = []byte("x")
	short := runnerFiles(h.key.signers)
	delete(short, "tmpfiles.conf")
	laurel := strings.Replace(string(manifestOf(runnerFiles(h.key.signers))), "component runner", "component laurel", 1)
	for label, c := range map[string]struct {
		files    map[string][]byte
		manifest []byte
		want     string
	}{
		"a file outside the table": {extra, manifestOf(extra), "not the runner's"},
		"a table file missing":     {short, manifestOf(short), "not the runner's"},
		"another component":        {runnerFiles(h.key.signers), []byte(laurel), "not of the runner component"},
	} {
		h.publish(t, c.files, c.manifest, h.key.sign(t, c.manifest, Namespace))
		h.refusedRun(t, s, label, maint, "", c.want)
	}
}

func TestRunnerRefusesABadMaintainer(t *testing.T) {
	h, s := newRunnerHost(t)
	for name, want := range map[string]string{
		"root": "bad maintainer name", "": "bad maintainer name", "MAINTAINER": "bad maintainer name",
		"1x": "bad maintainer name", "a b": "bad maintainer name", "ghost": "no user ghost",
		"daemon": "daemon is not a regular user", "nobody": "nobody is not a regular user",
	} {
		h.refusedRun(t, s, "maintainer "+name, name, "", want)
	}
}

// A running, unknown or changed unit refuses: drop-ins (set-property leaves one too) and copies elsewhere would
// outlive the install and change the unit.
func TestRunnerRefusesARunningOrChangedUnit(t *testing.T) {
	h, s := newRunnerHost(t)
	for _, u := range runnerUnits {
		for _, active := range []string{"active", "activating", "deactivating", "reloading", "x", ""} {
			s.units = map[string]map[string]string{u: {"ActiveState": active}}
			h.refusedRun(t, s, u+" "+active, maint, "", "not stopped")
		}
		for _, drop := range []string{unitDir + u + ".d/override.conf", "/etc/systemd/system.control/" + u + ".d/50-x.conf",
			"/run/systemd/system/" + u + ".d/a.conf /usr/lib/systemd/system/" + u + ".d/b.conf"} {
			s.units = map[string]map[string]string{u: {"DropInPaths": drop}}
			h.refusedRun(t, s, u+" "+drop, maint, "", u+" has drop-ins")
		}
		for _, frag := range []string{"/run/systemd/system/" + u, "/run/systemd/transient/" + u, "/usr/lib/systemd/system/" + u,
			unitDir + u + ".bak", "/x:" + unitDir + u, "/x" + unitDir + u} {
			s.units = map[string]map[string]string{u: {"FragmentPath": frag}}
			h.refusedRun(t, s, u+" "+frag, maint, "", "is loaded from")
		}
	}
	s.units = map[string]map[string]string{}
	s.showErr = errors.New("no bus")
	h.refusedRun(t, s, "systemd does not answer", maint, "", "cannot query")
}

// A unit from an earlier install, or none, passes before the reload.
func TestRunnerAcceptsUnitsFromThisInstallOrNone(t *testing.T) {
	for _, n := range []int{len(runnerUnits), 1, 0} {
		h, s := newRunnerHost(t)
		for _, u := range runnerUnits[:n] {
			s.units[u] = map[string]string{"FragmentPath": unitDir + u}
		}
		if err := h.install(t, s, maint, ""); err != nil {
			t.Fatalf("%d installed units: %v", n, err)
		}
	}
}

// systemd answers for a unit with no file only after the install's own reload: a drop-in or another file seen
// then stops the run there, logged with its step, and the installer does not replace itself.
func TestRunnerStopsOnAUnitSeenOnlyAfterTheReload(t *testing.T) {
	for _, u := range runnerUnits {
		for _, c := range [][2]string{{"DropInPaths", unitDir + u + ".d/old.conf"},
			{"FragmentPath", "/run/systemd/system/" + u}, {"FragmentPath", ""}} {
			prop, value := c[0], c[1]
			h, s := newRunnerHost(t)
			s.after = map[string]map[string]string{u: {prop: value}}
			if err := h.install(t, s, maint, ""); err == nil || !strings.Contains(err.Error(), "step check after the reload") {
				t.Fatalf("%s %s: %v", u, prop, err)
			}
			if !slices.Equal(s.cmds, wantCmds) || len(s.logs) != 1 || !strings.HasPrefix(s.logs[0], "balistid-install stopped") {
				t.Fatalf("%s %s: ran %q, logged %q", u, prop, s.cmds, s.logs)
			}
			if _, err := os.Lstat(filepath.Join(h.cfg.Root, "usr/local/lib/balistid/balistid-install")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("%s %s: the installer replaced itself: %v", u, prop, err)
			}
		}
	}
}

// A failed command stops the run, logged with the step that failed.
func TestRunnerLogsAFailedStep(t *testing.T) {
	h, s := newRunnerHost(t)
	s.failCmd = "systemd-sysusers"
	err := h.install(t, s, maint, "")
	if err == nil || len(s.logs) != 1 || !strings.Contains(s.logs[0], `stopped`) ||
		!strings.Contains(s.logs[0], `reason="step systemd-sysusers: exit status 1"`) {
		t.Fatalf("%v, logged %q", err, s.logs)
	}
	if !slices.Equal(s.cmds, wantCmds[:1]) {
		t.Fatalf("ran %q", s.cmds)
	}
}

// Every path on the way to a destination is root's, a directory, not writable by others: with the root standing
// for "/", os.Root contains nothing, so a link even inside the root, or a writable parent, refuses.
func TestRunnerRefusesARedirectedOrWritablePath(t *testing.T) {
	for label, c := range map[string]struct {
		spoil func(h *fakeHost)
		want  string
	}{
		"etc/systemd/system a link inside the root": {func(h *fakeHost) { h.relink(t, "etc/systemd/system") }, "/etc/systemd/system: not a directory"},
		"usr/local/lib a link inside the root":      {func(h *fakeHost) { h.relink(t, "usr/local/lib") }, "/usr/local/lib: not a directory"},
		"var/lib a link":                            {func(h *fakeHost) { h.relink(t, "var/lib") }, "/var/lib: not a directory"},
		"usr writable by group":                     {func(h *fakeHost) { h.chmod(t, "usr", 0o775) }, "/usr: writable by group or other"},
		"etc/systemd writable by other":             {func(h *fakeHost) { h.chmod(t, "etc/systemd", 0o757) }, "/etc/systemd: writable"},
		"the root writable":                         {func(h *fakeHost) { h.chmod(t, ".", 0o777) }, "/.: writable"},
		"var/lib setgid":                            {func(h *fakeHost) { h.chmod(t, "var/lib", fs.ModeSetgid|0o755) }, "/var/lib: setgid"},
		"lib/balistid writable":                     {func(h *fakeHost) { h.mkdir(t, "usr/local/lib/balistid", 0o777) }, "/usr/local/lib/balistid: mode"},
		"lib/balistid 0750":                         {func(h *fakeHost) { h.mkdir(t, "usr/local/lib/balistid", 0o750) }, "/usr/local/lib/balistid: mode"},
		"lib/balistid a link":                       {func(h *fakeHost) { h.mkdir(t, "usr/local/real", 0o755); h.symlink(t, "real", "usr/local/lib/balistid") }, "/usr/local/lib/balistid: mode"},
		"sysusers.d a file":                         {func(h *fakeHost) { h.put(t, "etc/sysusers.d", []byte("x"), 0o644) }, "/etc/sysusers.d: mode"},
		"tmpfiles.d 0750":                           {func(h *fakeHost) { h.mkdir(t, "etc/tmpfiles.d", 0o750) }, "/etc/tmpfiles.d: mode"},
		"state 0700":                                {func(h *fakeHost) { h.mkdir(t, "var/lib/balistid", 0o700) }, "/var/lib/balistid: mode"},
		"inbox 0777":                                {func(h *fakeHost) { h.prepare(t, "var/lib/balistid/inbox", 0o777) }, "/var/lib/balistid/inbox: mode"},
		"inbox without setgid":                      {func(h *fakeHost) { h.prepare(t, "var/lib/balistid/inbox", 0o750) }, "/var/lib/balistid/inbox: mode"},
		"objects a link": {func(h *fakeHost) {
			h.mkdir(t, "var/lib/balistid", 0o755)
			h.symlink(t, "/tmp", "var/lib/balistid/objects")
		}, "objects: mode"},
		"a target a directory":       {func(h *fakeHost) { h.mkdir(t, "etc/systemd/system/balistid-runner-tick.timer", 0o755) }, "not a regular file"},
		"a target a link":            {func(h *fakeHost) { h.symlink(t, "/dev/null", "etc/systemd/system/balistid-runner-tick.timer") }, "not a regular file"},
		"a stat error is not absent": {func(h *fakeHost) { h.chmod(t, "usr/local/lib", 0o600) }, "cannot stat /usr/local/lib/balistid"},
	} {
		h, s := newRunnerHost(t)
		c.spoil(h)
		s.groupMade = true // an existing inbox is checked against the runner's group
		h.refusedRun(t, s, label, maint, "", c.want)
		h.chmod(t, "usr/local/lib", 0o755) // lets the temp directory's cleanup read it
	}
}

func (h *fakeHost) relink(t *testing.T, dir string) {
	t.Helper()
	real := filepath.Join(h.cfg.Root, dir+"-real")
	must(t, os.Rename(filepath.Join(h.cfg.Root, dir), real))
	must(t, os.Symlink(filepath.Base(real), filepath.Join(h.cfg.Root, dir)))
}

func (h *fakeHost) chmod(t *testing.T, name string, mode fs.FileMode) {
	t.Helper()
	if fi, err := os.Lstat(filepath.Join(h.cfg.Root, name)); err == nil && fi.Mode()&fs.ModeSymlink == 0 {
		must(t, os.Chmod(filepath.Join(h.cfg.Root, name), mode))
	}
}

func (h *fakeHost) symlink(t *testing.T, target, name string) {
	t.Helper()
	must(t, os.Symlink(target, filepath.Join(h.cfg.Root, name)))
}

// prepare makes an inbox or objects directory as someone else might have, under a correct state directory.
func (h *fakeHost) prepare(t *testing.T, name string, mode fs.FileMode) {
	t.Helper()
	h.mkdir(t, path.Dir(name), 0o755)
	must(t, os.Mkdir(filepath.Join(h.cfg.Root, name), 0o700))
	h.chmod(t, name, mode)
}

// tmpfiles makes the runner's result directories; one prepared as a link or with other modes or owners before the
// install refuses before its first write, since tmpfiles would create directories through it first.
func TestRunnerRefusesATrappedResultsDirectory(t *testing.T) {
	results := "var/lib/balistid/results"
	exact := func(h *fakeHost) {
		h.mkdir(t, "var/lib/balistid", 0o755)
		h.mkdir(t, results, 0o750)
		for _, d := range []string{"agent", "evidence", "acceptance"} {
			h.mkdir(t, results+"/"+d, 0o750|fs.ModeSetgid)
		}
	}
	for label, c := range map[string]struct {
		spoil func(h *fakeHost)
		want  string
	}{
		"results a link outside": {func(h *fakeHost) { h.mkdir(t, "var/lib/balistid", 0o755); h.symlink(t, t.TempDir(), results) }, results + ": mode"},
		"results 0777":           {func(h *fakeHost) { h.mkdir(t, "var/lib/balistid", 0o755); h.mkdir(t, results, 0o777) }, results + ": mode"},
		"agent a link": {func(h *fakeHost) {
			exact(h)
			must(t, os.Remove(filepath.Join(h.cfg.Root, results, "agent")))
			h.symlink(t, "/etc", results+"/agent")
		}, "agent: mode"},
		"evidence without setgid":   {func(h *fakeHost) { exact(h); h.chmod(t, results+"/evidence", 0o750) }, "evidence: mode"},
		"acceptance group writable": {func(h *fakeHost) { exact(h); h.chmod(t, results+"/acceptance", 0o770|fs.ModeSetgid) }, "acceptance: mode"},
	} {
		h, s := newRunnerHost(t)
		c.spoil(h)
		s.groupMade = true
		h.refusedRun(t, s, label, maint, "", c.want)
	}
	h, s := newRunnerHost(t)
	exact(h)
	h.refusedRun(t, s, "results before the runner's user exists", maint, "", "no user balistid-runner")
	s.groupMade = true
	if err := h.install(t, s, maint, ""); err != nil {
		t.Fatalf("results exactly as tmpfiles makes them: %v", err)
	}
}

// The installer checks before tmpfiles runs only what it can read in tmpfiles.conf.
func TestRunnerRefusesATmpfilesLineItCannotCheck(t *testing.T) {
	for _, line := range []string{"L /etc/x - - - - /tmp", "d /etc/balistid 0755 root root -", "d /var/lib/balistid/../x 0755 root root -",
		"d /var/lib/balistid/x 4755 root root -", "d /var/lib/balistid/x 0755 root root 1d", "D /var/lib/balistid/x 0755 root root -"} {
		h, s := newRunnerHost(t)
		files := runnerFiles(h.key.signers)
		files["tmpfiles.conf"] = append(slices.Clone(deployTmpfiles), line+"\n"...)
		m := manifestOf(files)
		h.publish(t, files, m, h.key.sign(t, m, Namespace))
		h.refusedRun(t, s, line, maint, "", "tmpfiles.conf: line 10")
	}
}
