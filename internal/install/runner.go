package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
)

// target is where one file of a component goes and its mode.
type target struct {
	name, dest string
	mode       fs.FileMode
}

// runnerTable is the runner component (ADR 0011, 0058) in the order it is written; the installer goes last, so a
// stop leaves the one that ran in place.
var runnerTable = []target{
	{"balistid-runner", "usr/local/lib/balistid/balistid-runner", 0o755},
	{"balistid-runner-build.service", "etc/systemd/system/balistid-runner-build.service", 0o644},
	{"balistid-runner-tick.service", "etc/systemd/system/balistid-runner-tick.service", 0o644},
	{"balistid-runner-tick.timer", "etc/systemd/system/balistid-runner-tick.timer", 0o644},
	{"sysusers.conf", "etc/sysusers.d/balistid-runner.conf", 0o644},
	{"tmpfiles.conf", "etc/tmpfiles.d/balistid-runner.conf", 0o644},
	{signersName, path.Join(signersDir, signersName), 0o644},
	{"balistid-install", "usr/local/lib/balistid/balistid-install", 0o755},
}

var (
	// runnerComponent's created directories and stateDir are absent or exactly root:root 0755, whatever
	// tmpfiles.conf (which makes stateDir) says.
	runnerComponent = component{name: "runner", table: runnerTable,
		units:    []string{"balistid-runner-tick.timer", "balistid-runner-tick.service", "balistid-runner-build.service"},
		trusted:  []string{"etc/systemd/system", "usr/local/lib", "var/lib"},
		created:  []string{"usr/local/lib/balistid", "etc/sysusers.d", "etc/tmpfiles.d", signersDir},
		tmpfiles: []string{"tmpfiles.conf"}}
	unitProps      = []string{"Id", "ActiveState", "DropInPaths", "FragmentPath"}
	maintainerDirs = []string{stateDir + "/inbox", stateDir + "/objects"}
	maintainerName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

const (
	stateDir    = "var/lib/balistid"
	runnerGroup = "balistid-runner"
	agentsGroup = "balistid-agents"
	unitDir     = "/etc/systemd/system/"
)

// Runner installs the runner component from dir for maintainer, who owns its inbox and objects (ADR 0011,
// point 5). Every check, the signature first, runs before the first write; a refusal changes nothing and runs
// no command. A failed step stops with what was written in place: there is no rollback, as before. It starts
// nothing. Every outcome is logged through cfg.Log.
func Runner(ctx context.Context, cfg Config, dir, maintainer, fingerprint string) error {
	d := Decision{Outcome: "installed", Component: "runner", Version: buildinfo.Version}
	writing := false
	err := runner(ctx, cfg, dir, maintainer, fingerprint, &d, &writing)
	switch {
	case err != nil && writing:
		d.Outcome, d.Reason = "stopped", err.Error()
	case err != nil:
		d.Outcome, d.Reason = "refused", err.Error()
	}
	cfg.Log(ctx, d)
	return err
}

// DecisionSchema is the version of the Decision record; a reader rejects another major version (ENGINEERING.md 3).
const DecisionSchema = 1

// Decision is what one run logs: installed, refused or stopped, the reason and what the release was.
type Decision struct {
	Outcome, Component, Commit, ManifestSHA256, Signer, Version, Reason string
}

// Attrs are the decision's fields for log/slog, schema_version first.
func (d Decision) Attrs() []slog.Attr {
	return []slog.Attr{slog.Int("schema_version", DecisionSchema), slog.String("outcome", d.Outcome),
		slog.String("component", d.Component), slog.String("commit", d.Commit),
		slog.String("manifest_sha256", d.ManifestSHA256), slog.String("signer", d.Signer),
		slog.String("version", d.Version), slog.String("reason", d.Reason)}
}

// Line is the decision as one journal line of key=value fields; values are quoted where they need it.
func (d Decision) Line() string {
	var b strings.Builder
	b.WriteString("balistid-install")
	for _, a := range d.Attrs() {
		v := a.Value.String()
		if v == "" || strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == '"' || r == '=' || r > '~' }) {
			v = strconv.Quote(v)
		}
		b.WriteString(" " + a.Key + "=" + v)
	}
	return b.String()
}

func runner(ctx context.Context, cfg Config, dir, maintainer, fingerprint string, d *Decision, writing *bool) error {
	host, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return fmt.Errorf("open the root: %w", err)
	}
	defer host.Close() //nolint:errcheck // every write is synced by WriteIn
	c := runnerComponent
	r, err := c.released(ctx, cfg, host, dir, fingerprint, d)
	if err != nil {
		return err
	}
	muid, err := maintainerUID(cfg, maintainer)
	if err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, c.units, false); err != nil {
		return err
	}
	var extra []wantDir
	for _, dir := range maintainerDirs {
		extra = append(extra, wantDir{dir, maintainerOwner, runnerGroup, fs.ModeDir | fs.ModeSetgid | 0o750})
	}
	absent, err := preflight(cfg, host, c, muid, extra, c.tmpfilesConf(r))
	if err != nil {
		return err
	}
	*writing = true
	return apply(ctx, cfg, host, r, maintainer, muid, absent)
}

// maintainerUID is the uid of a regular user by a plain name, never root or a system account.
func maintainerUID(cfg Config, name string) (int, error) {
	if !maintainerName.MatchString(name) || name == "root" {
		return 0, errors.New("bad maintainer name")
	}
	uid, err := cfg.LookupUser(name)
	if err != nil {
		return 0, fmt.Errorf("no user %s: %w", name, err)
	}
	if uid < 1000 || uid > 60000 {
		return 0, fmt.Errorf("%s is not a regular user", name)
	}
	return uid, nil
}

// unitsAsWritten refuses a unit that runs, or that a drop-in or a file other than the one this install writes
// would change. systemd answers only for what it has loaded, so before the reload a unit with no file yet passes,
// and after it only the installed file does. Not checked: .wants/ and manager-wide settings; only root writes them.
func unitsAsWritten(ctx context.Context, cfg Config, units []string, reloaded bool) error {
	blocks, err := cfg.Show(ctx, units, unitProps)
	if err != nil {
		return fmt.Errorf("cannot query the units: %w", err)
	}
	if len(blocks) != len(units) {
		return errors.New("cannot query the units: an answer per unit is missing")
	}
	for i, u := range units {
		b := blocks[i]
		if a := b["ActiveState"]; !reloaded && a != "inactive" && a != "failed" {
			return fmt.Errorf("%s is %q, not stopped", u, a)
		}
		if b["DropInPaths"] != "" {
			return fmt.Errorf("%s has drop-ins", u)
		}
		if f := b["FragmentPath"]; f != unitDir+u && (reloaded || f != "") {
			return fmt.Errorf("%s is loaded from %q, not %s", u, f, unitDir+u)
		}
	}
	return nil
}

// preflight checks every path the install of c writes or creates, or tmpfiles makes, and extra, before the first
// write, and returns those absent. Absent means only "does not exist": any other error refuses. Nothing found is
// repaired, since others may have prepared it.
func preflight(cfg Config, host *os.Root, c component, muid int, extra []wantDir, tmpfiles []byte) (map[string]bool, error) {
	for _, dir := range c.trusted {
		if _, err := trustedPath(cfg, host, dir); err != nil {
			return nil, err
		}
	}
	made, err := tmpfilesDirs(tmpfiles)
	if err != nil {
		return nil, err
	}
	var dirs []wantDir
	for _, dir := range append(slices.Clone(c.created), stateDir) {
		dirs = append(dirs, wantDir{dir, "root", "root", fs.ModeDir | 0o755})
	}
	absent := map[string]bool{}
	for _, d := range slices.Concat(dirs, extra, made) {
		fi, err := host.Lstat(d.name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			absent[d.name] = true
			continue
		case err != nil:
			return nil, fmt.Errorf("cannot stat /%s: %w", d.name, err)
		}
		// Owners are looked up only for what exists: before sysusers they may not.
		uid, gid, err := d.owner(cfg, muid)
		if err != nil {
			return nil, fmt.Errorf("/%s: %w", d.name, err)
		}
		// tmpfiles restores the mode of a directory it gives to a user other than root, who owns and may change it;
		// one writable by others is still refused, since anyone could plant a link there before tmpfiles runs.
		mode := d.mode
		if d.user != "root" && d.user != maintainerOwner && fi.IsDir() {
			mode = fi.Mode() &^ 0o002
		}
		if err := ownedAs(fi, uid, gid, mode); err != nil {
			return nil, fmt.Errorf("/%s: %w", d.name, err)
		}
	}
	for _, f := range c.table {
		if absent[path.Dir(f.dest)] {
			absent[f.dest] = true
			continue
		}
		fi, err := host.Lstat(f.dest)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			absent[f.dest] = true
		case err != nil:
			return nil, fmt.Errorf("cannot stat /%s: %w", f.dest, err)
		case !fi.Mode().IsRegular():
			return nil, fmt.Errorf("/%s is not a regular file", f.dest)
		}
	}
	return absent, nil
}

// wantDir is a directory the install creates, or tmpfiles makes, as it must be when it exists already.
type wantDir struct {
	name, user, group string
	mode              fs.FileMode
}

// maintainerOwner stands for the maintainer's uid; it is no valid user name.
const maintainerOwner = "<maintainer>"

func (d wantDir) owner(cfg Config, muid int) (uid, gid int, err error) {
	uid, gid = cfg.UID, cfg.GID
	switch d.user {
	case "root":
	case maintainerOwner:
		uid = muid
	default:
		if uid, err = cfg.LookupUser(d.user); err != nil {
			return 0, 0, fmt.Errorf("no user %s: %w", d.user, err)
		}
	}
	if d.group != "root" {
		if gid, err = cfg.LookupGroup(d.group); err != nil {
			return 0, 0, fmt.Errorf("no group %s: %w", d.group, err)
		}
	}
	return uid, gid, nil
}

var tmpfilesLine = regexp.MustCompile(`^d (/var/lib/balistid(?:/[a-z0-9_-]+)*) ([0-7]{4}) ([a-z_][a-z0-9_-]*) ([a-z_][a-z0-9_-]*) -$`)

// tmpfilesDirs are the directories the release's tmpfiles.conf makes, all under /var/lib/balistid. Any other line
// but a comment or a blank one is refused: the installer checks before tmpfiles runs only what it can read here.
func tmpfilesDirs(conf []byte) ([]wantDir, error) {
	var dirs []wantDir
	for i, line := range strings.Split(strings.TrimSuffix(string(conf), "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := tmpfilesLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("tmpfiles.conf: line %d is not a directory the installer can check", i+1)
		}
		bits, err := strconv.ParseUint(m[2], 8, 32)
		if err != nil || bits&^0o2777 != 0 {
			return nil, fmt.Errorf("tmpfiles.conf: line %d: a mode other than permissions and setgid", i+1)
		}
		mode := fs.ModeDir | fs.FileMode(bits&0o777)
		if bits&0o2000 != 0 {
			mode |= fs.ModeSetgid
		}
		name := strings.TrimPrefix(m[1], "/")
		// Preflight checks what tmpfiles will make; a directory whose parent it does not make is not checked whole.
		if parent := path.Dir(name); name != stateDir && parent != stateDir &&
			!slices.ContainsFunc(dirs, func(d wantDir) bool { return d.name == parent }) {
			return nil, fmt.Errorf("tmpfiles.conf: line %d: its parent directory is not listed before it", i+1)
		}
		dirs = append(dirs, wantDir{name, m[3], m[4], mode})
	}
	return dirs, nil
}

// apply writes as the shell installer did: directories, then each file whole, then systemd's users, directories
// and units; it checks the units again after the reload and writes itself last. Each error names its step.
func apply(ctx context.Context, cfg Config, host *os.Root, r Release, maintainer string, muid int, absent map[string]bool) error {
	c := runnerComponent
	if err := c.createDirs(host, absent); err != nil {
		return err
	}
	if err := c.writeFiles(host, r, absent); err != nil {
		return err
	}
	if err := runAll(ctx, cfg, []string{"/usr/bin/systemd-sysusers", "/etc/sysusers.d/balistid-runner.conf"},
		[]string{"/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/balistid-runner.conf"}); err != nil {
		return err
	}
	if err := createMaintainerDirs(cfg, host, muid, absent); err != nil {
		return err
	}
	if err := runAll(ctx, cfg, []string{"/usr/sbin/usermod", "-aG", agentsGroup, maintainer},
		[]string{"/usr/bin/systemctl", "daemon-reload"}); err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, c.units, true); err != nil {
		return fmt.Errorf("step check after the reload: %w", err)
	}
	return c.writeInstaller(host, r)
}

func runAll(ctx context.Context, cfg Config, argvs ...[]string) error {
	for _, argv := range argvs {
		if err := cfg.Run(ctx, argv); err != nil {
			return fmt.Errorf("step %s: %w", path.Base(argv[0]), err)
		}
	}
	return nil
}

// createMaintainerDirs creates inbox and objects where absent, owned by the maintainer and the group sysusers just
// made, in the directory tmpfiles just made, checked again first.
func createMaintainerDirs(cfg Config, host *os.Root, muid int, absent map[string]bool) error {
	if err := rootDir(cfg, host, stateDir); err != nil {
		return fmt.Errorf("step check after tmpfiles: %w", err)
	}
	gid, err := cfg.LookupGroup(runnerGroup)
	if err != nil {
		return fmt.Errorf("step look up %s: %w", runnerGroup, err)
	}
	for _, dir := range maintainerDirs {
		if !absent[dir] {
			continue
		}
		if err := errors.Join(host.Mkdir(dir, 0o700), host.Chown(dir, muid, gid), host.Chmod(dir, fs.ModeSetgid|0o750)); err != nil {
			return fmt.Errorf("step create /%s: %w", dir, err)
		}
	}
	return nil
}

// runCommand runs argv with nothing of the caller's environment but the C locale; its output goes to stderr.
func runCommand(ctx context.Context, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // fixed absolute binaries and argv from this package
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	return nil
}

func lookupUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("look up %s: %w", name, err)
	}
	return strconv.Atoi(u.Uid) //nolint:wrapcheck // a number the passwd file holds
}

func lookupGID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("look up %s: %w", name, err)
	}
	return strconv.Atoi(g.Gid) //nolint:wrapcheck // a number the group file holds
}

// logDecision writes d to stderr as structured fields and to the journal through logger; a logger that fails is
// reported, not hidden.
func logDecision(ctx context.Context, d Decision) {
	slog.LogAttrs(ctx, slog.LevelInfo, "balistid-install decision", d.Attrs()...)
	if err := runCommand(ctx, []string{"/usr/bin/logger", "-t", "balistid-install", "--", d.Line()}); err != nil {
		slog.ErrorContext(ctx, "the decision did not reach the journal", "err", err)
	}
}
