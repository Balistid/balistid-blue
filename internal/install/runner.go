package install

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/wholefile"
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
	runnerUnits = []string{"balistid-runner-tick.timer", "balistid-runner-tick.service", "balistid-runner-build.service"}
	unitProps   = []string{"Id", "ActiveState", "DropInPaths", "FragmentPath"}
	// trustedDirs exist on every host; they and every directory above them are only checked, never changed.
	trustedDirs = []string{"etc/systemd/system", "usr/local/lib", "var/lib"}
	// createdDirs and stateDir are absent or exactly root:root 0755; tmpfiles makes stateDir.
	createdDirs    = []string{"usr/local/lib/balistid", "etc/sysusers.d", "etc/tmpfiles.d", signersDir}
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
	d := decision{component: "runner"}
	err := runner(ctx, cfg, dir, maintainer, fingerprint, &d)
	cfg.Log(ctx, d.line(err))
	return err
}

// decision is what one run logs: install or refuse, the reason and what the release was (ENGINEERING.md 3).
type decision struct {
	component, commit, manifest, signer string
	writing                             bool
}

func (d decision) line(err error) string {
	outcome := "installed"
	switch {
	case err != nil && d.writing:
		outcome = "stopped"
	case err != nil:
		outcome = "refused"
	}
	line := fmt.Sprintf("balistid-install %s component=%s commit=%s manifest_sha256=%s signer=%s version=%s",
		outcome, d.component, d.commit, d.manifest, d.signer, buildinfo.Version)
	if err != nil {
		line += fmt.Sprintf(" reason=%q", err.Error())
	}
	return line
}

func runner(ctx context.Context, cfg Config, dir, maintainer, fingerprint string, d *decision) error {
	host, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return fmt.Errorf("open the root: %w", err)
	}
	defer host.Close() //nolint:errcheck // every write is synced by WriteIn
	r, err := check(ctx, cfg, host, dir, fingerprint)
	if err != nil {
		return err
	}
	d.commit, d.manifest, d.signer = r.Manifest.Commit, hex.EncodeToString(r.ManifestSHA256[:]), r.Signer.Fingerprint()
	if r.Manifest.Component != d.component {
		return errors.New("the manifest is not of the runner component")
	}
	names := make([]string, len(runnerTable))
	for i, f := range runnerTable {
		names[i] = f.name
	}
	if !slices.Equal(slices.Sorted(slices.Values(names)), slices.Sorted(maps.Keys(r.Files))) {
		return errors.New("the manifest's files are not the runner's")
	}
	muid, err := maintainerUID(cfg, maintainer)
	if err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, false); err != nil {
		return err
	}
	absent, err := preflight(cfg, host, muid)
	if err != nil {
		return err
	}
	d.writing = true
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
func unitsAsWritten(ctx context.Context, cfg Config, reloaded bool) error {
	blocks, err := cfg.Show(ctx, runnerUnits, unitProps)
	if err != nil {
		return fmt.Errorf("cannot query the runner's units: %w", err)
	}
	if len(blocks) != len(runnerUnits) {
		return errors.New("cannot query the runner's units: an answer per unit is missing")
	}
	for i, u := range runnerUnits {
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

// preflight checks every path the install writes or creates, before the first write, and returns those absent.
// Absent means only "does not exist": any other error refuses. Nothing found is repaired, since others may
// have prepared it.
func preflight(cfg Config, host *os.Root, muid int) (map[string]bool, error) {
	for _, dir := range trustedDirs {
		if _, err := trustedPath(cfg, host, dir); err != nil {
			return nil, err
		}
	}
	absent := map[string]bool{}
	for _, dir := range slices.Concat(createdDirs, []string{stateDir}, maintainerDirs) {
		fi, err := host.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			absent[dir] = true
			continue
		case err != nil:
			return nil, fmt.Errorf("cannot stat /%s: %w", dir, err)
		}
		uid, gid, mode := cfg.UID, cfg.GID, fs.ModeDir|0o755
		// The group is looked up only for an inbox or objects that exist: before sysusers it may not.
		if slices.Contains(maintainerDirs, dir) {
			if gid, err = cfg.LookupGroup(runnerGroup); err != nil {
				return nil, fmt.Errorf("no group %s: %w", runnerGroup, err)
			}
			uid, mode = muid, fs.ModeDir|fs.ModeSetgid|0o750
		}
		if err := ownedAs(fi, uid, gid, mode); err != nil {
			return nil, fmt.Errorf("/%s: %w", dir, err)
		}
	}
	for _, f := range runnerTable {
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

// apply writes as the shell installer did: directories, then each file whole, then systemd's users, directories
// and units; it checks the units again after the reload and writes itself last. Each error names its step.
func apply(ctx context.Context, cfg Config, host *os.Root, r Release, maintainer string, muid int, absent map[string]bool) error {
	for _, dir := range createdDirs {
		if !absent[dir] {
			continue
		}
		if err := errors.Join(host.Mkdir(dir, 0o755), host.Chmod(dir, 0o755)); err != nil {
			return fmt.Errorf("step create /%s: %w", dir, err)
		}
	}
	last := runnerTable[len(runnerTable)-1]
	for _, f := range runnerTable[:len(runnerTable)-1] {
		if f.name == signersName && !absent[f.dest] {
			continue // check found the installed one equal to the bundle's
		}
		if err := wholefile.WriteIn(host, f.dest, r.Files[f.name], f.mode); err != nil {
			return fmt.Errorf("step write /%s: %w", f.dest, err)
		}
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
	if err := unitsAsWritten(ctx, cfg, true); err != nil {
		return fmt.Errorf("step check after the reload: %w", err)
	}
	if err := wholefile.WriteIn(host, last.dest, r.Files[last.name], last.mode); err != nil {
		return fmt.Errorf("step write /%s: %w", last.dest, err)
	}
	return nil
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

// logDecision writes line to stderr and to the journal through logger; a logger that fails is reported, not
// hidden.
func logDecision(ctx context.Context, line string) {
	slog.InfoContext(ctx, line)
	if err := runCommand(ctx, []string{"/usr/bin/logger", "-t", "balistid-install", "--", line}); err != nil {
		slog.ErrorContext(ctx, "the decision did not reach the journal", "err", err)
	}
}
