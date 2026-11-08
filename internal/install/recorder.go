package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// RecorderNotice is what the recorder's install changes beyond its files, said before it writes (ADR 0068, point 3).
const RecorderNotice = "installing the recorder turns io_uring off for the whole host at the next boot " +
	"(kernel.io_uring_disabled = 2) and locks the audit rules from that boot until the one after it (-e 2): " +
	"reboot to start recording"

// recorderTable is the recorder component (ADR 0068, point 2): units, sysusers and tmpfiles under /etc as the
// runner's, the sensor's files where the range image puts them (internal/rangevm imageFiles).
var recorderTable = []target{
	{"balistid-collector", "usr/local/lib/balistid/balistid-collector", 0o755},
	{"balistid-ledger", "usr/local/lib/balistid/balistid-ledger", 0o755},
	{"balistid-auditstat", "usr/local/lib/balistid/balistid-auditstat", 0o755},
	{"balistid", "usr/local/bin/balistid", 0o755},
	{"balistid-collector.service", "etc/systemd/system/balistid-collector.service", 0o644},
	{"balistid-collector.socket", "etc/systemd/system/balistid-collector.socket", 0o644},
	{"balistid-ledger.service", "etc/systemd/system/balistid-ledger.service", 0o644},
	{"balistid-auditstat.service", "etc/systemd/system/balistid-auditstat.service", 0o644},
	{"collector-sysusers.conf", "etc/sysusers.d/balistid-collector.conf", 0o644},
	{"ledger-sysusers.conf", "etc/sysusers.d/balistid-ledger.conf", 0o644},
	{"auditstat-sysusers.conf", "etc/sysusers.d/balistid-auditstat.conf", 0o644},
	{"collector-tmpfiles.conf", "etc/tmpfiles.d/balistid-collector.conf", 0o644},
	{"ledger-tmpfiles.conf", "etc/tmpfiles.d/balistid-ledger.conf", 0o644},
	{"balistid.rules", rulesDir + "/balistid.rules", 0o640},
	{"auditd.conf", auditdConf, 0o640},
	{"laurel-plugin.conf", "etc/audit/plugins.d/laurel.conf", 0o640},
	{"laurel-config.toml", "etc/laurel/config.toml", 0o644},
	{"sysctl.conf", "etc/sysctl.d/90-balistid.conf", 0o644},
	{signersName, path.Join(signersDir, signersName), 0o644},
	{"balistid-install", "usr/local/lib/balistid/balistid-install", 0o755},
}

var recorderComponent = component{name: "recorder", table: recorderTable,
	units: []string{"balistid-collector.socket", "balistid-collector.service", "balistid-ledger.service",
		"balistid-auditstat.service"},
	trusted: []string{"etc/systemd/system", "usr/local/lib", "usr/local/bin", "var/lib", "etc/audit", rulesDir,
		"etc/audit/plugins.d", "etc/sysctl.d"},
	created:  []string{"usr/local/lib/balistid", "etc/sysusers.d", "etc/tmpfiles.d", signersDir, "etc/laurel"},
	tmpfiles: []string{"collector-tmpfiles.conf", "ledger-tmpfiles.conf"},
	// The sensor's files change the next boot: locked rules, io_uring off, Laurel aimed at the collector's socket.
	late: []string{"balistid.rules", "auditd.conf", "laurel-plugin.conf", "laurel-config.toml", "sysctl.conf"}}

const (
	rulesDir   = "etc/audit/rules.d"
	auditdConf = "etc/audit/auditd.conf"
	// auditdOrig keeps the auditd.conf the first install replaced, for the uninstall.
	auditdOrig = signersDir + "/auditd.conf.orig"
	ledgerKey  = signersDir + "/ledger-key"
	ledgerPub  = signersDir + "/ledger-key.pub"
	ledgerLog  = stateDir + "/ledger/log"
	// backlogLimit is the kernel's queue before auditd loads the rules' -b (ADR 0004; range/mkosi.conf).
	backlogLimit = 65536
	maxKeyBytes  = 1 << 10
	maxConfBytes = 64 << 10
)

// hostPrograms are what the sensor runs by absolute path from the distribution and Laurel's package (ADR 0004, 0068).
// augenrules' shebang is /usr/bin/env, and it runs /usr/sbin/restorecon where that exists (optionalPrograms).
var hostPrograms = []string{"usr/bin/laurel", "usr/bin/augenrules", "usr/bin/auditd", "usr/bin/auditctl", "usr/bin/env"}

var optionalPrograms = []string{"usr/sbin/restorecon"}

// pathPrograms are what audit 4.2.1's augenrules runs through PATH at boot (its shebang is `env sh`); each must be
// /usr/bin's and no directory systemd searches before it may hold the name.
var pathPrograms = []string{"sh", "awk", "cat", "chmod", "cmp", "cp", "mktemp", "rm", "sort", "xargs"}

// bootPathBefore are the directories of systemd's default PATH before /usr/bin (`systemd-path search-binaries-default`
// and, where /usr/sbin is no link to bin, /usr/sbin).
var bootPathBefore = []string{"usr/local/sbin", "usr/local/bin", "usr/sbin"}

// Recorder installs the recorder component from dir (ADR 0068). Every check, the signature first, runs before the
// first write; a refusal changes nothing and runs no command. A failed step stops with what was written in place.
// It enables the units and starts nothing: the reboot loads and locks the rules. Every outcome is logged.
func Recorder(ctx context.Context, cfg Config, dir, fingerprint string) error {
	d := Decision{Outcome: "installed", Component: "recorder", Version: buildinfo.Version}
	writing := false
	err := recorder(ctx, cfg, dir, fingerprint, &d, &writing)
	switch {
	case err != nil && writing:
		d.Outcome, d.Reason = "stopped", err.Error()
	case err != nil:
		d.Outcome, d.Reason = "refused", err.Error()
	}
	cfg.Log(ctx, d)
	return err
}

func recorder(ctx context.Context, cfg Config, dir, fingerprint string, d *Decision, writing *bool) error {
	host, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return fmt.Errorf("open the root: %w", err)
	}
	defer host.Close() //nolint:errcheck // every write is synced by WriteIn
	c := recorderComponent
	r, err := c.released(ctx, cfg, host, dir, fingerprint, d)
	if err != nil {
		return err
	}
	if err := hostReady(cfg, host); err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, c.units, false); err != nil {
		return err
	}
	absent, err := preflight(cfg, host, c, 0, nil, r)
	if err != nil {
		return err
	}
	keyAbsent, err := installedLedgerKey(cfg, host)
	if err != nil {
		return err
	}
	orig, err := originalAuditdConf(cfg, host)
	if err != nil {
		return err
	}
	*writing = true
	if err := c.createDirs(host, absent); err != nil {
		return err
	}
	if orig != nil {
		if err := wholefile.WriteIn(host, auditdOrig, orig, 0o640); err != nil {
			return fmt.Errorf("step write /%s: %w", auditdOrig, err)
		}
	}
	if err := c.writeFiles(host, r, absent, false); err != nil {
		return err
	}
	if keyAbsent {
		if err := writeLedgerKey(host); err != nil {
			return err
		}
	}
	if err := runAll(ctx, cfg, []string{"/usr/bin/systemd-sysusers", "/etc/sysusers.d/balistid-collector.conf",
		"/etc/sysusers.d/balistid-ledger.conf", "/etc/sysusers.d/balistid-auditstat.conf"},
		[]string{"/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/balistid-collector.conf",
			"/etc/tmpfiles.d/balistid-ledger.conf"},
		[]string{"/usr/bin/systemctl", "daemon-reload"}); err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, c.units, true); err != nil {
		return fmt.Errorf("step check after the reload: %w", err)
	}
	if err := runAll(ctx, cfg, append([]string{"/usr/bin/systemctl", "enable", "--", "auditd.service"}, c.units...)); err != nil {
		return err
	}
	if err := c.writeFiles(host, r, absent, true); err != nil {
		return err
	}
	return c.writeInstaller(host, r)
}

// hostReady refuses a host the sensor cannot run on as installed: its programs missing or writable by others, no
// _laurel, a kernel booted without audit=1 and the backlog limit, or other rules augenrules would merge (ADR 0068).
func hostReady(cfg Config, host *os.Root) error {
	for _, p := range hostPrograms {
		if err := rootProgram(cfg, host, p); err != nil {
			return err
		}
	}
	for _, p := range optionalPrograms {
		p = usrMerged(host, p)
		if _, err := host.Lstat(p); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := rootProgram(cfg, host, p); err != nil {
			return err
		}
	}
	if err := bootPath(cfg, host); err != nil {
		return err
	}
	if _, err := cfg.LookupUser("_laurel"); err != nil {
		return fmt.Errorf("no user _laurel: install Laurel from packaging/laurel first: %w", err)
	}
	cmdline, err := wholefile.ReadIn(host, "proc/cmdline", 4<<10)
	if err != nil {
		return fmt.Errorf("/proc/cmdline: %w", err)
	}
	if !bootedForAudit(string(cmdline)) {
		return fmt.Errorf("the kernel command line must be printable ASCII with exactly audit=1 and "+
			"audit_backlog_limit=%d or more before --, and no other audit parameter: set the boot entry's options and reboot",
			backlogLimit)
	}
	if err := otherRules(cfg, host); err != nil {
		return err
	}
	return otherSysctl(cfg, host)
}

// bootPath refuses a host where augenrules at boot could run another program than /usr/bin's: each of pathPrograms
// must be root's there, and no directory systemd searches first may hold its name, whatever it is.
func bootPath(cfg Config, host *os.Root) error {
	for _, name := range pathPrograms {
		if err := rootProgram(cfg, host, "usr/bin/"+name); err != nil {
			return err
		}
		for _, dir := range bootPathBefore {
			fi, err := host.Lstat(dir)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				return fmt.Errorf("/%s: %w", dir, err)
			case fi.Mode()&fs.ModeSymlink != 0:
				if dir != "usr/sbin" || !sbinIsBin(host) {
					return fmt.Errorf("/%s is a link; only /usr/sbin may be one, to bin", dir)
				}
				continue
			}
			if _, err := trustedPath(cfg, host, dir); err != nil {
				return err
			}
			switch _, err := host.Lstat(path.Join(dir, name)); {
			case err == nil:
				return fmt.Errorf("/%s/%s comes before /usr/bin/%s on the boot PATH: augenrules would run it", dir, name, name)
			case !errors.Is(err, fs.ErrNotExist):
				return fmt.Errorf("/%s/%s: %w", dir, name, err)
			}
		}
	}
	return nil
}

// sysctlDirs are where systemd-sysctl reads settings; it applies all of them by file name, so any one of them could
// set io_uring_disabled after the recorder's 90-balistid.conf.
var sysctlDirs = []string{"etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d"}

// otherSysctl refuses any sysctl file but the recorder's that names io_uring_disabled: exit rules do not see
// io_uring's operations (ADR 0004), and nothing at runtime would show it on again. It changes none of them.
func otherSysctl(cfg Config, host *os.Root) error {
	files := []string{"etc/sysctl.conf"}
	for _, dir := range sysctlDirs {
		names, err := dirNames(cfg, host, dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, n := range names {
			if p := path.Join(dir, n); strings.HasSuffix(n, ".conf") && p != "etc/sysctl.d/90-balistid.conf" {
				files = append(files, p)
			}
		}
	}
	for _, p := range files {
		data, err := sysctlFile(cfg, host, p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return err
		case bytes.Contains(data, []byte("io_uring_disabled")):
			return fmt.Errorf("/%s sets io_uring_disabled, which the recorder's sysctl file sets: remove it first", p)
		}
	}
	return nil
}

// dirNames lists dir, which must be a directory on a trusted path (so opening it cannot block on a FIFO).
func dirNames(cfg Config, host *os.Root, dir string) ([]string, error) {
	if _, err := trustedPath(cfg, host, dir); err != nil {
		return nil, err
	}
	f, err := host.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", dir, err)
	}
	defer f.Close() //nolint:errcheck // read-only
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", dir, err)
	}
	return names, nil
}

// sysctlFile reads p as systemd-sysctl would apply it. A link is followed by nobody here: only a mask (to /dev/null)
// and any etc/sysctl.d link to ../sysctl.conf (Debian's 99-sysctl.conf), read on its own, pass; any other refuses.
// What is read must be root's plain file only root may write, on a trusted path; a FIFO or other type refuses.
func sysctlFile(cfg Config, host *os.Root, p string) ([]byte, error) {
	fi, err := host.Lstat(p)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", p, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := host.Readlink(p)
		if err != nil {
			return nil, fmt.Errorf("/%s: %w", p, err)
		}
		if target == "/dev/null" || target == "../sysctl.conf" && path.Dir(p) == "etc/sysctl.d" {
			return nil, nil
		}
		return nil, fmt.Errorf("/%s is a link the installer does not follow: make it a file or a mask", p)
	}
	if _, err := trustedPath(cfg, host, path.Dir(p)); err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(cfg.UID) || fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("/%s is not root's file that only root may write", p)
	}
	data, err := wholefile.ReadIn(host, p, maxConfBytes)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", p, err)
	}
	return data, nil
}

// rootProgram refuses p unless it is root's regular executable file only root may write, in a trusted directory.
// A link is followed only to a bare name in the same directory (/usr/bin/awk to gawk), which is then checked too.
func rootProgram(cfg Config, host *os.Root, p string) error {
	if _, err := trustedPath(cfg, host, path.Dir(p)); err != nil {
		return err
	}
	fi, err := host.Lstat(p)
	if err != nil {
		return fmt.Errorf("/%s: %w", p, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := host.Readlink(p)
		if err != nil || target == "" || strings.Contains(target, "/") || target == "." || target == ".." {
			return fmt.Errorf("/%s links outside its directory", p)
		}
		p = path.Join(path.Dir(p), target)
		if fi, err = host.Lstat(p); err != nil {
			return fmt.Errorf("/%s: %w", p, err)
		}
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 || fi.Mode().Perm()&0o100 == 0 || !ok ||
		int64(st.Uid) != int64(cfg.UID) {
		return fmt.Errorf("/%s is not an executable regular file of root's that only root may write", p)
	}
	return nil
}

// sbinIsBin is whether /usr/sbin is the merged-/usr link to bin beside it.
func sbinIsBin(host *os.Root) bool {
	target, err := host.Readlink("usr/sbin")
	return err == nil && target == "bin"
}

// usrMerged is p with usr/sbin read as usr/bin where /usr/sbin is the merged-/usr link, so rootProgram checks the file.
func usrMerged(host *os.Root, p string) string {
	if rest, ok := strings.CutPrefix(p, "usr/sbin/"); ok && sbinIsBin(host) {
		return "usr/bin/" + rest
	}
	return p
}

// bootedForAudit is whether the command line holds, before "--" (what follows goes to init), exactly one audit=1
// and one audit_backlog_limit of at least backlogLimit in plain decimal (the kernel reads base 0), and no other
// parameter that names audit anywhere: the kernel and systemd read "-" as "_" in names, and auditd's unit does not
// start on audit=0 or audit=off. Only printable ASCII words split by spaces are read; anything else refuses.
func bootedForAudit(cmdline string) bool {
	cmdline = strings.TrimSuffix(cmdline, "\n")
	if strings.ContainsFunc(cmdline, func(r rune) bool { return r < ' ' || r > '~' || r == '"' }) {
		return false
	}
	audit, limits, kernel := 0, 0, true
	for _, f := range strings.Split(cmdline, " ") {
		if f == "--" {
			kernel = false
			continue
		}
		key, value, _ := strings.Cut(f, "=")
		key = strings.ReplaceAll(key, "-", "_")
		switch {
		case !strings.Contains(key, "audit"):
		case !kernel:
			return false
		case key == "audit" && value == "1":
			audit++
		case key == "audit_backlog_limit":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || value[0] == '0' || n < backlogLimit {
				return false
			}
			limits++
		default:
			return false
		}
	}
	return audit == 1 && limits == 1
}

// otherRules refuses any *.rules in rules.d but the recorder's: augenrules would merge it and the collector read the
// loaded rules as rules-differ (ADR 0059). It moves none of them.
func otherRules(cfg Config, host *os.Root) error {
	names, err := dirNames(cfg, host, rulesDir)
	if err != nil {
		return err
	}
	var other []string
	for _, n := range names {
		if strings.HasSuffix(n, ".rules") && n != "balistid.rules" {
			other = append(other, n)
		}
	}
	if len(other) > 0 {
		slices.Sort(other)
		return fmt.Errorf("/%s holds rules the recorder does not own; move them out first: %s", rulesDir,
			strings.Join(other, " "))
	}
	return nil
}

// installedLedgerKey is true when no ledger key is installed. An installed key is kept only as a root-owned pair,
// private 0600 and public 0644, that signs and verifies: a new key would start another log.
func installedLedgerKey(cfg Config, host *os.Root) (absent bool, err error) {
	_, privErr := host.Lstat(ledgerKey)
	_, pubErr := host.Lstat(ledgerPub)
	switch {
	case errors.Is(privErr, fs.ErrNotExist) && errors.Is(pubErr, fs.ErrNotExist):
		return true, nil
	case errors.Is(privErr, fs.ErrNotExist) && pubErr == nil:
		// A public key alone, before the ledger's log exists, is what a stopped install leaves (writeLedgerKey
		// writes it first): nothing was signed with its private half, so a new pair replaces it.
		if _, err := rootFile(cfg, host, ledgerPub, 0o644, maxKeyBytes); err != nil {
			return false, err
		}
		if _, err := host.Lstat(ledgerLog); errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, errors.New("the ledger's public key is installed without its private key, and its log exists")
	case errors.Is(pubErr, fs.ErrNotExist):
		return false, errors.New("the ledger's private key is installed without its public key")
	}
	skey, err := rootFile(cfg, host, ledgerKey, 0o600, maxKeyBytes)
	if err != nil {
		return false, err
	}
	vkey, err := rootFile(cfg, host, ledgerPub, 0o644, maxKeyBytes)
	if err != nil {
		return false, err
	}
	signer, err := note.NewSigner(strings.TrimSpace(string(skey)))
	if err != nil {
		return false, errors.New("/" + ledgerKey + " is not a note signing key")
	}
	verifier, err := note.NewVerifier(strings.TrimSpace(string(vkey)))
	if err != nil {
		return false, errors.New("/" + ledgerPub + " is not a note verifier key")
	}
	msg, err := note.Sign(&note.Note{Text: "balistid-install key check\n"}, signer)
	if err != nil {
		return false, fmt.Errorf("the installed ledger key cannot sign: %w", err)
	}
	if _, err := note.Open(msg, note.VerifierList(verifier)); err != nil {
		return false, errors.New("the installed ledger keys are not one pair")
	}
	return false, nil
}

// rootFile reads name, root's with exactly mode and one link, on a trusted path, at most limit bytes.
func rootFile(cfg Config, host *os.Root, name string, mode fs.FileMode, limit int64) ([]byte, error) {
	if _, err := trustedPath(cfg, host, path.Dir(name)); err != nil {
		return nil, err
	}
	fi, err := host.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", name, err)
	}
	if err := ownedAs(fi, cfg.UID, cfg.GID, mode); err != nil {
		return nil, fmt.Errorf("/%s: %w", name, err)
	}
	data, err := wholefile.ReadIn(host, name, limit)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", name, err)
	}
	return data, nil
}

// originalAuditdConf is the auditd.conf to keep as auditdOrig: the installed one while none is kept, else nil. A
// kept one must be root's 0640 file as written; the audit package's auditd.conf must exist to be kept.
func originalAuditdConf(cfg Config, host *os.Root) ([]byte, error) {
	data, err := wholefile.ReadIn(host, auditdConf, maxConfBytes)
	if err != nil {
		return nil, fmt.Errorf("/%s: %w", auditdConf, err)
	}
	switch _, err := host.Lstat(auditdOrig); {
	case err == nil:
		_, err := rootFile(cfg, host, auditdOrig, 0o640, maxConfBytes)
		return nil, err
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("/%s: %w", auditdOrig, err)
	}
	return data, nil
}

// writeLedgerKey makes the ledger's checkpoint key under a new random origin (ADR 0068, point 3).
func writeLedgerKey(host *os.Root) error {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("step make the ledger key: %w", err)
	}
	skey, vkey, err := note.GenerateKey(rand.Reader, "balistid.dev/log/"+hex.EncodeToString(id))
	if err != nil {
		return fmt.Errorf("step make the ledger key: %w", err)
	}
	if err := wholefile.WriteIn(host, ledgerPub, []byte(vkey+"\n"), 0o644); err != nil {
		return fmt.Errorf("step write /%s: %w", ledgerPub, err)
	}
	if err := wholefile.WriteIn(host, ledgerKey, []byte(skey+"\n"), 0o600); err != nil {
		return fmt.Errorf("step write /%s: %w", ledgerKey, err)
	}
	return nil
}
