package install

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/Balistid/balistid-blue/internal/buildinfo"
)

// judgeTable is the judge component (ADR 0074, point 1) in the order it is written; the installer goes last. It
// holds no file of the recorder but the shared allowed_signers and installer.
var judgeTable = []target{
	{"balistid-judge", "usr/local/lib/balistid/balistid-judge", 0o755},
	{"balistid-judge.service", "etc/systemd/system/balistid-judge.service", 0o644},
	{signersName, path.Join(signersDir, signersName), 0o644},
	{"balistid-install", "usr/local/lib/balistid/balistid-install", 0o755},
}

// judgeComponent has no sysusers or tmpfiles file: it runs as the collector's uid, which the recorder made, and
// systemd makes its state directory. Its unit has no [Install] section and no timer, so nothing is enabled.
var judgeComponent = component{name: "judge", table: judgeTable,
	units:   []string{"balistid-judge.service"},
	trusted: []string{"etc/systemd/system", "usr/local/lib", "var/lib"},
	created: []string{"usr/local/lib/balistid", signersDir}}

// Judge installs the judge component from dir (ADR 0074). Every check, the signature first, runs before the first
// write; a refusal changes nothing and runs no command. A failed step stops with what was written in place. It
// reloads systemd and enables and starts nothing. Every outcome is logged through cfg.Log.
func Judge(ctx context.Context, cfg Config, dir, fingerprint string) error {
	d := Decision{Outcome: "installed", Component: "judge", Version: buildinfo.Version}
	writing := false
	err := judge(ctx, cfg, dir, fingerprint, &d, &writing)
	switch {
	case err != nil && writing:
		d.Outcome, d.Reason = "stopped", err.Error()
	case err != nil:
		d.Outcome, d.Reason = "refused", err.Error()
	}
	cfg.Log(ctx, d)
	return err
}

func judge(ctx context.Context, cfg Config, dir, fingerprint string, d *Decision, writing *bool) error {
	host, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return fmt.Errorf("open the root: %w", err)
	}
	defer host.Close() //nolint:errcheck // every write is synced by WriteIn
	c := judgeComponent
	r, err := c.released(ctx, cfg, host, dir, fingerprint, d)
	if err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, c.units, false); err != nil {
		return err
	}
	absent, err := preflight(cfg, host, c, 0, nil, r)
	if err != nil {
		return err
	}
	*writing = true
	if err := c.createDirs(host, absent); err != nil {
		return err
	}
	if err := c.writeFiles(host, r, absent, false); err != nil {
		return err
	}
	if err := runAll(ctx, cfg, []string{"/usr/bin/systemctl", "daemon-reload"}); err != nil {
		return err
	}
	if err := unitsAsWritten(ctx, cfg, c.units, true); err != nil {
		return fmt.Errorf("step check after the reload: %w", err)
	}
	return c.writeInstaller(host, r)
}
