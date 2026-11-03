package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/status"
	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// Config is where and as whom balistid-install works. DefaultConfig is the host's; tests point it at a fake root
// owned by their own uid, a software key type and stand-in programs.
type Config struct {
	Root          string // the host's "/"
	UID, GID      int    // owner of every root-owned path it checks or writes
	KeyType       string // the only key type allowed_signers may hold
	SSHKeygen     string
	VerifyTimeout time.Duration
	Run           func(ctx context.Context, argv []string) error                                // a command that changes the host
	Show          func(ctx context.Context, names, props []string) ([]map[string]string, error) // systemctl show
	LookupUser    func(name string) (uid int, err error)
	LookupGroup   func(name string) (gid int, err error)
	Log           func(ctx context.Context, d Decision) // the decision of a run
}

// DefaultConfig is the configuration of a real host: root's paths, the token's key type (R2), the real commands.
func DefaultConfig() Config {
	return Config{Root: "/", KeyType: SKKeyType, SSHKeygen: "/usr/bin/ssh-keygen", VerifyTimeout: 10 * time.Second,
		Run: runCommand, Show: status.Show, LookupUser: lookupUID, LookupGroup: lookupGID, Log: logDecision}
}

const (
	bundleName  = "balistid-runner-bundle.tar"
	sigName     = "MANIFEST.sig"
	signersName = "allowed_signers"
	signersDir  = "etc/balistid"
	// maxSigBytes is about ten times an armored ed25519-sk signature, and the bootstrap's cap (release.py SIG_MAX_BYTES).
	maxSigBytes = 4 << 10
)

// Release is a bundle whose MANIFEST the trusted key signed and whose files are exactly the manifest's.
type Release struct {
	Manifest       Manifest
	ManifestSHA256 [32]byte
	Signer         Signer
	Files          map[string][]byte // by name, MANIFEST excluded
}

// Check reads the bundle and its signature from dir once and returns the release only when the signature
// verifies and every file matches its sha256; it writes nothing. The key is the installed allowed_signers, whose
// copy in the bundle must be identical; given a fingerprint (the first install), the bundle's own key must have it,
// and a key already installed must be that same key (ADR 0058, point 5).
func Check(ctx context.Context, cfg Config, dir, fingerprint string) (Release, error) {
	host, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return Release{}, fmt.Errorf("open the root: %w", err)
	}
	defer host.Close() //nolint:errcheck // read-only here
	return check(ctx, cfg, host, dir, fingerprint)
}

func check(ctx context.Context, cfg Config, host *os.Root, dir, fingerprint string) (Release, error) {
	in, err := os.OpenRoot(dir)
	if err != nil {
		return Release{}, fmt.Errorf("open %s: %w", dir, err)
	}
	defer in.Close() //nolint:errcheck // read-only
	tarBytes, err := wholefile.ReadIn(in, bundleName, MaxBundleBytes)
	if err != nil {
		return Release{}, fmt.Errorf("%s: %w", bundleName, err)
	}
	sig, err := wholefile.ReadIn(in, sigName, maxSigBytes)
	if err != nil {
		return Release{}, fmt.Errorf("%s: %w", sigName, err)
	}
	files, err := ReadBundle(tarBytes)
	if err != nil {
		return Release{}, err
	}
	signer, err := trustedSigner(cfg, host, files[signersName], fingerprint)
	if err != nil {
		return Release{}, err
	}
	text := files[manifestName]
	if err := verifySignature(ctx, cfg, signer, text, sig); err != nil {
		return Release{}, err
	}
	m, err := ParseManifest(text)
	if err != nil {
		return Release{}, err
	}
	delete(files, manifestName)
	names := make([]string, len(m.Files))
	for i, f := range m.Files {
		names[i] = f.Name
	}
	if !slices.Equal(names, slices.Sorted(maps.Keys(files))) {
		return Release{}, errors.New("the bundle's files are not the manifest's")
	}
	for _, f := range m.Files {
		if sha256.Sum256(files[f.Name]) != f.SHA256 {
			return Release{}, fmt.Errorf("%s does not match its sha256", f.Name)
		}
	}
	return Release{Manifest: m, ManifestSHA256: sha256.Sum256(text), Signer: signer, Files: files}, nil
}

// trustedSigner is the key a release must be signed with: the installed one, or on the first install the
// bundle's own if it has the fingerprint root typed. Either way the bundle carries exactly that line.
func trustedSigner(cfg Config, host *os.Root, bundled []byte, fingerprint string) (Signer, error) {
	file := path.Join(signersDir, signersName)
	if fingerprint != "" {
		if _, err := host.Lstat(file); errors.Is(err, fs.ErrNotExist) {
			s, err := ParseSigners(bundled, cfg.KeyType)
			if err != nil {
				return Signer{}, err
			}
			if s.Fingerprint() != fingerprint {
				return Signer{}, errors.New("the bundle's key does not have the typed fingerprint")
			}
			return s, nil
		}
		// A first install that stopped after writing the key runs again: the installed key must then pass
		// every check below and have the typed fingerprint too.
	}
	if err := rootDir(cfg, host, signersDir); err != nil {
		return Signer{}, err
	}
	fi, err := host.Lstat(file)
	if err != nil {
		return Signer{}, fmt.Errorf("/%s: %w", file, err)
	}
	if err := ownedAs(fi, cfg.UID, cfg.GID, 0o644); err != nil {
		return Signer{}, fmt.Errorf("/%s: %w", file, err)
	}
	data, err := wholefile.ReadIn(host, file, maxSignersBytes)
	if err != nil {
		return Signer{}, fmt.Errorf("/%s: %w", file, err)
	}
	s, err := ParseSigners(data, cfg.KeyType)
	if err != nil {
		return Signer{}, err
	}
	if !bytes.Equal(bundled, data) {
		return Signer{}, errors.New("the bundle's allowed_signers is not the installed one; a new key is installed by hand")
	}
	if fingerprint != "" && s.Fingerprint() != fingerprint {
		return Signer{}, errors.New("the installed key does not have the typed fingerprint")
	}
	return s, nil
}

// trustedPath checks every directory from the root down to name: a directory, not a link, owned by cfg.UID, not
// writable by group or other, not setgid. With the root standing for "/", os.Root contains nothing, so this is
// what keeps a write from being redirected. It returns name's own state.
func trustedPath(cfg Config, host *os.Root, name string) (fs.FileInfo, error) {
	p := "."
	var fi fs.FileInfo
	for _, part := range append([]string{"."}, strings.Split(name, "/")...) {
		p = path.Join(p, part)
		var err error
		if fi, err = host.Lstat(p); err != nil {
			return nil, fmt.Errorf("/%s: %w", p, err)
		}
		if err := trustedAncestor(cfg, fi); err != nil {
			return nil, fmt.Errorf("/%s: %w", p, err)
		}
	}
	return fi, nil
}

// rootDir checks name is on a trusted path and exactly root:root 0755, as an install leaves it.
func rootDir(cfg Config, host *os.Root, name string) error {
	fi, err := trustedPath(cfg, host, name)
	if err != nil {
		return err
	}
	if err := ownedAs(fi, cfg.UID, cfg.GID, fs.ModeDir|0o755); err != nil {
		return fmt.Errorf("/%s: %w", name, err)
	}
	return nil
}

func trustedAncestor(cfg Config, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return errors.New("not a directory")
	case !ok || int64(st.Uid) != int64(cfg.UID):
		return errors.New("not owned by root")
	case fi.Mode().Perm()&0o022 != 0:
		return errors.New("writable by group or other")
	case fi.Mode()&fs.ModeSetgid != 0:
		return errors.New("setgid")
	}
	return nil
}

// ownedAs checks fi is uid:gid with exactly mode (type bits included) and, for a file, one link.
func ownedAs(fi fs.FileInfo, uid, gid int, mode fs.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok || int64(st.Uid) != int64(uid) || int64(st.Gid) != int64(gid):
		return fmt.Errorf("not owned by %d:%d", uid, gid)
	case fi.Mode() != mode:
		return fmt.Errorf("mode %v, not %v", fi.Mode(), mode)
	case !fi.IsDir() && st.Nlink != 1:
		return errors.New("more than one link")
	}
	return nil
}

// verifySignature runs ssh-keygen -Y verify as ADR 0053 point 3 names it, with the manifest on stdin and the
// signer's line and the signature as pipes, so nothing is written to disk and no path is read twice. Only
// exit 0 passes; its output is discarded, never logged.
func verifySignature(ctx context.Context, cfg Config, signer Signer, manifest, sig []byte) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.VerifyTimeout)
	defer cancel()
	var readers, writers []*os.File
	defer func() {
		for _, f := range slices.Concat(readers, writers) {
			_ = f.Close() // closing twice only reports os.ErrClosed
		}
	}()
	for range 2 {
		r, w, err := os.Pipe()
		if err != nil {
			return fmt.Errorf("ssh-keygen: %w", err)
		}
		readers, writers = append(readers, r), append(writers, w)
	}
	cmd := exec.CommandContext(ctx, cfg.SSHKeygen, "-Y", "verify", "-f", "/dev/fd/3", "-I", Principal, //nolint:gosec // a fixed binary and argv
		"-n", Namespace, "-s", "/dev/fd/4")
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(manifest)
	cmd.ExtraFiles = readers
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("the signature does not verify: ssh-keygen: %w", err)
	}
	// A pipe can hold less than the input when the uid's pipe budget is spent, so ssh-keygen must already read it;
	// once it exits or is killed, a blocked write fails and its goroutine ends.
	for _, r := range readers {
		_ = r.Close()
	}
	written := make(chan error, len(writers))
	for i, data := range [][]byte{signer.Line, sig} {
		go func() {
			_, err := writers[i].Write(data)
			written <- errors.Join(err, writers[i].Close())
		}()
	}
	err := cmd.Wait()
	werr := errors.Join(<-written, <-written)
	if err != nil {
		return fmt.Errorf("the signature does not verify: ssh-keygen: %w", err)
	}
	if werr != nil {
		return fmt.Errorf("the signature does not verify: writing to ssh-keygen: %w", werr)
	}
	return checkSSHSIG(signer, manifest, sig)
}
