package rangevm

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Retention (R5): base images are about a GiB each; results are small.
const (
	keepImages   = 3
	keepResults  = 100
	maxManifest  = 8 << 20
	guestUnit    = "kordon-range-guest.service"
	stampLayout  = "20060102T150405Z"
	resultSchema = 1
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Result is what one run stores: the verdict and everything that identifies what ran.
type Result struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	RangeCommit   string          `json:"range_commit"`
	Image         string          `json:"image"`
	ImageSHA256   string          `json:"image_sha256"`
	TargetKernel  string          `json:"target_kernel"`
	GuestKernel   string          `json:"guest_kernel"`
	Verdict       string          `json:"verdict"`
	Reason        string          `json:"reason"`
	Manifest      json.RawMessage `json:"manifest"`
}

// Build exports the commit at HEAD of the repository at root, so neither uncommitted nor untracked
// files (mkosi also reads untracked range/mkosi.local.conf) reach the image, builds the guest
// program and range/ from that export, and stores the image with its commit under cache/images.
// Tool output goes to log.
func Build(ctx context.Context, root, cache string, log io.Writer) (image string, err error) {
	unlock, err := lock(cache)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	stage, err := os.MkdirTemp(cache, "stage-")
	if err != nil {
		return "", fmt.Errorf("staging directory: %w", err)
	}
	defer func() { err = errors.Join(err, removeDir(stage)) }()

	head, err := exec.CommandContext(ctx, "/usr/bin/git", "-C", root, "rev-parse", "--verify", "HEAD^{commit}").Output() //nolint:gosec // absolute binary, fixed argv
	commit := strings.TrimSpace(string(head))
	if err != nil || !commitRE.MatchString(commit) {
		return "", fmt.Errorf("resolve HEAD: %q: %w", commit, err)
	}
	src, tree := filepath.Join(stage, "src"), filepath.Join(stage, "tree")
	if err := os.Mkdir(src, 0o700); err != nil {
		return "", fmt.Errorf("export directory: %w", err)
	}
	steps := []*exec.Cmd{
		exec.CommandContext(ctx, "/usr/bin/git", "-C", root, "archive", "--format=tar", "-o", filepath.Join(stage, "src.tar"), commit),                     //nolint:gosec // absolute binary, fixed argv
		exec.CommandContext(ctx, "/usr/bin/tar", "-xf", filepath.Join(stage, "src.tar"), "-C", src),                                                        //nolint:gosec // absolute binary, fixed argv
		exec.CommandContext(ctx, "/usr/bin/go", "build", "-trimpath", "-o", filepath.Join(tree, "usr/lib/kordon-range/guest"), "./cmd/kordon-range-guest"), //nolint:gosec // absolute binary, fixed argv
	}
	steps[2].Dir = src
	steps[2].Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local")
	for _, cmd := range steps {
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("%s: %w", filepath.Base(cmd.Path), err)
		}
	}
	unit, err := os.ReadFile(filepath.Join(src, "range", guestUnit)) //nolint:gosec // our own export
	if err != nil {
		return "", fmt.Errorf("guest unit: %w", err)
	}
	unitDir := filepath.Join(tree, "usr/lib/systemd/system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil { //nolint:gosec // becomes a system directory in the image
		return "", fmt.Errorf("guest unit: %w", err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, guestUnit), unit, 0o644); err != nil { //nolint:gosec // units are world-readable in the image
		return "", fmt.Errorf("guest unit: %w", err)
	}

	out, err := os.MkdirTemp(cache, "build-")
	if err != nil {
		return "", fmt.Errorf("build directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removeDir(out))
		}
	}()
	mkosi := exec.CommandContext(ctx, "/usr/bin/mkosi", "--directory="+filepath.Join(src, "range"), //nolint:gosec // absolute binary, fixed argv
		"--extra-tree="+tree, "--output-directory="+out, "build")
	mkosi.Stdout, mkosi.Stderr = log, log
	if err := mkosi.Run(); err != nil {
		return "", fmt.Errorf("mkosi: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(out, "commit"), []byte(commit+"\n")); err != nil {
		return "", err
	}
	sum, err := fileSHA256(ctx, filepath.Join(out, "image.raw"))
	if err != nil {
		return "", err
	}
	images := filepath.Join(cache, "images")
	if err := os.MkdirAll(images, 0o700); err != nil {
		return "", fmt.Errorf("image directory: %w", err)
	}
	dest := filepath.Join(images, time.Now().UTC().Format(stampLayout)+"-"+sum[:16])
	if err := os.Rename(out, dest); err != nil {
		return "", fmt.Errorf("store image: %w", err)
	}
	return filepath.Join(dest, "image.raw"), prune(images, keepImages)
}

// Check runs the self-test of image once and stores its Result and serial log under
// state/results/<id>; a run that ends in an error leaves no result directory behind.
func Check(ctx context.Context, image, cache, state string) (res Result, err error) {
	unlock, err := lock(cache)
	if err != nil {
		return Result{}, err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	sum, err := fileSHA256(ctx, image)
	if err != nil {
		return Result{}, err
	}
	dir := filepath.Dir(image)
	manifest, err := readManifest(filepath.Join(dir, "image.manifest"))
	if err != nil {
		return Result{}, err
	}
	commit, err := readCommit(filepath.Join(dir, "commit"))
	if err != nil {
		return Result{}, err
	}

	resultsDir := filepath.Join(state, "results")
	if err := os.MkdirAll(resultsDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("results directory: %w", err)
	}
	if err := prune(resultsDir, keepResults-1); err != nil {
		return Result{}, err
	}
	var token [4]byte
	if _, err := rand.Read(token[:]); err != nil {
		return Result{}, fmt.Errorf("run id: %w", err)
	}
	id := time.Now().UTC().Format(stampLayout) + "-" + hex.EncodeToString(token[:])
	out := filepath.Join(resultsDir, id)
	if err := os.Mkdir(out, 0o700); err != nil {
		return Result{}, fmt.Errorf("result directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removeDir(out))
		}
	}()
	serial, err := os.OpenFile(filepath.Join(out, "serial.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // our own results directory
	if err != nil {
		return Result{}, fmt.Errorf("serial log: %w", err)
	}
	outcome, runErr := Run(ctx, image, filepath.Join(cache, "runs"), serial)
	if err := errors.Join(runErr, serial.Close()); err != nil {
		return Result{}, err
	}

	res = Result{
		SchemaVersion: resultSchema, ID: id, RangeCommit: commit, Image: image,
		ImageSHA256: sum, TargetKernel: TargetKernel, Manifest: manifest,
	}
	if outcome.Invalid != "" {
		res.Verdict, res.Reason = Invalid, outcome.Invalid
	} else {
		res.Verdict, res.Reason = Selftest(outcome.Facts)
		for _, f := range outcome.Facts {
			if f.Name == FactKernel {
				res.GuestKernel = f.Value
			}
		}
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("encode result: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(out, "result.json"), data); err != nil {
		return Result{}, err
	}
	return res, nil
}

// lock lets one kordon-range at a time own the cache, then removes the staging, build and run
// directories a killed or crashed earlier invocation left behind (R5). The lock ends with the
// process, so a crash never leaves it held.
func lock(cache string) (unlock func() error, err error) {
	if err := os.MkdirAll(filepath.Join(cache, "runs"), 0o700); err != nil {
		return nil, fmt.Errorf("cache directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(cache, "lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // our own cache directory
	if err != nil {
		return nil, fmt.Errorf("cache lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(fmt.Errorf("another kordon-range is running (%s): %w", f.Name(), err), f.Close())
	}
	var errs []error
	for _, pattern := range []string{"stage-*", "build-*", "runs/run-*"} {
		stale, err := filepath.Glob(filepath.Join(cache, pattern))
		errs = append(errs, err)
		for _, d := range stale {
			errs = append(errs, removeDir(d))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, errors.Join(fmt.Errorf("remove stale directories: %w", err), f.Close())
	}
	return func() error {
		if err := f.Close(); err != nil {
			return fmt.Errorf("release cache lock: %w", err)
		}
		return nil
	}, nil
}

// openRegular opens path for reading without blocking on a FIFO or device and refuses anything
// that is not a regular file.
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // the maintainer names the image; its files sit next to it
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open %s: %w", path, err), f.Close())
	}
	return f, nil
}

func readSmall(path string, limit int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return data, nil
}

// readManifest returns mkosi's package manifest if it is the version we read and pins the
// target kernel package, so a stored PASS always names what the image contained (ADR 0009, point 8).
func readManifest(path string) (json.RawMessage, error) {
	data, err := readSmall(path, maxManifest)
	if err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	var m struct {
		ManifestVersion int          `json:"manifest_version"`
		Packages        []pkgVersion `json:"packages"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	if m.ManifestVersion != 1 {
		return nil, fmt.Errorf("image manifest version %d, want 1", m.ManifestVersion)
	}
	kernelPkg := strings.Replace(TargetKernel, "-", ".", 1) // uname 7.2.8-arch1-2 is package 7.2.8.arch1-2
	if !slices.Contains(m.Packages, pkgVersion{Name: "linux", Version: kernelPkg}) {
		return nil, fmt.Errorf("image manifest has no linux %s", kernelPkg)
	}
	return data, nil
}

type pkgVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func readCommit(path string) (string, error) {
	data, err := readSmall(path, 64)
	if err != nil {
		return "", fmt.Errorf("image commit: %w", err)
	}
	commit := string(bytes.TrimSpace(data))
	if !commitRE.MatchString(commit) {
		return "", fmt.Errorf("image commit %q is not a full commit id", commit)
	}
	return commit, nil
}

func fileSHA256(ctx context.Context, path string) (string, error) {
	f, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // read-only file
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx, f}); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ctxReader stops a long read when ctx ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	n, err := c.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("read: %w", err)
	}
	return n, err //nolint:wrapcheck // io.EOF must stay unwrapped for io.Copy
}

// writeFileAtomic follows ENGINEERING.md 7 for whole files: temp file, fsync, rename, fsync dir.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_, werr := tmp.Write(data)
	if err := errors.Join(werr, tmp.Sync(), tmp.Close()); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), os.Remove(tmp.Name()))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), os.Remove(tmp.Name()))
	}
	d, err := os.Open(dir) //nolint:gosec // our own directory
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}

func removeDir(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// prune keeps the newest keep entries of dir; names start with a UTC stamp, so name order is age.
func prune(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("retention %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	var errs []error
	for len(names) > keep {
		errs = append(errs, removeDir(filepath.Join(dir, names[0])))
		names = names[1:]
	}
	return errors.Join(errs...)
}
