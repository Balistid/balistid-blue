package rangevm

import (
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
	"runtime/debug"
	"slices"
	"time"
)

// Retention (R5): base images are a few hundred MiB each; results are small.
const (
	keepImages   = 3
	keepResults  = 100
	maxManifest  = 8 << 20
	guestUnit    = "kordon-range-guest.service"
	stampLayout  = "20060102T150405Z"
	resultSchema = 1
)

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

// Build stages the guest program and its unit from the repository at root, lets mkosi build
// root/range, and stores the image under cache/images in a directory named by its sha256.
// Tool output goes to log.
func Build(ctx context.Context, root, cache string, log io.Writer) (image string, err error) {
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", fmt.Errorf("cache directory: %w", err)
	}
	stage, err := os.MkdirTemp(cache, "stage-")
	if err != nil {
		return "", fmt.Errorf("staging directory: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(stage); rmErr != nil {
			err = errors.Join(err, fmt.Errorf("remove staging directory: %w", rmErr))
		}
	}()

	goBuild := exec.CommandContext(ctx, "/usr/bin/go", "build", "-trimpath", //nolint:gosec // absolute binary, fixed argv, our own directories
		"-o", filepath.Join(stage, "usr/lib/kordon-range/guest"), "./cmd/kordon-range-guest")
	goBuild.Dir = root
	goBuild.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=readonly", "GOTOOLCHAIN=local")
	goBuild.Stdout, goBuild.Stderr = log, log
	if err := goBuild.Run(); err != nil {
		return "", fmt.Errorf("build guest program: %w", err)
	}
	unit, err := os.ReadFile(filepath.Join(root, "range", guestUnit)) //nolint:gosec // fixed path in the repository
	if err != nil {
		return "", fmt.Errorf("guest unit: %w", err)
	}
	unitDir := filepath.Join(stage, "usr/lib/systemd/system")
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
	mkosi := exec.CommandContext(ctx, "/usr/bin/mkosi", "--directory="+filepath.Join(root, "range"), //nolint:gosec // absolute binary, fixed argv, our own directories
		"--extra-tree="+stage, "--output-directory="+out, "build")
	mkosi.Stdout, mkosi.Stderr = log, log
	if err := mkosi.Run(); err != nil {
		return "", errors.Join(fmt.Errorf("mkosi: %w", err), os.RemoveAll(out))
	}
	sum, err := fileSHA256(filepath.Join(out, "image.raw"))
	if err != nil {
		return "", errors.Join(err, os.RemoveAll(out))
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
// state/results/<id>. Run directories live under cache/runs.
func Check(ctx context.Context, image, cache, state string) (res Result, err error) {
	sum, err := fileSHA256(image)
	if err != nil {
		return Result{}, err
	}
	manifest, err := readManifest(filepath.Join(filepath.Dir(image), "image.manifest"))
	if err != nil {
		return Result{}, err
	}
	var token [4]byte
	if _, err := rand.Read(token[:]); err != nil {
		return Result{}, fmt.Errorf("run id: %w", err)
	}
	id := time.Now().UTC().Format(stampLayout) + "-" + hex.EncodeToString(token[:])
	runs := filepath.Join(cache, "runs")
	resultsDir := filepath.Join(state, "results")
	out := filepath.Join(resultsDir, id)
	for _, d := range []string{runs, out} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return Result{}, fmt.Errorf("directory: %w", err)
		}
	}
	serial, err := os.OpenFile(filepath.Join(out, "serial.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // our own results directory
	if err != nil {
		return Result{}, fmt.Errorf("serial log: %w", err)
	}
	outcome, runErr := Run(ctx, image, runs, serial)
	if err := errors.Join(runErr, serial.Close()); err != nil {
		return Result{}, err
	}

	res = Result{
		SchemaVersion: resultSchema, ID: id, RangeCommit: rangeCommit(), Image: image,
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
	return res, prune(resultsDir, keepResults)
}

// rangeCommit is the commit this binary was built from, marked dirty when the tree had changes.
func rangeCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "unknown", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty {
		return rev + "-dirty"
	}
	return rev
}

func readManifest(path string) (json.RawMessage, error) {
	f, err := os.Open(path) //nolint:gosec // the maintainer names the image; its manifest sits next to it
	if err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	data, err := io.ReadAll(io.LimitReader(f, maxManifest+1))
	if err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	if len(data) > maxManifest || !json.Valid(data) {
		return nil, fmt.Errorf("image manifest %s is not JSON of at most %d bytes", path, maxManifest)
	}
	return data, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the maintainer names the image
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only file
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	d, err := os.Open(dir) //nolint:gosec // our own results directory
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	if err := errors.Join(d.Sync(), d.Close()); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
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
		errs = append(errs, os.RemoveAll(filepath.Join(dir, names[0])))
		names = names[1:]
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("retention %s: %w", dir, err)
	}
	return nil
}
