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
	"runtime/debug"
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
	stampLayout  = "20060102T150405Z"
	resultSchema = 1
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// sourceDateEpoch is the SourceDateEpoch of range/mkosi.conf, so the Laurel package, like the rest
// of the image, does not change with the build time.
const sourceDateEpoch = "1790899200"

// buildInputs are the paths Build reads; they must match the commit it records.
var buildInputs = []string{"range", "cmd", "internal", "go.mod", "packaging", "deploy"}

// imageFiles are copied from the checked tree into the image: the guest unit and the floor-0 sensor
// configuration exactly as kordon-install will place it on a host (ADR 0004).
var imageFiles = []struct {
	src, dst string
	mode     os.FileMode
}{
	{"range/kordon-range-guest.service", "usr/lib/systemd/system/kordon-range-guest.service", 0o644},
	{"deploy/audit/kordon.rules", "etc/audit/rules.d/kordon.rules", 0o640},
	{"deploy/auditd/auditd.conf", "etc/audit/auditd.conf", 0o640},
	{"deploy/auditd/laurel-plugin.conf", "etc/audit/plugins.d/laurel.conf", 0o640},
	{"deploy/laurel/config.toml", "etc/laurel/config.toml", 0o644},
	{"deploy/sysctl/kordon.conf", "etc/sysctl.d/90-kordon.conf", 0o644},
}

// proxyEnv are the only variables makepkg inherits besides its own paths: network settings, not
// build settings.
var proxyEnv = []string{"http_proxy", "https_proxy", "no_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"}

// Result is what one run stores: the verdict and everything that identifies what ran.
type Result struct {
	SchemaVersion  int             `json:"schema_version"`
	ID             string          `json:"id"`
	RangeCommit    string          `json:"range_commit"`
	LauncherCommit string          `json:"launcher_commit"`
	Image          string          `json:"image"`
	ImageSHA256    string          `json:"image_sha256"`
	TargetKernel   string          `json:"target_kernel"`
	GuestKernel    string          `json:"guest_kernel"`
	Verdict        string          `json:"verdict"`
	Reason         string          `json:"reason"`
	Manifest       json.RawMessage `json:"manifest"`
}

// Build builds the guest program and range/ from the repository at root and stores the image
// with its commit under cache/images. It refuses a tree whose build inputs differ from HEAD,
// including untracked and ignored files (mkosi reads an untracked range/mkosi.local.conf), so the
// recorded commit is what the image holds (index flags such as skip-worktree can still hide a
// change; T33). The launcher must be a clean build of that commit too. Tool output goes to log.
func Build(ctx context.Context, root, cache string, log io.Writer) (image string, err error) {
	held, err := lock(cache)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, closeLock(held)) }()
	stage, err := os.MkdirTemp(cache, "stage-")
	if err != nil {
		return "", fmt.Errorf("staging directory: %w", err)
	}
	defer func() { err = errors.Join(err, removeDir(stage)) }()
	if err := os.Mkdir(filepath.Join(stage, "home"), 0o700); err != nil {
		return "", fmt.Errorf("staging directory: %w", err)
	}
	tool := newTool(ctx, stage, log)

	head := tool(root, "/usr/bin/git", "rev-parse", "--verify", "HEAD^{commit}")
	head.Stdout = nil
	out, err := head.Output()
	commit := strings.TrimSpace(string(out))
	if err != nil || !commitRE.MatchString(commit) {
		return "", fmt.Errorf("resolve HEAD: %q: %w", commit, err)
	}
	status := tool(root, "/usr/bin/git", append([]string{"status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--"}, buildInputs...)...)
	status.Stdout = nil
	out, err = status.Output()
	if err != nil {
		return "", fmt.Errorf("git status: %w", err)
	}
	if len(out) > 0 {
		return "", fmt.Errorf("build inputs differ from %s; commit or remove first:\n%s", commit, out)
	}
	if err := regularFilesOnly(tool, root, commit); err != nil {
		return "", err
	}
	if lc := launcherCommit(); lc != commit {
		return "", fmt.Errorf("launcher %q is not a clean build of HEAD %s", lc, commit)
	}

	tree, pkgs := filepath.Join(stage, "tree"), filepath.Join(stage, "pkg")
	goBuild := tool(root, "/usr/bin/go", "build", "-trimpath", "-o", filepath.Join(tree, "usr/lib/kordon-range/guest"), "./cmd/kordon-range-guest")
	if err := goBuild.Run(); err != nil {
		return "", fmt.Errorf("build guest program: %w", err)
	}
	for _, f := range imageFiles {
		if err := copyInto(filepath.Join(root, f.src), filepath.Join(tree, f.dst), f.mode); err != nil {
			return "", err
		}
	}
	// makepkg gets a clean environment and writes only into the stage, so no user makepkg.conf,
	// RUSTFLAGS or leftover in packaging/ changes the package, and the tree stays clean.
	makepkg := tool(filepath.Join(root, "packaging", "laurel"), "/usr/bin/makepkg", "--noconfirm", "--nodeps")
	makepkg.Env = []string{"PATH=/usr/bin", "HOME=" + filepath.Join(stage, "home"), "PKGDEST=" + pkgs, "SOURCE_DATE_EPOCH=" + sourceDateEpoch,
		"SRCDEST=" + filepath.Join(stage, "src"), "BUILDDIR=" + filepath.Join(stage, "build"), "LOGDEST=" + filepath.Join(stage, "log")}
	for _, k := range proxyEnv {
		if v, ok := os.LookupEnv(k); ok {
			makepkg.Env = append(makepkg.Env, k+"="+v)
		}
	}
	for _, d := range []string{"src", "build", "log", "pkg"} {
		if err := os.Mkdir(filepath.Join(stage, d), 0o700); err != nil {
			return "", fmt.Errorf("staging directory: %w", err)
		}
	}
	if err := makepkg.Run(); err != nil {
		return "", fmt.Errorf("makepkg laurel: %w", err)
	}

	built, err := os.MkdirTemp(cache, "build-")
	if err != nil {
		return "", fmt.Errorf("build directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removeDir(built))
		}
	}()
	mkosi := tool(root, "/usr/bin/mkosi", "--directory="+filepath.Join(root, "range"), "--extra-tree="+tree, "--package-directory="+pkgs, "--output-directory="+built, "build")
	// mkosi inherits the lock, so it stays held while mkosi runs even if this process is killed
	// and the next invocation never sweeps a build directory mkosi still writes.
	mkosi.ExtraFiles = []*os.File{held}
	if err := mkosi.Run(); err != nil {
		return "", fmt.Errorf("mkosi: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(built, "commit"), []byte(commit+"\n")); err != nil {
		return "", err
	}
	sum, err := fileSHA256(ctx, filepath.Join(built, "image.raw"))
	if err != nil {
		return "", err
	}
	images := filepath.Join(cache, "images")
	if err := os.MkdirAll(images, 0o700); err != nil {
		return "", fmt.Errorf("image directory: %w", err)
	}
	dest := filepath.Join(images, time.Now().UTC().Format(stampLayout)+"-"+sum[:16])
	if err := os.Rename(built, dest); err != nil {
		return "", fmt.Errorf("store image: %w", err)
	}
	return filepath.Join(dest, "image.raw"), prune(images, keepImages)
}

// newTool returns the constructor for every program Build runs. Each gets toolEnv, never the
// caller's environment: GOFLAGS=-toolexec, GOROOT, a go.env file, a git config or a build cache that
// an agent at the same uid can write would otherwise decide what is built (T34).
func newTool(ctx context.Context, stage string, log io.Writer) func(dir, path string, args ...string) *exec.Cmd {
	env := toolEnv(stage)
	return func(dir, path string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // absolute binaries, fixed argv
		cmd.Dir = dir
		cmd.Env = slices.Clone(env)
		cmd.Stdout, cmd.Stderr = log, log
		return cmd
	}
}

// toolEnv is the whole environment of the tools Build runs: fixed values with caches inside stage,
// plus the proxy settings, which choose the network path and not what is built.
func toolEnv(stage string) []string {
	home := filepath.Join(stage, "home")
	env := []string{
		"PATH=/usr/bin",
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GOENV=off",
		"GOCACHE=" + filepath.Join(home, "gocache"),
		"GOMODCACHE=" + filepath.Join(home, "gomod"),
		"GOPROXY=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
	}
	for _, k := range proxyEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// regularFilesOnly refuses a commit whose build inputs hold anything but regular files. A symlink
// would make Build read a host file outside the tree (a key the agent may not read) into the image,
// where guest code from the same commit can print it; a submodule is a tree the commit does not
// pin byte for byte (T34). Allowlist of modes, so a new kind of entry is refused too.
func regularFilesOnly(tool func(dir, path string, args ...string) *exec.Cmd, root, commit string) error {
	ls := tool(root, "/usr/bin/git", append([]string{"ls-tree", "-r", "-z", "--full-tree", "--format=%(objectmode) %(path)", commit, "--"}, buildInputs...)...)
	ls.Stdout = nil
	out, err := ls.Output()
	if err != nil {
		return fmt.Errorf("git ls-tree: %w", err)
	}
	for entry := range strings.SplitSeq(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		mode, path, ok := strings.Cut(entry, " ")
		if !ok {
			return fmt.Errorf("git ls-tree: unexpected entry %q", entry)
		}
		if mode != "100644" && mode != "100755" {
			return fmt.Errorf("build input %q is not a regular file (mode %s); commit the file itself", path, mode)
		}
	}
	return nil
}

// launcherCommit is the clean commit this binary was built from, or "" when the build carries no
// VCS stamp (go run) or had uncommitted changes.
func launcherCommit() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return cleanRevision(info.Settings)
}

func cleanRevision(settings []debug.BuildSetting) string {
	rev, modified := "", true
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value != "false"
		}
	}
	if modified || !commitRE.MatchString(rev) {
		return ""
	}
	return rev
}

// Check runs the self-test of image once and stores its Result and serial log under
// state/results/<id>; a run that ends in an error leaves no result directory behind. A launcher
// that is not a clean build of the image's commit judged the run with code nobody can name, so
// its verdict is UNKNOWN (R1).
func Check(ctx context.Context, image, cache, state string) (res Result, err error) {
	held, err := lock(cache)
	if err != nil {
		return Result{}, err
	}
	defer func() { err = errors.Join(err, closeLock(held)) }()
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
		SchemaVersion: resultSchema, ID: id, RangeCommit: commit, LauncherCommit: launcherCommit(),
		Image: image, ImageSHA256: sum, TargetKernel: TargetKernel, Manifest: manifest,
	}
	for _, f := range outcome.Facts {
		if f.Name == FactKernel {
			res.GuestKernel = f.Value
		}
	}
	res.Verdict, res.Reason = judge(outcome, res.LauncherCommit, commit)
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("encode result: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(out, "result.json"), data); err != nil {
		return Result{}, err
	}
	return res, nil
}

func judge(o Outcome, launcher, image string) (verdict, reason string) {
	if o.Invalid != "" {
		return Invalid, o.Invalid
	}
	verdict, reason = Selftest(o.Facts)
	if verdict == Pass && launcher != image {
		return Unknown, fmt.Sprintf("launcher is not a clean build of the image commit %s (got %q)", image, launcher)
	}
	return verdict, reason
}

// lock lets one kordon-range at a time own the cache, then removes the staging, build and run
// directories a killed earlier invocation left behind (R5). The lock lives as long as the open
// file, held by this process and the tools it starts, so a crash never leaves it held.
func lock(cache string) (*os.File, error) {
	runs := filepath.Join(cache, "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return nil, fmt.Errorf("cache directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(cache, "lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // our own cache directory
	if err != nil {
		return nil, fmt.Errorf("cache lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(fmt.Errorf("another kordon-range is running (%s): %w", f.Name(), err), f.Close())
	}
	errs := []error{sweep(cache, "stage-", "build-"), sweep(runs, "run-")}
	if err := errors.Join(errs...); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// sweep removes the entries of dir whose names start with one of prefixes. Names are compared
// literally; dir is never a pattern.
func sweep(dir string, prefixes ...string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("sweep %s: %w", dir, err)
	}
	var errs []error
	for _, e := range entries {
		if slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(e.Name(), p) }) {
			errs = append(errs, removeDir(filepath.Join(dir, e.Name())))
		}
	}
	return errors.Join(errs...)
}

// maxImageFile caps one configuration file copied into the image (R5).
const maxImageFile = 1 << 20

// copyInto copies one file of the checked tree into the image tree with the mode it has there.
func copyInto(src, dst string, mode os.FileMode) error {
	data, err := readSmall(src, maxImageFile)
	if err != nil {
		return fmt.Errorf("image file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // system directories in the image
		return fmt.Errorf("image file: %w", err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil { //nolint:gosec // dst is in our staging tree, from the fixed imageFiles table
		return fmt.Errorf("image file: %w", err)
	}
	// WriteFile applies the umask; the image must not depend on the builder's.
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("image file: %w", err)
	}
	return nil
}

func closeLock(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("release cache lock: %w", err)
	}
	return nil
}

// openRegular opens path for reading without blocking on a FIFO or device and refuses anything
// that is not a regular file. It does not follow a symlink in the last component: the tree Build
// copies from and the cache next to an image are writable by an agent at the same uid, and a link
// there would read a host file the agent may not read into the image or the result (T34).
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0) //nolint:gosec // the maintainer names the image; its files sit next to it
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

// readManifest returns mkosi's package manifest if it is the version we read and lists packages,
// so a stored result names what the image contained (ADR 0009, point 8). The kernel is judged from
// what the guest runs, in Selftest.
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
	if m.ManifestVersion != 1 || len(m.Packages) == 0 {
		return nil, fmt.Errorf("image manifest: version %d with %d packages, want version 1 with packages", m.ManifestVersion, len(m.Packages))
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
