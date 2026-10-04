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

// Build builds the image of the commit the launcher was built from, read from the object store of
// the repository at root, and stores it with its commit under cache/images. Building a commit runs
// its range/ and packaging/ on this host, so only build commits whose code you would run (T34). git
// never runs in root and nothing in its object store is trusted: the tools build from an export of
// the commit verified object by object (ADR 0010). Tool output goes to log.
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
	for _, d := range []string{"home", "src", "src-pkg", "build", "log", "pkg"} {
		if err := os.Mkdir(filepath.Join(stage, d), 0o700); err != nil {
			return "", fmt.Errorf("staging directory: %w", err)
		}
	}
	tool := newTool(ctx, stage, log)
	src := filepath.Join(stage, "src")
	commit := launcherCommit()
	if commit == "" {
		return "", errors.New("launcher is not a clean VCS build of a commit (go run, -buildvcs=false or uncommitted changes)")
	}
	// Objects in root's store can be FIFOs or huge, so the copy has a deadline; it takes well under
	// a second today.
	fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	if err := fetchAndExport(newTool(fetchCtx, stage, log), root, stage, commit, defaultLimits()); err != nil {
		return "", err
	}

	tree, pkgs := filepath.Join(stage, "tree"), filepath.Join(stage, "pkg")
	goBuild := tool(src, "/usr/bin/go", "build", "-trimpath", "-buildvcs=false", "-o", filepath.Join(tree, "usr/lib/kordon-range/guest"), "./cmd/kordon-range-guest")
	if err := goBuild.Run(); err != nil {
		return "", fmt.Errorf("build guest program: %w", err)
	}
	for _, f := range imageFiles {
		if err := copyInto(filepath.Join(src, f.src), filepath.Join(tree, f.dst), f.mode); err != nil {
			return "", err
		}
	}
	makepkg := tool(filepath.Join(src, "packaging", "laurel"), "/usr/bin/makepkg", "--noconfirm", "--nodeps")
	makepkg.Env = append(makepkg.Env, "PKGDEST="+pkgs, "SOURCE_DATE_EPOCH="+sourceDateEpoch, "SRCDEST="+filepath.Join(stage, "src-pkg"),
		"BUILDDIR="+filepath.Join(stage, "build"), "LOGDEST="+filepath.Join(stage, "log"))
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
	mkosi := tool(src, "/usr/bin/mkosi", "--directory="+filepath.Join(src, "range"), "--extra-tree="+tree, "--package-directory="+pkgs, "--output-directory="+built, "build")
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

// limits bound an export (R5). Only the built commit's own objects are copied, no history; today
// that is about 110 KiB.
type limits struct {
	pack, listing, blob, export int64
	entries, pathLen, depth     int
}

// fetchTimeout bounds copying and exporting the commit (§7).
const fetchTimeout = 2 * time.Minute

func defaultLimits() limits {
	return limits{pack: 64 << 20, listing: 8 << 20, blob: 32 << 20, export: 256 << 20, entries: 20000, pathLen: 512, depth: 32}
}

// fetchAndExport copies commit from the repository at root into a fresh repository in the stage
// and exports its files to stage/src. root's objects are never read as content: a loose object
// there can carry other bytes than its name says, and git serves them unchecked. They travel as a
// pack, index-pack names every object by its recomputed hash, and the export then reads only from
// the stage repository, where a forged object is simply missing.
func fetchAndExport(tool toolFunc, root, stage, commit string, lim limits) error {
	objectsDir, err := filepath.Abs(filepath.Join(root, ".git", "objects"))
	if err != nil || strings.ContainsAny(objectsDir, "\n\r") {
		return fmt.Errorf("object store of %s: %q: %w", root, objectsDir, err)
	}
	if st, err := os.Stat(objectsDir); err != nil || !st.IsDir() {
		return fmt.Errorf("object store of %s is not a directory: %w", root, err)
	}
	// git never runs in root: its configuration, attributes, refs and work tree are the agent's to
	// write. A repository of ours borrows root's objects (alternates) and reads them with our own
	// configuration; their content is still untrusted until index-pack has named it.
	reader, gitDir := filepath.Join(stage, "reader"), filepath.Join(stage, "git")
	for _, dir := range []string{reader, gitDir} {
		if err := tool(stage, "/usr/bin/git", "init", "--quiet", "--bare", "--template=", dir).Run(); err != nil {
			return fmt.Errorf("git init: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Join(reader, "objects", "info"), 0o700); err != nil {
		return fmt.Errorf("alternates: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(reader, "objects", "info", "alternates"), []byte(objectsDir+"\n")); err != nil {
		return err
	}
	list := stageGit(tool, reader, "rev-list", "--objects", "--no-walk", commit)
	pack := stageGit(tool, reader, "pack-objects", "--stdout")
	// index-pack streams blobs over 1 MiB instead of holding them in memory; --fsck-objects refuses
	// malformed trees (duplicate or full-path entries, bad order) that would export ambiguously.
	index := stageGit(tool, gitDir, "-c", "core.bigFileThreshold=1m", "index-pack", "--stdin", "--fsck-objects")
	if err := copyObjects(list, pack, index, lim.pack); err != nil {
		return fmt.Errorf("copy %s into a verified repository: %w", commit, err)
	}
	// Every object of the commit must have arrived under its own name.
	check := stageGit(tool, gitDir, "rev-list", "--objects", "--no-walk", commit)
	check.Stdout = io.Discard
	if err := check.Run(); err != nil {
		return fmt.Errorf("commit %s is incomplete or forged in its repository: %w", commit, err)
	}
	files, err := listTree(tool, gitDir, commit, lim)
	if err != nil {
		return err
	}
	return export(tool, gitDir, files, filepath.Join(stage, "src"), lim)
}

// copyObjects runs list | pack | index and refuses more than limit bytes into index. The children own
// the pipe between list and pack; the parent closes its ends as soon as they started, so either one
// exiting ends the other instead of leaving it blocked.
func copyObjects(list, pack, index *exec.Cmd, limit int64) error {
	objects, listOut, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	list.Stdout, pack.Stdin, pack.Stdout = listOut, objects, nil
	packOut, err := pack.StdoutPipe()
	if err != nil {
		return errors.Join(err, objects.Close(), listOut.Close())
	}
	capped := &cappedReader{r: packOut, left: limit}
	index.Stdin = capped
	listErr := list.Start()
	packErr := pack.Start()
	if err := errors.Join(objects.Close(), listOut.Close()); err != nil {
		return errors.Join(fmt.Errorf("pipe: %w", err), waitStarted(list, listErr), waitStarted(pack, packErr))
	}
	if listErr != nil || packErr != nil {
		return errors.Join(listErr, packErr, waitStarted(list, listErr), waitStarted(pack, packErr))
	}
	indexErr := index.Run()
	// Closing the pipe stops a pack-objects still writing after a refused or failed copy.
	err = errors.Join(indexErr, packOut.Close(), pack.Wait(), list.Wait())
	if capped.over {
		return fmt.Errorf("over %d bytes packed", limit)
	}
	return err
}

// waitStarted reaps cmd if it started.
func waitStarted(cmd *exec.Cmd, startErr error) error {
	if startErr != nil {
		return nil
	}
	return cmd.Wait()
}

// readCapped reads r to EOF but stops, with an error, as soon as it has more than limit bytes.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("over %d bytes", limit)
	}
	return data, err
}

// entry is one file of a commit: its git mode and object name.
type entry struct{ mode, oid string }

// listTree returns every file of commit, refusing anything but regular files (a symlink would make
// a tool read outside the export, a submodule is content the commit does not hold) and paths that
// are not plain relative paths. Allowlist of modes, so a new kind of entry is refused too. With -z
// git prints each path raw after a tab.
func listTree(tool toolFunc, gitDir, commit string, lim limits) (map[string]entry, error) {
	ls := stageGit(tool, gitDir, "ls-tree", "-r", "-z", commit)
	ls.Stdout = nil
	out, err := ls.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree: %w", err)
	}
	if err := ls.Start(); err != nil {
		return nil, fmt.Errorf("git ls-tree: %w", err)
	}
	data, readErr := readCapped(out, lim.listing)
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("tree of %s: %w", commit, readErr), out.Close(), ls.Wait())
	}
	if err := ls.Wait(); err != nil {
		return nil, fmt.Errorf("git ls-tree %s: %w", commit, err)
	}
	files := map[string]entry{}
	for rec := range strings.SplitSeq(strings.TrimSuffix(string(data), "\x00"), "\x00") {
		meta, path, ok := strings.Cut(rec, "\t")
		fields := strings.Split(meta, " ")
		if !ok || len(fields) != 3 || !commitRE.MatchString(fields[2]) {
			return nil, fmt.Errorf("git ls-tree %s: unexpected entry %q", commit, rec)
		}
		if fields[0] != "100644" && fields[0] != "100755" || fields[1] != "blob" {
			return nil, fmt.Errorf("%q in %s is not a regular file (mode %s)", path, commit, fields[0])
		}
		if err := plainPath(path, lim); err != nil {
			return nil, fmt.Errorf("%q in %s: %w", path, commit, err)
		}
		if len(files) == lim.entries {
			return nil, fmt.Errorf("tree of %s has over %d files", commit, lim.entries)
		}
		files[path] = entry{fields[0], fields[2]}
	}
	return files, nil
}

// plainPath accepts a clean relative path below the export directory that names no .git.
func plainPath(p string, lim limits) error {
	parts := strings.Split(p, "/")
	if len(p) > lim.pathLen || len(parts) > lim.depth {
		return errors.New("not a plain relative path")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") {
			return errors.New("not a plain relative path")
		}
	}
	return nil
}

// export writes every file of the commit into dir, which must be empty. Every file is created
// (O_EXCL also refuses an existing link) and gets exactly mode 0644 or 0755.
func export(tool toolFunc, gitDir string, files map[string]entry, dir string, lim limits) error {
	var total int64
	for path, e := range files {
		dst := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fmt.Errorf("export %s: %w", path, err)
		}
		perm := os.FileMode(0o644)
		if e.mode == "100755" {
			perm = 0o755
		}
		f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm) //nolint:gosec // inside the fresh export directory
		if err != nil {
			return fmt.Errorf("export %s: %w", path, err)
		}
		cat := stageGit(tool, gitDir, "cat-file", "blob", e.oid)
		capped := &cappedWriter{w: f, left: lim.blob}
		cat.Stdout = capped
		err = errors.Join(cat.Run(), f.Chmod(perm), f.Close())
		if capped.over {
			return fmt.Errorf("export %s: over %d bytes", path, lim.blob)
		}
		if err != nil {
			return fmt.Errorf("export %s: %w", path, err)
		}
		if total += lim.blob - capped.left; total > lim.export {
			return fmt.Errorf("export is over %d bytes", lim.export)
		}
	}
	return nil
}

// toolFunc builds the command for one program Build runs.
type toolFunc func(dir, path string, args ...string) *exec.Cmd

// stageGit runs git on the verified repository in the stage.
func stageGit(tool toolFunc, gitDir string, args ...string) *exec.Cmd {
	return tool(gitDir, "/usr/bin/git", append([]string{"--git-dir=" + gitDir}, args...)...)
}

// cappedReader returns an error once more than left bytes were read, so a tool fed from it stops.
type cappedReader struct {
	r    io.Reader
	left int64
	over bool
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.left -= int64(n); c.left < 0 {
		c.over = true
		return 0, errors.New("input over its limit")
	}
	return n, err
}

// cappedWriter refuses writes past left bytes.
type cappedWriter struct {
	w    io.Writer
	left int64
	over bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		c.over = true
		return 0, errors.New("output over its limit")
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

// newTool returns the constructor for every program Build runs. Each gets toolEnv, never the
// caller's environment: GOFLAGS=-toolexec, GOROOT, a go.env file, a git config or a build cache that
// an agent at the same uid can write would otherwise decide what is built (T34).
func newTool(ctx context.Context, stage string, log io.Writer) toolFunc {
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
// plus the proxy settings, which choose the network path and not what is built. Git looks for no
// repository above the stage, which sits inside the maintainer's home repository.
func toolEnv(stage string) []string {
	home := filepath.Join(stage, "home")
	env := []string{
		"PATH=/usr/bin",
		"HOME=" + home,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + stage,
		"GOENV=off",
		"GOCACHE=" + filepath.Join(home, "gocache"),
		"GOMODCACHE=" + filepath.Join(home, "gomod"),
		"GOPROXY=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOFLAGS=-mod=readonly -buildvcs=false",
		"CGO_ENABLED=0",
	}
	for _, k := range proxyEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
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

// copyInto copies one file of the export into the image tree with the mode it has there.
func copyInto(src, dst string, mode os.FileMode) error {
	data, err := readSmall(src, maxImageFile)
	if err != nil {
		return fmt.Errorf("image file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // system directories in the image
		return fmt.Errorf("image file: %w", err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
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
