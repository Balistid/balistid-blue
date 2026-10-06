package rangevm

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	return got
}

func TestPruneKeepsTheNewest(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"20261003T100000Z-c", "20261001T100000Z-a", "20261002T100000Z-b"} {
		if err := os.Mkdir(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := prune(dir, 2); err != nil {
		t.Fatal(err)
	}
	if got, want := names(t, dir), []string{"20261002T100000Z-b", "20261003T100000Z-c"}; !slices.Equal(got, want) {
		t.Fatalf("kept %q, want %q", got, want)
	}
}

func TestLockRemovesStaleDirectoriesAndExcludesASecondHolder(t *testing.T) {
	parent := t.TempDir()
	// Glob characters in the cache path must not widen what the sweep removes.
	cache := filepath.Join(parent, "cache-*[1]")
	neighbour := filepath.Join(parent, "cache-x1", "stage-live")
	for _, d := range []string{filepath.Join(cache, "stage-1"), filepath.Join(cache, "build-2"),
		filepath.Join(cache, "runs/run-3"), filepath.Join(cache, "images/20261003T100000Z-x"), neighbour} {
		if err := os.MkdirAll(filepath.Join(d, "big"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	held, err := Lock(cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(neighbour); err != nil {
		t.Fatalf("the sweep left its cache: %v", err)
	}
	if got, want := names(t, cache), []string{"images", "lock", "runs"}; !slices.Equal(got, want) {
		t.Fatalf("cache holds %q, want %q", got, want)
	}
	if got := names(t, filepath.Join(cache, "runs")); len(got) != 0 {
		t.Fatalf("stale run directories left: %q", got)
	}
	if _, err := Lock(cache); err == nil {
		t.Fatal("a second holder got the lock")
	}
	if err := closeLock(held); err != nil {
		t.Fatal(err)
	}
	again, err := Lock(cache)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := closeLock(again); err != nil {
		t.Fatal(err)
	}
}

func TestReadResults(t *testing.T) {
	dir := t.TempDir()
	good := append(stream(t, fact(FactKernel, TargetKernel), end(1)), make([]byte, ResultsBytes)...)[:ResultsBytes]
	cases := map[string]struct {
		data    []byte
		mode    os.FileMode
		invalid bool
	}{
		"complete":        {good, 0o600, false},
		"grown past size": {append(slices.Clone(good), 1), 0o600, true},
		"shrunk":          {good[:1024], 0o600, true},
		"unreadable":      {good, 0o000, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, c.data, c.mode); err != nil {
				t.Fatal(err)
			}
			if got := readResults(path); (got.Invalid != "") != c.invalid {
				t.Fatalf("readResults = %+v, want invalid=%v", got.Invalid, c.invalid)
			}
		})
	}
	if got := readResults(filepath.Join(dir, "missing")); got.Invalid == "" {
		t.Fatal("a missing results disk was not INVALID")
	}
}

func TestJudge(t *testing.T) {
	commit := strings.Repeat("a", 40)
	pass := Outcome{Facts: passing(nil)}
	nic := Outcome{Facts: passing(map[string]string{FactNet: "eth0,lo"})}
	cases := []struct {
		name     string
		o        Outcome
		launcher string
		want     string
	}{
		{"clean launcher of the image commit", pass, commit, Pass},
		{"go run or dirty launcher", pass, "", Unknown},
		{"launcher of another commit", pass, strings.Repeat("b", 40), Unknown},
		{"a NIC fails whatever the launcher", nic, "", Fail},
		{"invalid run", Outcome{Invalid: "vm: exit status 1"}, commit, Invalid},
	}
	for _, c := range cases {
		if got, reason := JudgeSelftest(c.o, c.launcher, commit); got != c.want {
			t.Errorf("%s: judge = %s (%s), want %s", c.name, got, reason, c.want)
		}
	}
	// Equal is not enough: neither side may be a placeholder such as an unset build version.
	for _, both := range []string{"", "dev", strings.ToUpper(commit)} {
		if got, _ := JudgeSelftest(pass, both, both); got != Unknown {
			t.Errorf("launcher and image both %q: %s, want %s", both, got, Unknown)
		}
	}
}

func TestReadManifest(t *testing.T) {
	linux := `{"name":"linux","version":"` + strings.Replace(TargetKernel, "-", ".", 1) + `"}`
	cases := map[string]struct {
		body string
		ok   bool
	}{
		"target kernel":  {`{"manifest_version":1,"packages":[{"name":"systemd","version":"262-1"},` + linux + `]}`, true},
		"other kernel":   {`{"manifest_version":1,"packages":[{"name":"linux","version":"7.2.7.arch1-1"}]}`, true},
		"no kernel":      {`{"manifest_version":1,"packages":[]}`, false},
		"future version": {`{"manifest_version":2,"packages":[` + linux + `]}`, false},
		"null":           {`null`, false},
		"array":          {`[]`, false},
		"not json":       {`linux 7.2.8`, false},
		"oversized":      {`{"manifest_version":1,"packages":[` + linux + `],"x":"` + strings.Repeat("x", maxManifest) + `"}`, false},
	}
	dir := t.TempDir()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readManifest(path); (err == nil) != c.ok {
				t.Fatalf("readManifest error = %v, want ok=%v", err, c.ok)
			}
		})
	}
	if _, err := readManifest(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing manifest was accepted")
	}
}

func TestReadCommit(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]bool{
		strings.Repeat("a", 40) + "\n": true,
		strings.Repeat("a", 39):        false,
		"HEAD":                         false,
		strings.Repeat("A", 40):        false,
	}
	for body, ok := range cases {
		path := filepath.Join(dir, "commit")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCommit(path); (err == nil) != ok {
			t.Errorf("readCommit(%q) error = %v, want ok=%v", body, err, ok)
		}
	}
}

func TestImageInputsMustBeRegularFiles(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "image.raw")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fileSHA256(context.Background(), fifo); err == nil {
		t.Fatal("hashed a FIFO")
	}
	if _, err := fileSHA256(context.Background(), t.TempDir()); err == nil {
		t.Fatal("hashed a directory")
	}
}

func TestHashStopsWhenCancelled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(path, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fileSHA256(ctx, path); err == nil {
		t.Fatal("hashing ignored a cancelled context")
	}
}

func TestWriteFileAtomicIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := WriteFileAtomic(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
}

func TestCleanRevision(t *testing.T) {
	rev := strings.Repeat("c", 40)
	cases := []struct {
		name     string
		settings []debug.BuildSetting
		want     string
	}{
		{"clean", []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: "false"}}, rev},
		{"dirty", []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: "true"}}, ""},
		{"no modified flag", []debug.BuildSetting{{Key: "vcs.revision", Value: rev}}, ""},
		{"go run, no stamp", nil, ""},
	}
	for _, c := range cases {
		if got := cleanRevision(c.settings); got != c.want {
			t.Errorf("%s: cleanRevision = %q, want %q", c.name, got, c.want)
		}
	}
}

// withoutGit drops GIT_* variables so the environment cannot point git at another repository.
func withoutGit(env []string) []string {
	return slices.DeleteFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "GIT_") })
}

// testRepo creates a repository holding range/mkosi.conf and returns its root and a git runner.
func testRepo(t *testing.T) (string, func(args ...string) string) {
	t.Helper()
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "/usr/bin/git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...) //nolint:gosec // test temp repository
		cmd.Env = withoutGit(os.Environ())
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(filepath.Join(root, "range"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.conf"), []byte("[Distribution]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "x")
	return root, git
}

func TestCopyIntoIgnoresTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "tree/etc/x.conf")
	if err := copyInto(src, dst, 0o644); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dst); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, %v; want 0644 under umask 077", st.Mode().Perm(), err)
	}
}

func TestSourceDateEpochMatchesTheImageConfig(t *testing.T) {
	conf, err := os.ReadFile("../../range/mkosi.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "\nSourceDateEpoch="+sourceDateEpoch+"\n") {
		t.Fatalf("range/mkosi.conf does not set SourceDateEpoch=%s", sourceDateEpoch)
	}
}

func TestToolEnvIsExactlyTheAllowlist(t *testing.T) {
	for _, k := range proxyEnv {
		t.Setenv(k, "") // restored after the test
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range map[string]string{"GOFLAGS": "-toolexec=/tmp/x", "GOROOT": "/tmp/goroot", "GOCACHE": "/tmp/cache",
		"LD_PRELOAD": "/tmp/x.so", "GIT_DIR": "/tmp/repo", "https_proxy": "http://proxy:3128"} {
		t.Setenv(k, v)
	}
	stage := t.TempDir()
	home := filepath.Join(stage, "home")
	want := []string{"PATH=/usr/bin", "HOME=" + home, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + stage, "GOENV=off", "GOCACHE=" + filepath.Join(home, "gocache"),
		"GOMODCACHE=" + filepath.Join(home, "gomod"), "GOPROXY=off", "GOTOOLCHAIN=local", "GOWORK=off",
		"GOFLAGS=-mod=readonly -buildvcs=false", "CGO_ENABLED=0",
		"https_proxy=http://proxy:3128"}
	cmd := newTool(t.Context(), stage, io.Discard)("/", "/usr/bin/true")
	if !slices.Equal(cmd.Env, want) {
		t.Fatalf("tool environment\n got %q\nwant %q", cmd.Env, want)
	}
}

func TestCopyIntoRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "balistid.conf")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "tree/etc/x.conf")
	if err := copyInto(link, dst, 0o644); err == nil {
		t.Fatal("copied the file a symlink points to")
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatalf("destination exists after a refused copy: %v", err)
	}
}

// stageFor makes the stage directories fetchAndExport expects.
func stageFor(t *testing.T) string {
	t.Helper()
	stage := t.TempDir()
	for _, d := range []string{"home", "src"} {
		if err := os.Mkdir(filepath.Join(stage, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return stage
}

func exportOf(t *testing.T, root, commit string) (string, error) {
	t.Helper()
	return exportWith(t, root, commit, defaultLimits())
}

func exportWith(t *testing.T, root, commit string, lim limits) (string, error) {
	t.Helper()
	stage := stageFor(t)
	err := fetchAndExport(t.Context(), newTool(t.Context(), stage, io.Discard), root, stage, commit, lim)
	return filepath.Join(stage, "src"), err
}

// The export is the commit: not the work tree, an index flag, a replace ref or an untracked file,
// all of which an agent at the maintainer's uid controls (T34).
func TestExportIsTheCommit(t *testing.T) {
	root, git := testRepo(t)
	head := git("rev-parse", "HEAD")
	evil := git("hash-object", "-w", "/dev/null") // an empty blob
	git("update-index", "--assume-unchanged", "range/mkosi.conf")
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.conf"), []byte("[Content]\nExtraTrees=/home\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.local.conf"), []byte("[Content]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("replace", git("rev-parse", "HEAD:range/mkosi.conf"), evil)
	src, err := exportOf(t, root, head)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(src, "range", "mkosi.conf")) //nolint:gosec // test export directory
	if err != nil || string(got) != "[Distribution]\n" {
		t.Fatalf("exported mkosi.conf = %q, %v; want the committed bytes", got, err)
	}
	if _, err := os.Lstat(filepath.Join(src, "range", "mkosi.local.conf")); !os.IsNotExist(err) {
		t.Fatalf("untracked file exported: %v", err)
	}
}

// A loose object whose bytes do not match its name is served by git unchecked; the copy into the
// stage verifies every object, so a forged range/ never reaches mkosi.
func TestForgedObjectIsRefused(t *testing.T) {
	root, git := testRepo(t)
	oid := git("rev-parse", "HEAD:range/mkosi.conf")
	path := filepath.Join(root, ".git", "objects", oid[:2], oid[2:])
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	var forged bytes.Buffer
	z := zlib.NewWriter(&forged)
	if _, err := z.Write([]byte("blob 15\x00[Content]\nX=1\n")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, forged.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exportOf(t, root, git("rev-parse", "HEAD")); err == nil || !strings.Contains(err.Error(), "forged") {
		t.Fatalf("export of a forged object = %v, want a refusal", err)
	}
}

func TestExportRefusesLinksAndSubmodules(t *testing.T) {
	for name, add := range map[string]func(root string, git func(...string) string){
		"symlink": func(root string, git func(...string) string) {
			if err := os.Symlink("/etc/passwd", filepath.Join(root, "range", "balistid-range-guest.service")); err != nil {
				t.Fatal(err)
			}
			git("add", ".")
		},
		"submodule": func(_ string, git func(...string) string) {
			git("update-index", "--add", "--cacheinfo", "160000,"+git("rev-parse", "HEAD")+",cmd/sub")
		},
	} {
		root, git := testRepo(t)
		add(root, git)
		git("commit", "-q", "-m", name)
		_, err := exportOf(t, root, git("rev-parse", "HEAD"))
		if err == nil || !strings.Contains(err.Error(), "is not a regular file") {
			t.Errorf("%s: export = %v, want a refusal", name, err)
		}
	}
}

func TestPlainPath(t *testing.T) {
	for p, ok := range map[string]bool{
		"range/mkosi.conf": true, "internal/rangeguest/x_test.go": true,
		"../x": false, "a/../b": false, "./a": false, "a//b": false, "/etc/passwd": false, "a/": false,
		".git/config": false, "a/.GIT/b": false, "": false, strings.Repeat("a/", 40) + "b": false,
		strings.Repeat("x", defaultLimits().pathLen+1): false,
	} {
		if err := plainPath(p, defaultLimits()); (err == nil) != ok {
			t.Errorf("plainPath(%q) = %v, want ok=%v", p, err, ok)
		}
	}
}

func TestCappedReaderAndWriter(t *testing.T) {
	r := &cappedReader{r: strings.NewReader("12345"), left: 4}
	if _, err := io.ReadAll(r); err == nil || !r.over {
		t.Fatalf("read 5 bytes with a cap of 4: %v over=%v", err, r.over)
	}
	var b bytes.Buffer
	w := &cappedWriter{w: &b, left: 4}
	if _, err := w.Write([]byte("12345")); err == nil || !w.over || b.Len() != 0 {
		t.Fatalf("wrote 5 bytes with a cap of 4: %v over=%v wrote=%d", err, w.over, b.Len())
	}
}

// The stage lies inside the maintainer's home repository; with the tool environment go build must
// not stamp (and so not run git status in) the enclosing repository.
func TestGuestBuildRunsNoGitAboveTheStage(t *testing.T) {
	// Build runs /usr/bin/go; on a host whose /usr/bin/go is another Go (the CI runner's), skip.
	if out, err := exec.CommandContext(t.Context(), "/usr/bin/go", "env", "GOVERSION").Output(); err != nil || strings.TrimSpace(string(out)) != runtime.Version() {
		t.Skipf("/usr/bin/go is not this Go (%q, %v)", out, err)
	}
	outer := t.TempDir()
	if out, err := exec.CommandContext(t.Context(), "/usr/bin/git", "init", "-q", outer).CombinedOutput(); err != nil { //nolint:gosec // test temp repository
		t.Fatalf("git init: %v %s", err, out)
	}
	stage := filepath.Join(outer, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(stage, "src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"go.mod": "module m\n\ngo 1.27\n", "main.go": "package main\n\nfunc main() {}\n"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tool := newTool(t.Context(), stage, io.Discard)
	build := tool(src, "/usr/bin/go", "build", "-o", filepath.Join(stage, "bin"), ".")
	build.Env = append(build.Env, "GOCACHE="+goCache(t)) // a warm cache keeps the test fast
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), "/usr/bin/go", "version", "-m", filepath.Join(stage, "bin")).Output() //nolint:gosec // test binary
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "vcs.") {
		t.Fatalf("guest build stamped the enclosing repository:\n%s", out)
	}
}

func goCache(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "/usr/bin/go", "env", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// Lazy fetch from a promisor remote would run the remote's upload-pack, which the repository's own
// configuration names.
func TestExportRunsNoLazyFetch(t *testing.T) {
	root, git := testRepo(t)
	marker := filepath.Join(t.TempDir(), "ran")
	hook := filepath.Join(t.TempDir(), "upload-pack")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o700); err != nil { //nolint:gosec // test hook
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "range", "big"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "big")
	head, oid := git("rev-parse", "HEAD"), git("rev-parse", "HEAD:range/big")
	if err := os.Remove(filepath.Join(root, ".git", "objects", oid[:2], oid[2:])); err != nil {
		t.Fatal(err)
	}
	git("config", "extensions.partialClone", "origin")
	git("config", "remote.origin.url", root)
	git("config", "remote.origin.promisor", "true")
	git("config", "remote.origin.uploadpack", hook)
	if _, err := exportOf(t, root, head); err == nil {
		t.Fatal("exported a commit with a missing object")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("lazy fetch ran the remote's upload-pack: %v", err)
	}
}

// With -z git prints paths raw; the export must reproduce every name byte for byte.
func TestExportKeepsUnusualNames(t *testing.T) {
	root, git := testRepo(t)
	names := []string{"deploy/a b", "deploy/tab\there", "deploy/new\nline", "deploy/back\\slash", "deploy/é", "deploy/\"q\""}
	for _, n := range names {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(n)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("add", ".")
	git("commit", "-q", "-m", "names")
	src, err := exportOf(t, root, git("rev-parse", "HEAD"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if got, err := os.ReadFile(filepath.Join(src, n)); err != nil || string(got) != n { //nolint:gosec // test export directory
			t.Errorf("%q: got %q, %v", n, got, err)
		}
	}
}

func TestExportModesIgnoreTheUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	root, git := testRepo(t)
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.postinst"), []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // test script
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "script")
	src, err := exportOf(t, root, git("rev-parse", "HEAD"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"mkosi.conf": 0o644, "mkosi.postinst": 0o755} {
		if st, err := os.Stat(filepath.Join(src, "range", name)); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: mode %v, %v; want %v", name, st.Mode().Perm(), err, want)
		}
	}
}

// The export creates every file; a name that already exists, as a file or a link, is refused.
func TestExportCreatesEveryFile(t *testing.T) {
	root, git := testRepo(t)
	target := filepath.Join(t.TempDir(), "target")
	stage := stageFor(t)
	if err := os.MkdirAll(filepath.Join(stage, "src", "range"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stage, "src", "range", "mkosi.conf")); err != nil {
		t.Fatal(err)
	}
	err := fetchAndExport(t.Context(), newTool(t.Context(), stage, io.Discard), root, stage, git("rev-parse", "HEAD"), defaultLimits())
	if err == nil || !strings.Contains(err.Error(), "export range/mkosi.conf") {
		t.Fatalf("export = %v, want a refusal of the existing link", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("export wrote through the link: %v", err)
	}
	stage = stageFor(t)
	if err := os.MkdirAll(filepath.Join(stage, "src", "range"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "src", "range", "mkosi.conf"), []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fetchAndExport(t.Context(), newTool(t.Context(), stage, io.Discard), root, stage, git("rev-parse", "HEAD"), defaultLimits()); err == nil {
		t.Fatal("export overwrote an existing file")
	}
}

// Only the commit's own objects are copied: a large file deleted earlier in history is not.
func TestExportCopiesNoHistory(t *testing.T) {
	root, git := testRepo(t)
	big := make([]byte, 1<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "range", "old"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "old")
	git("rm", "-q", "range/old")
	git("commit", "-q", "-m", "gone")
	lim := defaultLimits()
	lim.pack = 64 << 10
	if _, err := exportWith(t, root, git("rev-parse", "HEAD"), lim); err != nil {
		t.Fatalf("export copied history: %v", err)
	}
}

func TestExportLimits(t *testing.T) {
	root, git := testRepo(t)
	if err := os.WriteFile(filepath.Join(root, "range", "two"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "two")
	head := git("rev-parse", "HEAD")
	for name, set := range map[string]func(*limits){
		"pack":    func(l *limits) { l.pack = 64 },
		"listing": func(l *limits) { l.listing = 64 },
		"entries": func(l *limits) { l.entries = 1 },
		"blob":    func(l *limits) { l.blob = 5 },
		"export":  func(l *limits) { l.export = 12 },
	} {
		lim := defaultLimits()
		set(&lim)
		if _, err := exportWith(t, root, head, lim); err == nil || !strings.Contains(err.Error(), "over") {
			t.Errorf("%s limit: export = %v, want a refusal", name, err)
		}
	}
	if _, err := exportOf(t, root, head); err != nil {
		t.Fatalf("export within the limits: %v", err)
	}
}

// The test binary carries no VCS stamp, so it names no commit to build: Build refuses before it
// reads the repository.
func TestBuildRefusesALauncherWithoutAStamp(t *testing.T) {
	root, _ := testRepo(t)
	_, err := Build(t.Context(), root, t.TempDir(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not a clean VCS build") {
		t.Fatalf("Build = %v, want a refusal of the launcher", err)
	}
}

// Malformed trees that git itself never writes but an agent can plant: a duplicate name and a name
// with a slash would export ambiguously, so the copy refuses them.
func TestExportRefusesMalformedTrees(t *testing.T) {
	for name, entries := range map[string]string{
		"duplicate": "100644 x\x00%[1]s100644 x\x00%[2]s",
		"full path": "100644 a/b\x00%[1]s",
	} {
		root, git := testRepo(t)
		raw := func(hexOID string) string {
			b, err := hex.DecodeString(hexOID)
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		oid := git("rev-parse", "HEAD:range/mkosi.conf")
		tree := filepath.Join(t.TempDir(), "tree")
		if err := os.WriteFile(tree, fmt.Appendf(nil, entries, raw(oid), raw(oid)), 0o600); err != nil {
			t.Fatal(err)
		}
		commit := git("commit-tree", git("hash-object", "-w", "--literally", "-t", "tree", tree), "-m", name)
		if _, err := exportOf(t, root, commit); err == nil {
			t.Errorf("%s: exported a malformed tree", name)
		}
	}
}

// countingReader serves n bytes and counts what was read, so a test can see a read stop early
// without an unbounded reader (a broken limit would then eat the host's memory).
type countingReader struct{ left, read int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	if c.left == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), c.left)
	c.left -= n
	c.read += n
	return int(n), nil
}

func TestReadCappedStopsAtTheLimit(t *testing.T) {
	r := &countingReader{left: 16 << 20}
	if _, err := readCapped(r, 1<<10); err == nil {
		t.Fatal("read 16 MiB under a 1 KiB limit without an error")
	}
	if r.read > 1<<16 {
		t.Fatalf("read %d bytes under a 1 KiB limit; want it to stop at the limit", r.read)
	}
}

// When pack-objects fails early, rev-list must not stay blocked on a pipe the parent still holds.
func TestCopyEndsWhenPackObjectsFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	list := exec.CommandContext(ctx, "/usr/bin/yes")   // writes until its pipe closes
	pack := exec.CommandContext(ctx, "/usr/bin/false") // fails at once
	index := exec.CommandContext(ctx, "/usr/bin/cat")  // reads the empty pack stream
	index.Stdout = io.Discard
	start := time.Now()
	err := copyObjects(list, pack, index, 1<<20)
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("copy after a failed pack-objects: %v after %v, want a prompt error", err, time.Since(start))
	}
}

// Build bounds the copy with its own deadline, whatever the caller's context.
func TestBuildCopyHasATimeLimit(t *testing.T) {
	root, git := testRepo(t)
	_, err := buildCommit(t.Context(), root, t.TempDir(), io.Discard, git("rev-parse", "HEAD"), time.Nanosecond)
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("buildCommit with an expired copy limit = %v, want a deadline error", err)
	}
}

// git never runs in root: configuration that includes a FIFO or names an attributes file outside
// the repository, a FIFO .gitattributes and a replace ref change nothing and leak nothing.
func TestSourceRepositoryIsNotRead(t *testing.T) {
	root, git := testRepo(t)
	head := git("rev-parse", "HEAD")
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("PRIVATE-VALUE!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("replace", git("rev-parse", "HEAD:range/mkosi.conf"), git("hash-object", "-w", "/dev/null"))
	git("config", "core.attributesFile", secret)
	git("config", "include.path", filepath.Join(dir, "include"))
	// Planted last: git in this test would block on them too.
	for _, fifo := range []string{filepath.Join(dir, "include"), filepath.Join(root, ".gitattributes")} {
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	stage := stageFor(t)
	start := time.Now()
	log, err := exportLogged(t, ctx, root, stage, head)
	if err != nil {
		t.Fatalf("export: %v (log %q)", err, log)
	}
	if time.Since(start) > 10*time.Second || strings.Contains(log, "PRIVATE-VALUE") {
		t.Fatalf("root's configuration was read: %v, log %q", time.Since(start), log)
	}
	got, err := os.ReadFile(filepath.Join(stage, "src", "range", "mkosi.conf")) //nolint:gosec // test export directory
	if err != nil || string(got) != "[Distribution]\n" {
		t.Fatalf("exported mkosi.conf = %q, %v; want the committed bytes", got, err)
	}
}

// exportLogged runs fetchAndExport with a file as its log, as Build does with os.Stderr (a shared
// in-memory buffer would race between the tools' output copiers).
func exportLogged(t *testing.T, ctx context.Context, root, stage, commit string) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	err = fetchAndExport(ctx, newTool(ctx, stage, f), root, stage, commit, defaultLimits())
	if cerr := f.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	data, rerr := os.ReadFile(f.Name())
	if rerr != nil {
		t.Fatal(rerr)
	}
	return string(data), err
}

// Links in the object store that lead out of the repository (alternates, the commit-graph chain, an
// object file, the pack directory) are not followed: a hidden file never reaches git, the export or
// the log.
func TestObjectStoreLinksAreNotFollowed(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("PRIVATE-VALUE-1\nPRIVATE-VALUE-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, ok := range map[string]bool{"info/alternates": true, "info/commit-graphs/commit-graph-chain": true, "object": false, "pack": false} {
		root, git := testRepo(t)
		head := git("rev-parse", "HEAD")
		link := filepath.Join(root, ".git", "objects", filepath.FromSlash(name))
		target := secret
		switch name {
		case "object":
			oid := git("rev-parse", "HEAD:range/mkosi.conf")
			link = filepath.Join(root, ".git", "objects", oid[:2], oid[2:])
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
		case "pack":
			target = t.TempDir()
			if err := os.Remove(link); err != nil { // the empty pack directory git init made
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		log, err := exportLogged(t, t.Context(), root, stageFor(t), head)
		leaked := strings.Contains(log, "PRIVATE-VALUE") || err != nil && strings.Contains(err.Error(), "PRIVATE-VALUE")
		if (err == nil) != ok || leaked {
			t.Errorf("%s: export = %v, want ok=%v; log %q", name, err, ok, log)
		}
	}
}

func TestObjectStoreLimit(t *testing.T) {
	root, git := testRepo(t)
	lim := defaultLimits()
	lim.store = 16
	if _, err := exportWith(t, root, git("rev-parse", "HEAD"), lim); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("export over the object store limit = %v, want a refusal", err)
	}
}

// An object header can claim gigabytes; git on the stage repositories allocates under a limit.
func TestStageGitRunsUnderAMemoryLimit(t *testing.T) {
	cmd := stageGit(newTool(t.Context(), t.TempDir(), io.Discard), "/x", "rev-list")
	if want := []string{"/usr/bin/prlimit", "--data=" + strconv.Itoa(gitMemory), "--", "/usr/bin/git", "--git-dir=/x", "rev-list"}; !slices.Equal(cmd.Args, want) {
		t.Fatalf("argv %q, want %q", cmd.Args, want)
	}
}

func TestObjectStoreFileLimit(t *testing.T) {
	root, git := testRepo(t)
	lim := defaultLimits()
	lim.objects = 1
	if _, err := exportWith(t, root, git("rev-parse", "HEAD"), lim); err == nil || !strings.Contains(err.Error(), "over 1 entries") {
		t.Fatalf("export over the object file limit = %v, want a refusal", err)
	}
}

// Only object files are copied: an alternates file naming another store that holds the commit is
// not, so a commit missing from root's own store is refused.
func TestOnlyObjectFilesAreCopied(t *testing.T) {
	root, git := testRepo(t)
	head := git("rev-parse", "HEAD")
	elsewhere := filepath.Join(t.TempDir(), "objects")
	if err := os.Rename(filepath.Join(root, ".git", "objects"), elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git", "objects", "info"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "objects", "info", "alternates"), []byte(elsewhere+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := exportOf(t, root, head); err == nil {
		t.Fatal("export used an alternates file of root's store")
	}
}

// .git replaced by a link to another repository: its objects are outside root and never copied.
func TestForeignRepositoryIsNotCopied(t *testing.T) {
	foreign, _ := testRepo(t)
	root, git := testRepo(t)
	head := git("rev-parse", "HEAD")
	moved := filepath.Join(t.TempDir(), "git")
	if err := os.Rename(filepath.Join(root, ".git"), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(foreign, ".git"), filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	stage := stageFor(t)
	if err := fetchAndExport(t.Context(), newTool(t.Context(), stage, io.Discard), root, stage, head, defaultLimits()); err == nil {
		t.Fatal("exported through a .git link to another repository")
	}
	copied, _ := filepath.Glob(filepath.Join(stage, "reader", "objects", "??", "*"))
	if len(copied) > 0 {
		t.Fatalf("copied %d objects of the other repository: %v", len(copied), copied)
	}
}

// A FIFO where the store has a directory is refused at once instead of blocking the open.
func TestObjectStoreFIFOIsRefused(t *testing.T) {
	root, git := testRepo(t)
	pack := filepath.Join(root, ".git", "objects", "pack")
	if err := os.Remove(pack); err != nil { // the empty pack directory git init made
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(pack, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := exportOf(t, root, git("rev-parse", "HEAD")); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("exported with a FIFO as the pack directory")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("opening the FIFO blocked the copy")
	}
}

// Only a full object name reaches git: anything else could be read as an option or a revision range.
func TestExportRefusesANonCommitName(t *testing.T) {
	root, _ := testRepo(t)
	for _, name := range []string{"", "HEAD", "--all", "-n1", strings.Repeat("a", 39), strings.Repeat("A", 40)} {
		if _, err := exportOf(t, root, name); err == nil || !strings.Contains(err.Error(), "not a full object name") {
			t.Errorf("export of %q = %v, want a refusal", name, err)
		}
	}
}

// The copy deadline ends the object store copy between reads, not only between files: one large
// pack file (sparse, so the test writes no real data first) must not run past it.
func TestObjectStoreCopyStopsAtTheDeadline(t *testing.T) {
	root, _ := testRepo(t)
	pack := filepath.Join(root, ".git", "objects", "pack", "pack-"+strings.Repeat("a", 40)+".pack")
	f, err := os.Create(pack) //nolint:gosec // test temp repository
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(f.Truncate(64<<20), f.Close()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Millisecond)
	defer cancel()
	if err := copyObjectStore(ctx, root, filepath.Join(stageFor(t), "objects"), defaultLimits()); err == nil {
		t.Fatal("copied a 64 MiB pack past a 2 ms deadline")
	}
}

// The runner names its commit (ADR 0011, point 2); anything that is not a full lower-case commit
// id is refused before the cache is even locked.
func TestBuildCommitRefusesANonCommitFirst(t *testing.T) {
	root, git := testRepo(t)
	head := git("rev-parse", "HEAD")
	for _, c := range []string{"", "dev", strings.ToUpper(head), head[:39], head + "0", "-" + head[1:]} {
		cache := t.TempDir()
		if _, err := BuildCommit(t.Context(), root, cache, io.Discard, c); err == nil || !strings.Contains(err.Error(), "not 40 lower-case hex") {
			t.Errorf("BuildCommit(%q) = %v, want a refusal", c, err)
		}
		if got := names(t, cache); len(got) != 0 {
			t.Errorf("BuildCommit(%q) left %q in the cache", c, got)
		}
	}
}

// BuildCommit builds the commit it is given, not HEAD and not the launcher's: an older commit of
// the repository exports and reaches the guest build (which this test repository cannot pass), and
// a commit missing from it does not.
func TestBuildCommitBuildsTheNamedCommit(t *testing.T) {
	root, git := testRepo(t)
	old := git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.conf"), []byte("[Distribution]\nRelease=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "y")
	_, err := BuildCommit(t.Context(), root, t.TempDir(), io.Discard, old)
	if err == nil || !strings.Contains(err.Error(), "build guest program") {
		t.Fatalf("BuildCommit(older commit) = %v, want it to reach the guest build", err)
	}
	_, err = BuildCommit(t.Context(), root, t.TempDir(), io.Discard, strings.Repeat("ab", 20))
	if err == nil || strings.Contains(err.Error(), "build guest program") {
		t.Fatalf("BuildCommit(missing commit) = %v, want the copy to refuse it", err)
	}
}

func storeImage(t *testing.T, images, name, commit string) string {
	t.Helper()
	dir := filepath.Join(images, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"image.raw":      "image " + name,
		"image.manifest": `{"manifest_version":1,"packages":[{"name":"linux","version":"7.2.8"}]}`,
		"commit":         commit + "\n",
	}
	for f, data := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "image.raw")
}

func TestOpenImage(t *testing.T) {
	commit := strings.Repeat("a", 40)
	path := storeImage(t, t.TempDir(), "x", commit)
	img, err := OpenImage(t.Context(), path)
	sum := sha256.Sum256([]byte("image x"))
	if err != nil || img.Commit != commit || img.SHA256 != hex.EncodeToString(sum[:]) || len(img.Manifest) == 0 {
		t.Fatalf("OpenImage = %+v, %v", img, err)
	}
	// Beside its own commit and manifest, so only the link itself can be refused.
	link := filepath.Join(filepath.Dir(path), "link.raw")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenImage(t.Context(), link); err == nil {
		t.Fatal("OpenImage followed a link")
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), "commit")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenImage(t.Context(), path); err == nil {
		t.Fatal("OpenImage of an image without its commit succeeded")
	}
}

func TestLockExcludesBuildAndCheck(t *testing.T) {
	root, git := testRepo(t)
	cache := t.TempDir()
	held, err := Lock(cache)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Check(t.Context(), filepath.Join(cache, "none"), cache, t.TempDir()); err == nil || !strings.Contains(err.Error(), "another balistid-range") {
		t.Errorf("Check under the lock = %v", err)
	}
	if _, err := BuildCommit(t.Context(), root, cache, io.Discard, git("rev-parse", "HEAD")); err == nil || !strings.Contains(err.Error(), "another balistid-range") {
		t.Errorf("BuildCommit under the lock = %v", err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := Lock(cache); err != nil {
		t.Fatalf("Lock after Close = %v", err)
	} else if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}
