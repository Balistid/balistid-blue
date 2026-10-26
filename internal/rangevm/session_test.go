package rangevm

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
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

// The mode is the one asked for whatever the umask: 0600 for private state, 0640 for results the
// maintainer's group reads.
func TestWriteFileAtomicSetsTheMode(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	for _, perm := range []os.FileMode{0o600, 0o640} {
		path := filepath.Join(t.TempDir(), "result.json")
		if err := WriteFileAtomic(path, []byte("{}"), perm); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != perm {
			t.Fatalf("mode %v, want %v", st.Mode().Perm(), perm)
		}
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
	stage := t.TempDir() // before TMPDIR changes below
	for k, v := range map[string]string{"GOFLAGS": "-toolexec=/tmp/x", "GOROOT": "/tmp/goroot", "GOCACHE": "/tmp/cache",
		"LD_PRELOAD": "/tmp/x.so", "GIT_DIR": "/tmp/repo", "TMPDIR": "/tmp/shared", "XDG_CACHE_HOME": "/tmp/cache",
		"GOPROXY": "http://evil,direct", "GOMODCACHE": "/tmp/mod", "GONOSUMDB": "*", "GOPRIVATE": "*", "GOINSECURE": "*",
		"GOSUMDB": "off", "GOVCS": "*:all", "https_proxy": "http://proxy:3128", "HTTPS_PROXY": "http://proxy:3129"} {
		t.Setenv(k, v)
	}
	home := filepath.Join(stage, "home")
	// The mirror alone, spelled out so a change of moduleProxy fails here too.
	goWant := []string{"PATH=/usr/bin", "HOME=" + home, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + stage, "GOENV=off", "GOCACHE=" + filepath.Join(home, "gocache"),
		"GOMODCACHE=" + filepath.Join(home, "gomod"), "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org", "GOTOOLCHAIN=local", "GOWORK=off",
		"GOFLAGS=-mod=readonly -buildvcs=false", "CGO_ENABLED=0", "TMPDIR=" + filepath.Join(stage, "tmp")}
	// go gets no proxy variable; makepkg and mkosi keep the caller's, which choose their network path.
	cmd := newGoTool(t.Context(), stage, defaultBuild().proxy, io.Discard)("/", "/usr/bin/true")
	if !slices.Equal(cmd.Env, goWant) {
		t.Fatalf("go environment\n got %q\nwant %q", cmd.Env, goWant)
	}
	want := append(slices.Clone(goWant), "https_proxy=http://proxy:3128", "HTTPS_PROXY=http://proxy:3129")
	cmd = newTool(t.Context(), stage, defaultBuild().proxy, io.Discard)("/", "/usr/bin/true")
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
	err := fetchAndExport(t.Context(), newTool(t.Context(), stage, moduleProxy, io.Discard), root, stage, commit, lim)
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
	requireHostGo(t)
	outer := t.TempDir()
	if out, err := exec.CommandContext(t.Context(), "/usr/bin/git", "init", "-q", outer).CombinedOutput(); err != nil { //nolint:gosec // test temp repository
		t.Fatalf("git init: %v %s", err, out)
	}
	stage := filepath.Join(outer, "stage")
	for _, d := range stageDirs {
		if err := os.MkdirAll(filepath.Join(stage, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	src := filepath.Join(stage, "src")
	for name, body := range map[string]string{"go.mod": "module m\n\ngo 1.27\n", "main.go": "package main\n\nfunc main() {}\n"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tool := newGoTool(t.Context(), stage, moduleProxy, io.Discard)
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

// requireHostGo skips the test unless /usr/bin/go, which Build runs, is this Go (the CI runner's is
// another).
func requireHostGo(t *testing.T) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), "/usr/bin/go", "env", "GOVERSION").Output(); err != nil || strings.TrimSpace(string(out)) != runtime.Version() {
		t.Skipf("/usr/bin/go is not this Go (%q, %v)", out, err)
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
	err := fetchAndExport(t.Context(), newTool(t.Context(), stage, moduleProxy, io.Discard), root, stage, git("rev-parse", "HEAD"), defaultLimits())
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
	if err := fetchAndExport(t.Context(), newTool(t.Context(), stage, moduleProxy, io.Discard), root, stage, git("rev-parse", "HEAD"), defaultLimits()); err == nil {
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
	_, err := buildCommit(t.Context(), root, t.TempDir(), io.Discard, git("rev-parse", "HEAD"), buildConfig{copyTimeout: time.Nanosecond, proxy: moduleProxy})
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
	err = fetchAndExport(ctx, newTool(ctx, stage, moduleProxy, f), root, stage, commit, defaultLimits())
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
	cmd := stageGit(newTool(t.Context(), t.TempDir(), moduleProxy, io.Discard), "/x", "rev-list")
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
	if err := fetchAndExport(t.Context(), newTool(t.Context(), stage, moduleProxy, io.Discard), root, stage, head, defaultLimits()); err == nil {
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

// mkosi gets every writable directory inside the stage, which the build creates and removes: its
// workspace defaults to /var/tmp and, at a system uid, its package cache to /var/cache (T34). It
// maps one uid, so a killed build leaves only files the next Lock can remove.
func TestBuildKeepsMkosiDirectoriesInTheStage(t *testing.T) {
	stage, built := t.TempDir(), t.TempDir()
	cmd := mkosiCommand(newTool(t.Context(), stage, moduleProxy, io.Discard), stage, built)
	if want := append(toolEnv(stage, moduleProxy), "MKOSI_FORCE_USERNS_FALLBACK=1"); !slices.Equal(cmd.Env, want) {
		t.Errorf("mkosi environment\n got %q\nwant %q", cmd.Env, want)
	}
	if cmd.Path != "/usr/bin/mkosi" || cmd.Dir != filepath.Join(stage, "src") {
		t.Errorf("mkosi runs %s in %s", cmd.Path, cmd.Dir)
	}
	args := cmd.Args[1:]
	if args[len(args)-1] != "build" {
		t.Fatalf("mkosi argv %q does not end in the build verb", args)
	}
	inStage := func(path string) bool {
		rel, err := filepath.Rel(stage, path)
		return err == nil && filepath.IsLocal(rel)
	}
	// mkosi creates its workspace with mkdtemp inside the given directory, so it must exist.
	created := func(path string) bool {
		return inStage(path) && slices.Contains(stageDirs, strings.TrimPrefix(path, stage+"/"))
	}
	named := map[string]string{}
	for _, a := range args[:len(args)-1] {
		opt, path, ok := strings.Cut(a, "=")
		if !ok || !filepath.IsAbs(path) {
			t.Fatalf("mkosi option %q does not name an absolute path", a)
		}
		named[opt] = path
		if opt != "--output-directory" && !inStage(path) {
			t.Errorf("mkosi option %s is outside the stage's directories", a)
		}
	}
	if named["--output-directory"] != built {
		t.Errorf("mkosi output directory = %q, want %q", named["--output-directory"], built)
	}
	for _, opt := range []string{"--workspace-directory", "--package-cache-directory"} {
		if !created(named[opt]) {
			t.Errorf("mkosi %s = %q, want a directory the stage creates", opt, named[opt])
		}
	}
	tmp := ""
	for _, kv := range toolEnv(stage, moduleProxy) {
		if v, ok := strings.CutPrefix(kv, "TMPDIR="); ok {
			tmp = v
		}
	}
	if !created(tmp) {
		t.Errorf("tool TMPDIR = %q, want a directory the stage creates", tmp)
	}
}

// A killed mkosi leaves directories without owner permissions (an overlay work directory is mode
// 000, here not empty); the next Lock still sweeps the stage, and follows no symlink out of it.
func TestSweepRemovesDirectoriesWithoutPermissions(t *testing.T) {
	cache, outside := t.TempDir(), t.TempDir()
	locked := filepath.Join(outside, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(cache, "stage-x", "mkosi-workspace", "work")
	if err := os.MkdirAll(filepath.Join(work, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "work", "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{filepath.Join(cache, "stage-x", "link"), filepath.Join(cache, "stage-link")} {
		if err := os.Symlink(outside, l); err != nil {
			t.Fatal(err)
		}
	}
	for path, mode := range map[string]os.FileMode{filepath.Join(work, "work"): 0, work: 0o500, locked: 0, outside: 0o750} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o700) }) //nolint:gosec // let TempDir clean up
	}
	held, err := Lock(cache)
	if err != nil {
		t.Fatalf("Lock after a killed build: %v", err)
	}
	if err := closeLock(held); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(cache, "stage-x"), filepath.Join(cache, "stage-link")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the sweep: %v", p, err)
		}
	}
	for path, want := range map[string]os.FileMode{outside: 0o750, locked: 0} {
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s outside the stage has mode %v, want %v", path, st.Mode().Perm(), want)
		}
	}
}

// A process at the build's uid swaps a directory of the stage for a hard link to a file outside
// while the stage is opened for removal; the file outside keeps its mode.
func TestOpenDirsChangesNoSwappedName(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(outside, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	d := filepath.Join(stage, "d")
	for range 3000 {
		if err := os.Mkdir(d, 0o500); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if os.Remove(d) == nil {
				_ = os.Link(outside, d)
			}
		}()
		_ = openDirs(stage)
		<-done
		st, err := os.Stat(outside)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o400 {
			t.Fatalf("file outside the stage has mode %v after openDirs", st.Mode().Perm())
		}
		if err := os.Remove(d); err != nil {
			t.Fatal(err)
		}
	}
}

func deepTree(t *testing.T, depth int) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(append([]string{root}, slices.Repeat([]string{"a"}, depth)...)...), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

// T36: a planted tree deeper than any stage fails closed instead of costing memory quadratic in its depth.
func TestOpenDirsRefusesATreeTooDeep(t *testing.T) {
	if err := openDirs(deepTree(t, maxStageDepth)); err != nil {
		t.Fatalf("tree at the limit: %v", err)
	}
	if err := openDirs(deepTree(t, maxStageDepth+1)); err == nil || !strings.Contains(err.Error(), "directories deep") {
		t.Fatalf("tree over the limit: %v", err)
	}
}

// Errors opening the root and listing a directory are returned, not treated as a name to skip.
func TestOpenDirsReturnsItsErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches a mode 000 directory")
	}
	shut := t.TempDir()
	if err := os.Mkdir(filepath.Join(shut, "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shut, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shut, 0o700) }) //nolint:gosec // let TempDir clean up
	if err := openDirs(filepath.Join(shut, "c")); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("openDirs below an unsearchable directory: %v", err)
	}
	root := deepTree(t, 200)
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old) })
	low := syscall.Rlimit{Cur: 64, Max: old.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Fatal(err)
	}
	if err := openDirs(root); !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("openDirs with 64 descriptors on a 200-deep tree: %v", err)
	}
}

// BuildCommit builds the commit it is given, not HEAD and not the launcher's: an older commit of
// the repository exports and reaches the first step after the copy, reading its go.mod (which this
// test repository lacks), and a commit missing from it does not.
func TestBuildCommitBuildsTheNamedCommit(t *testing.T) {
	root, git := testRepo(t)
	old := git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.conf"), []byte("[Distribution]\nRelease=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "y")
	_, err := BuildCommit(t.Context(), root, t.TempDir(), io.Discard, old)
	if err == nil || !strings.Contains(err.Error(), "read go.mod") {
		t.Fatalf("BuildCommit(older commit) = %v, want it to reach the go.mod check", err)
	}
	_, err = BuildCommit(t.Context(), root, t.TempDir(), io.Discard, strings.Repeat("ab", 20))
	if err == nil || strings.Contains(err.Error(), "read go.mod") {
		t.Fatalf("BuildCommit(missing commit) = %v, want the copy to refuse it", err)
	}
}

// The module the tests' file:// proxy serves.
const (
	fixturePath    = "example.com/fixture"
	fixtureVersion = "v1.0.0"
	fixtureMod     = "module " + fixturePath + "\n\ngo 1.24\n"
	fixtureSource  = "package fixture\n\nconst X = 1\n"
)

// fixtureZip is the content of the fixture's module zip, by the names go.sum hashes.
func fixtureZip(source string) map[string]string {
	prefix := fixturePath + "@" + fixtureVersion + "/"
	return map[string]string{prefix + "go.mod": fixtureMod, prefix + "fixture.go": source}
}

// h1 is the hash a go.sum line carries (dirhash.Hash1 of golang.org/x/mod): SHA-256 over the
// sorted "sha256  name" lines of the files.
func h1(files map[string]string) string {
	sum := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		_, _ = fmt.Fprintf(sum, "%x  %s\n", sha256.Sum256([]byte(files[name])), name) // a hash never fails a write
	}
	return "h1:" + base64.StdEncoding.EncodeToString(sum.Sum(nil))
}

// fixtureSum is the fixture's go.sum: its go.mod line and, unless modOnly, the line of a zip of zipped.
func fixtureSum(zipped map[string]string, modOnly bool) string {
	sum := fixturePath + " " + fixtureVersion + "/go.mod " + h1(map[string]string{"go.mod": fixtureMod}) + "\n"
	if !modOnly {
		sum += fixturePath + " " + fixtureVersion + " " + h1(zipped) + "\n"
	}
	return sum
}

// fileProxy lays out a GOPROXY directory that serves the fixture with zipped as its zip and
// returns its file:// URL: modules come from it without any network.
func fileProxy(t *testing.T, zipped map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(zipped)) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, zipped[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	v := filepath.Join(dir, fixturePath, "@v")
	if err := os.MkdirAll(v, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"list":                   fixtureVersion + "\n",
		fixtureVersion + ".info": `{"Version":"` + fixtureVersion + `","Time":"2026-01-01T00:00:00Z"}`,
		fixtureVersion + ".mod":  fixtureMod,
		fixtureVersion + ".zip":  buf.String(),
	} {
		if err := os.WriteFile(filepath.Join(v, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return "file://" + dir
}

// moduleRepo is testRepo with a guest program that imports the fixture and goSum as its go.sum.
func moduleRepo(t *testing.T, goSum string) (root, commit string) {
	t.Helper()
	return replacingRepo(t, goSum, "", nil)
}

// replacingRepo is moduleRepo with replace as a replace directive in go.mod (none when empty) and
// files added to the commit.
func replacingRepo(t *testing.T, goSum, replace string, files map[string]string) (root, commit string) {
	t.Helper()
	root, git := testRepo(t)
	goMod := "module m\n\ngo 1.24\n\nrequire " + fixturePath + " " + fixtureVersion + "\n"
	if replace != "" {
		goMod += "\nreplace " + replace + "\n"
	}
	all := map[string]string{
		"go.mod":                           goMod,
		"go.sum":                           goSum,
		"cmd/balistid-range-guest/main.go": "package main\n\nimport \"" + fixturePath + "\"\n\nfunc main() { _ = fixture.X }\n",
		"cmd/balistid-collector/main.go":   "package main\n\nfunc main() {}\n",
	}
	maps.Copy(all, files)
	for name, body := range all {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("add", ".")
	git("commit", "-q", "-m", "module")
	return root, git("rev-parse", "HEAD")
}

// buildWithProxy runs buildCommit with modules from proxy and a file as its log (see exportLogged)
// and returns the log and the error. go leaves its module cache read-only; the stage holding it
// must still be removed.
func buildWithProxy(t *testing.T, root, commit, proxy string) (string, error) {
	t.Helper()
	return buildInCache(t, t.TempDir(), root, commit, proxy)
}

// buildInCache is buildWithProxy with cache as the build cache, which holds the stage.
func buildInCache(t *testing.T, cache, root, commit, proxy string) (string, error) {
	t.Helper()
	cfg := defaultBuild()
	cfg.proxy = proxy
	return buildWith(t, cache, root, commit, cfg)
}

// buildWith is buildInCache with the whole configuration given.
func buildWith(t *testing.T, cache, root, commit string, cfg buildConfig) (string, error) {
	t.Helper()
	requireHostGo(t)
	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildCommit(t.Context(), root, cache, f, commit, cfg)
	if cerr := f.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	data, rerr := os.ReadFile(f.Name())
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, n := range names(t, cache) {
		if strings.HasPrefix(n, "stage-") {
			t.Errorf("build left its stage %s behind: %v", n, err)
		}
	}
	return string(data), err
}

// go in the stage runs with telemetry off, so it starts no sidecar that would outlive the build and
// write into the stage while it is removed.
func TestStageGoHasTelemetryOff(t *testing.T) {
	requireHostGo(t)
	stage := t.TempDir()
	if err := prepareStage(stage); err != nil {
		t.Fatal(err)
	}
	cmd := newGoTool(t.Context(), stage, moduleProxy, io.Discard)(stage, "/usr/bin/go", "env", "GOTELEMETRY")
	cmd.Stdout = nil
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "off" {
		t.Fatalf("go env GOTELEMETRY in the stage = %q, %v; want off", out, err)
	}
}

// A module go.sum names comes from the proxy into the stage, and the guest builds with it. This
// test repository has no image files, so the build stops at the first one.
func TestBuildFetchesTheModulesGoSumNames(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	root, commit := moduleRepo(t, fixtureSum(zipped, false))
	log, err := buildWithProxy(t, root, commit, fileProxy(t, zipped))
	if err == nil || !strings.Contains(err.Error(), "image file") {
		t.Fatalf("build = %v, want the guest built and then a missing image file; log:\n%s", err, log)
	}
}

// The collector is built into the image with the guest (ADR 0022, point 1): its modules come down in
// the same checked download, and a collector that does not build fails the image.
func TestBuildBuildsTheCollector(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	uses := map[string]string{
		"cmd/balistid-range-guest/main.go": "package main\n\nfunc main() {}\n",
		"cmd/balistid-collector/main.go":   "package main\n\nimport \"" + fixturePath + "\"\n\nfunc main() { _ = fixture.X }\n",
	}
	broken := map[string]string{"cmd/balistid-collector/main.go": "package main\n\nfunc main() {\n"}
	for _, tc := range []struct {
		name, goSum, want string
		files             map[string]string
	}{
		{"module missing from go.sum", fixtureSum(zipped, true), "download modules", uses},
		{"collector does not build", fixtureSum(zipped, false), "build collector program", broken},
		{"both build", fixtureSum(zipped, false), "image file", uses},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, commit := replacingRepo(t, tc.goSum, "", tc.files)
			log, err := buildWithProxy(t, root, commit, fileProxy(t, zipped))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("build = %v, want %q; log:\n%s", err, tc.want, log)
			}
		})
	}
}

// The image's programs and every directory of its tree are 0755 whatever the builder's umask: the
// collector runs as its own uid, not root, and must reach and exec its binary in the range.
func TestImageTreeIsOpenToOtherUsers(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	files := map[string]string{}
	for _, f := range imageFiles {
		files[f.src] = "x\n"
	}
	root, commit := replacingRepo(t, fixtureSum(zipped, false), "", files)
	cfg := defaultBuild()
	cfg.proxy = fileProxy(t, zipped)
	var wrong []string
	reached := false
	cfg.afterTree = func(tree string) {
		reached = true
		err := filepath.WalkDir(tree, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if d.IsDir() && info.Mode().Perm() != 0o755 {
				wrong = append(wrong, fmt.Sprintf("%s %o", path, info.Mode().Perm()))
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
		for _, p := range imagePrograms {
			if st, err := os.Stat(filepath.Join(tree, p.dst)); err != nil || st.Mode().Perm() != 0o755 {
				wrong = append(wrong, fmt.Sprintf("%s %v", p.dst, err))
			}
		}
	}
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	log, err := buildWith(t, t.TempDir(), root, commit, cfg)
	if !reached || err == nil || !strings.Contains(err.Error(), "makepkg") {
		t.Fatalf("build = %v (tree reached %v), want the tree built and makepkg to fail; log:\n%s", err, reached, log)
	}
	if len(wrong) > 0 {
		t.Fatalf("not open to other users: %v", wrong)
	}
}

// T34: a link planted in the stage tree never widens a file outside it: the walk skips a link to a
// directory, and a program that is a link out of the tree fails instead of changing its target.
func TestOpenTreeChangesNothingOutsideTheTree(t *testing.T) {
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil { //nolint:gosec // a directory, owner only
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	for _, p := range imagePrograms {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(tree, p.dst)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tree, p.dst), nil, 0o700); err != nil { //nolint:gosec // a program, as go build writes it
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(tree, "usr", "out")); err != nil {
		t.Fatal(err)
	}
	if err := openTree(tree); err != nil {
		t.Fatalf("a tree with a link to a directory outside: %v", err)
	}
	program := filepath.Join(tree, imagePrograms[1].dst)
	if err := os.Remove(program); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, program); err != nil {
		t.Fatal(err)
	}
	if err := openTree(tree); err == nil {
		t.Error("a program linked out of the tree was accepted")
	}
	for path, want := range map[string]os.FileMode{outside: 0o700, secret: 0o600} {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: mode %v (%v), want %o", path, st.Mode().Perm(), err, want)
		}
	}
}

// T34: a proxy that serves other bytes than go.sum names fails the guest build. The check is Go's
// own under -mod=readonly, not code here: the test guards that toolEnv keeps it on.
func TestBuildRefusesAModuleThatDoesNotMatchGoSum(t *testing.T) {
	root, commit := moduleRepo(t, fixtureSum(fixtureZip(fixtureSource), false))
	log, err := buildWithProxy(t, root, commit, fileProxy(t, fixtureZip("package fixture\n\nconst X = 2\n")))
	if err == nil || !strings.Contains(err.Error(), "build guest program") || !strings.Contains(log, "checksum mismatch") {
		t.Fatalf("build = %v, want a checksum mismatch in the guest build; log:\n%s", err, log)
	}
}

// T34: a module go.sum does not name is not added to it, so the build never takes what the proxy
// serves on its word.
func TestBuildRefusesAModuleMissingFromGoSum(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	root, commit := moduleRepo(t, fixtureSum(zipped, true))
	log, err := buildWithProxy(t, root, commit, fileProxy(t, zipped))
	if err == nil || !strings.Contains(err.Error(), "build guest program") || !strings.Contains(log, "missing go.sum entry") {
		t.Fatalf("build = %v, want a missing go.sum entry in the guest build; log:\n%s", err, log)
	}
}

// T34: a replace to a path makes go build a module from the file system with no go.sum line, from
// the host as well as from the export, so the build refuses it before go build runs. The replaced
// source does not compile, so a go build that ran, with or without the refusal after it, fails the
// guest build instead.
func TestBuildRefusesAPathReplace(t *testing.T) {
	const broken = "package fixture\n\nconst X =\n"
	host := t.TempDir()
	for name, body := range map[string]string{"go.mod": fixtureMod, "fixture.go": broken} {
		if err := os.WriteFile(filepath.Join(host, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		target string
		files  map[string]string
	}{
		"host directory":   {target: host},
		"export directory": {target: "./fixture", files: map[string]string{"fixture/go.mod": fixtureMod, "fixture/fixture.go": broken}},
	} {
		t.Run(name, func(t *testing.T) {
			root, commit := replacingRepo(t, "", fixturePath+" => "+tc.target, tc.files)
			log, err := buildWithProxy(t, root, commit, fileProxy(t, fixtureZip(fixtureSource)))
			if err == nil || !strings.Contains(err.Error(), "a replace to a path is refused") || strings.Contains(err.Error(), "build guest program") {
				t.Fatalf("build = %v, want the path replace refused before go build; log:\n%s", err, log)
			}
		})
	}
}

// A replace by a module version is not refused. It only tests the refusal: the replaced v0.9.0 is
// never selected (MVS takes the required v1.0.0), so the replace changes nothing in the build.
func TestBuildDoesNotRefuseAVersionReplace(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	root, commit := replacingRepo(t, fixtureSum(zipped, false), fixturePath+" v0.9.0 => "+fixturePath+" "+fixtureVersion, nil)
	log, err := buildWithProxy(t, root, commit, fileProxy(t, zipped))
	if err == nil || !strings.Contains(err.Error(), "image file") {
		t.Fatalf("build = %v, want the guest built and then a missing image file; log:\n%s", err, log)
	}
}

// R5: the modules a build downloads may take at most cfg.moduleCache on disk. A fixture with a
// 2 MiB file is refused under a 1 MiB cap before go build runs, and builds under a 16 MiB one.
func TestBuildCapsTheModuleCache(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	zipped[fixturePath+"@"+fixtureVersion+"/blob.txt"] = strings.Repeat("x", 2<<20)
	root, commit := moduleRepo(t, fixtureSum(zipped, false))
	proxy := fileProxy(t, zipped)
	for _, tc := range []struct {
		limit int64
		want  string
	}{{1 << 20, "modules take more than 1048576 bytes on disk"}, {16 << 20, "image file"}} {
		cfg := defaultBuild()
		cfg.proxy, cfg.moduleCache = proxy, tc.limit
		log, err := buildWith(t, t.TempDir(), root, commit, cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "build guest program") {
			t.Errorf("build with a %d byte cap = %v, want %q before any failing go command; log:\n%s", tc.limit, err, tc.want, log)
		}
	}
	if defaultBuild().moduleCache != 1<<30 {
		t.Errorf("default module cache cap %d, want 1 GiB", defaultBuild().moduleCache)
	}
}

// A guest that needs no module leaves no module cache, and the cap does not refuse that.
func TestModuleCacheCapWithoutModules(t *testing.T) {
	if err := capModuleCache(filepath.Join(t.TempDir(), "gomod"), 0); err != nil {
		t.Fatalf("cap on a missing cache = %v, want nil", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := capModuleCache(dir, 0); err == nil {
		t.Fatal("a cache over its cap passed")
	}
}

// The cap counts allocated blocks, refuses a cache it cannot walk whole (R6) and one reached
// through a link, whose target it would not measure.
func TestModuleCacheCapCountsBlocksAndRefusesWhatItCannotRead(t *testing.T) {
	sparse := t.TempDir()
	hole := filepath.Join(sparse, "sparse")
	if err := errors.Join(os.WriteFile(hole, nil, 0o600), os.Truncate(hole, 1<<30)); err != nil {
		t.Fatal(err)
	}
	if err := capModuleCache(sparse, 1<<20); err != nil {
		t.Errorf("a sparse 1 GiB file under a 1 MiB cap = %v, want nil", err)
	}

	unreadable := t.TempDir()
	sub := filepath.Join(unreadable, "sub")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) }) //nolint:gosec // lets TempDir remove it
	if err := capModuleCache(unreadable, 1<<30); err == nil {
		t.Error("a cache with an unreadable directory passed")
	}

	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "big"), bytes.Repeat([]byte("x"), 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "gomod")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := capModuleCache(link, 1<<30); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a linked cache = %v, want it refused", err)
	}
	if err := capModuleCache(filepath.Join(target, "big"), 1<<30); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file as the cache = %v, want it refused", err)
	}
	for name, create := range map[string]func(string) error{
		"link": func(p string) error { return os.Symlink(target, p) },
		"fifo": func(p string) error { return syscall.Mkfifo(p, 0o600) },
	} {
		dir := t.TempDir()
		if err := create(filepath.Join(dir, "entry")); err != nil {
			t.Fatal(err)
		}
		if err := capModuleCache(dir, 1<<30); err == nil || !strings.Contains(err.Error(), "not a file or directory") {
			t.Errorf("a %s in the cache = %v, want it refused", name, err)
		}
	}
}

// go build runs with GOPROXY=off: a module missing after the cap fails the build instead of
// coming down unmeasured.
func TestBuildFetchesNothingAfterTheCap(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	root, commit := moduleRepo(t, fixtureSum(zipped, false))
	cfg := defaultBuild()
	cfg.proxy = fileProxy(t, zipped)
	cfg.afterCap = func(stage string) {
		if err := os.Rename(moduleCache(stage), moduleCache(stage)+".gone"); err != nil {
			t.Error(err)
		}
	}
	log, err := buildWith(t, t.TempDir(), root, commit, cfg)
	if err == nil || !strings.Contains(err.Error(), "build guest program") || !strings.Contains(log, "GOPROXY=off") {
		t.Fatalf("build without its modules after the cap = %v, want go build to fail offline; log:\n%s", err, log)
	}
}

// A cache reached through a symbolic link (a linked ~/.cache or XDG_CACHE_HOME) builds: go names
// the export's go.mod by its real path, and the module check accepts that spelling.
func TestBuildThroughASymlinkedCache(t *testing.T) {
	zipped := fixtureZip(fixtureSource)
	root, commit := moduleRepo(t, fixtureSum(zipped, false))
	cache := filepath.Join(t.TempDir(), "cache")
	if err := os.Symlink(t.TempDir(), cache); err != nil {
		t.Fatal(err)
	}
	log, err := buildInCache(t, cache, root, commit, fileProxy(t, zipped))
	if err == nil || !strings.Contains(err.Error(), "image file") {
		t.Fatalf("build = %v, want the guest built and then a missing image file; log:\n%s", err, log)
	}
}

// T34: an export without a go.mod would make go use one above the stage, which an agent at the
// same uid can plant, and compile host files into the guest. The build refuses it before go build
// runs; the planted package does not compile, so a go build that ran fails the guest build instead.
func TestBuildRefusesAGoModAboveTheExport(t *testing.T) {
	root, git := testRepo(t)
	guest := filepath.Join(root, "cmd", "balistid-range-guest")
	if err := os.MkdirAll(guest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guest, "main.go"), []byte("package main\n\nimport _ \"m/planted\"\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "no go.mod")
	cache := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cache, "planted"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"go.mod": "module m\n\ngo 1.24\n", "planted/planted.go": "package planted\n\nconst X =\n"} {
		if err := os.WriteFile(filepath.Join(cache, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log, err := buildInCache(t, cache, root, git("rev-parse", "HEAD"), fileProxy(t, fixtureZip(fixtureSource)))
	if err == nil || !strings.Contains(err.Error(), "not the export's own") || strings.Contains(err.Error(), "build guest program") {
		t.Fatalf("build = %v, want the go.mod above the export refused before go build; log:\n%s", err, log)
	}
}

// T34: go reaches only the configured module proxy, never through an HTTP proxy from the caller's
// environment. Neither address is served: go never proxies a loopback address but does proxy
// 0.0.0.0, so a go that took the proxy variables reports a proxyconnect error, one that did not a
// refused connection to 0.0.0.0. No network is used.
func TestGoUsesNoHTTPProxy(t *testing.T) {
	for _, k := range proxyEnv {
		v := "http://127.0.0.1:9"
		if strings.EqualFold(k, "no_proxy") {
			v = ""
		}
		t.Setenv(k, v)
	}
	zipped := fixtureZip(fixtureSource)
	root, commit := moduleRepo(t, fixtureSum(zipped, false))
	log, err := buildWithProxy(t, root, commit, "https://0.0.0.0:1")
	if err == nil || !strings.Contains(err.Error(), "build guest program") || strings.Contains(log, "proxyconnect") || !strings.Contains(log, "0.0.0.0:1") {
		t.Fatalf("build = %v, want a direct, refused connection to the module proxy; log:\n%s", err, log)
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
