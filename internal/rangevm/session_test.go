package rangevm

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"testing"
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
	held, err := lock(cache)
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
	if _, err := lock(cache); err == nil {
		t.Fatal("a second holder got the lock")
	}
	if err := closeLock(held); err != nil {
		t.Fatal(err)
	}
	again, err := lock(cache)
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
	pass := Outcome{Facts: []Record{fact(FactKernel, TargetKernel), fact(FactNet, "lo"), fact(FactPCINet, "")}}
	nic := Outcome{Facts: []Record{fact(FactKernel, TargetKernel), fact(FactNet, "eth0,lo"), fact(FactPCINet, "")}}
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
		if got, reason := judge(c.o, c.launcher, commit); got != c.want {
			t.Errorf("%s: judge = %s (%s), want %s", c.name, got, reason, c.want)
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
	if err := writeFileAtomic(path, []byte("{}")); err != nil {
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

func TestBuildRefusesInputsThatDifferFromHead(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "/usr/bin/git", append([]string{"-C", root, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...) //nolint:gosec // test temp repository
		cmd.Env = withoutGit(os.Environ())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
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
	// mkosi would read this untracked file, so the image would not be what the commit says.
	if err := os.WriteFile(filepath.Join(root, "range", "mkosi.local.conf"), []byte("[Content]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Build(t.Context(), root, t.TempDir(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "build inputs differ") {
		t.Fatalf("Build = %v, want a refusal for the untracked file", err)
	}
}
