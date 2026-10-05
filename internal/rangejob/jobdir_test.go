package rangejob

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	runJSON  = `{"schema_version":1,"kind":"run","trials":2}`
	execJSON = `{"schema_version":1,"kind":"exec","program":"probe","timeout_s":10}`
)

// inbox makes an inbox with one job directory "j1" holding files, and opens it as a root.
func inbox(t *testing.T, files map[string]string) (*os.Root, string) {
	t.Helper()
	base := t.TempDir()
	job := filepath.Join(base, "j1")
	if err := os.Mkdir(job, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(job, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, job
}

// readJob fails the test if ReadJob blocks, which is what an opened FIFO would do.
func readJob(t *testing.T, root *os.Root, name string) (Job, error) {
	t.Helper()
	type result struct {
		job Job
		err error
	}
	done := make(chan result, 1)
	go func() {
		job, err := ReadJob(root, name)
		done <- result{job, err}
	}()
	select {
	case r := <-done:
		return r.job, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("ReadJob blocked")
		return Job{}, nil
	}
}

func TestReadJobAccepts(t *testing.T) {
	root, _ := inbox(t, map[string]string{RequestFile: runJSON})
	job, err := readJob(t, root, "j1")
	if err != nil || job.Request.Kind != KindRun || job.Request.Trials != 2 || job.Program != nil {
		t.Fatalf("run job: %+v, %v", job, err)
	}
	root, _ = inbox(t, map[string]string{RequestFile: execJSON, "probe": "#!/bin/sh\nid\n"})
	job, err = readJob(t, root, "j1")
	if err != nil || job.Name != "j1" || job.Request.Program != "probe" || !bytes.Equal(job.Program, []byte("#!/bin/sh\nid\n")) {
		t.Fatalf("exec job: %+v, %v", job, err)
	}
}

func TestReadJobRefusesLayouts(t *testing.T) {
	cases := map[string]map[string]string{
		"no request":         {"probe": "x"},
		"exec without file":  {RequestFile: execJSON},
		"run with a program": {RequestFile: runJSON, "probe": "x"},
		"extra file":         {RequestFile: execJSON, "probe": "x", "other": "x"},
		"bad request":        {RequestFile: `{"kind":"run"}`},
		"program over cap":   {RequestFile: execJSON, "probe": strings.Repeat("x", MaxProgramBytes+1)},
		"request over cap":   {RequestFile: runJSON + strings.Repeat(" ", MaxRequestBytes)},
	}
	for name, files := range cases {
		root, _ := inbox(t, files)
		if job, err := readJob(t, root, "j1"); err == nil {
			t.Errorf("%s: accepted %+v", name, job)
		}
	}
}

func TestReadJobRefusesNames(t *testing.T) {
	root, _ := inbox(t, map[string]string{RequestFile: runJSON})
	for _, name := range []string{"", ".", "..", "J1", "j1/", "../j1", "-j", strings.Repeat("j", 65), "nope"} {
		if _, err := readJob(t, root, name); err == nil {
			t.Errorf("job name %q accepted", name)
		}
	}
}

// Each special entry replaces job.json or the program; none may be opened, so a FIFO cannot block.
func TestReadJobRefusesSpecialFilesUnopened(t *testing.T) {
	special := map[string]func(t *testing.T, path, job string){
		"symlink inside the inbox": func(t *testing.T, path, job string) {
			real := filepath.Join(filepath.Dir(job), "real-"+filepath.Base(path))
			must(t, os.WriteFile(real, []byte(execJSON), 0o600))
			must(t, os.Symlink("../"+filepath.Base(real), path))
		},
		"symlink out of the inbox": func(t *testing.T, path, _ string) {
			must(t, os.Symlink("/etc/passwd", path))
		},
		"hard link": func(t *testing.T, path, _ string) {
			other := filepath.Join(t.TempDir(), "x")
			must(t, os.WriteFile(other, []byte(execJSON), 0o600))
			must(t, os.Link(other, path))
		},
		"fifo":      func(t *testing.T, path, _ string) { must(t, syscall.Mkfifo(path, 0o600)) },
		"directory": func(t *testing.T, path, _ string) { must(t, os.Mkdir(path, 0o700)) },
	}
	for name, make := range special {
		for _, target := range []string{RequestFile, "probe"} {
			files := map[string]string{RequestFile: execJSON, "probe": "x"}
			delete(files, target)
			root, job := inbox(t, files)
			make(t, filepath.Join(job, target), job)
			if j, err := readJob(t, root, "j1"); err == nil {
				t.Errorf("%s as %s: accepted %+v", name, target, j)
			}
		}
	}
}

func TestReadJobRefusesALinkedJobDirectory(t *testing.T) {
	root, job := inbox(t, map[string]string{RequestFile: runJSON})
	must(t, os.Symlink(job, filepath.Join(filepath.Dir(job), "j2")))
	if j, err := readJob(t, root, "j2"); err == nil {
		t.Fatalf("symlinked job directory accepted: %+v", j)
	}
	fifoRoot, base := inbox(t, map[string]string{RequestFile: runJSON})
	must(t, syscall.Mkfifo(filepath.Join(filepath.Dir(base), "j3"), 0o600))
	if j, err := readJob(t, fifoRoot, "j3"); err == nil {
		t.Fatalf("FIFO job accepted: %+v", j)
	}
}

// The agent can swap the job directory after ReadJob's Lstat; openJobDir is what then runs.
func TestOpenJobDirRefusesASwappedDirectory(t *testing.T) {
	root, job := inbox(t, map[string]string{RequestFile: runJSON})
	base := filepath.Dir(job)
	checked, err := root.Lstat("j1")
	must(t, err)
	must(t, syscall.Mkfifo(filepath.Join(base, "fifo"), 0o600))
	must(t, os.Mkdir(filepath.Join(base, "other"), 0o700))
	must(t, os.Symlink("other", filepath.Join(base, "link")))
	for _, name := range []string{"fifo", "other", "link"} {
		done := make(chan error, 1)
		go func() {
			dir, err := openJobDir(root, name, checked)
			if err == nil {
				_ = dir.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s opened as the checked job directory", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: openJobDir blocked", name)
		}
	}
}

// entries reads exactly three names: two would let readdir order decide whether a third file is
// seen, more would read a directory of any size.
func TestEntriesReadsAtMostThree(t *testing.T) {
	root, _ := inbox(t, map[string]string{RequestFile: execJSON, "probe": "x", "a": "x", "b": "x"})
	dir, err := root.OpenRoot("j1")
	must(t, err)
	defer dir.Close() //nolint:errcheck // test
	names, err := entries(dir)
	if err != nil || len(names) != 3 {
		t.Fatalf("entries = %v, %v; want 3 names", names, err)
	}
	if job, err := readJob(t, root, "j1"); err == nil {
		t.Fatalf("extra files accepted: %+v", job)
	}
}

func TestReadJobErrorsDoNotQuoteContent(t *testing.T) {
	marker := "IGNOREPREVIOUS"
	root, _ := inbox(t, map[string]string{
		RequestFile: `{"schema_version":1,"kind":"exec","program":"probe","timeout_s":10}`, "probe": marker,
		marker: marker,
	})
	if _, err := readJob(t, root, "j1"); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("error %v quotes the job", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
