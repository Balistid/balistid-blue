package rangejob

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"syscall"
)

// MaxProgramBytes caps the program of an exec job; it must fit the job disk.
const MaxProgramBytes = 1 << 20

var jobName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Job is a job directory read in full: its request and, for exec, the program's bytes.
type Job struct {
	Name    string
	Request Request
	Program []byte
}

// ReadJob reads the job directory name in inbox. The directory holds job.json and, for an exec
// job, the program it names, nothing else. Every entry is checked with Lstat before it is opened
// (a directory, a regular file with one link, within its cap), so a symlink, hard link or FIFO is
// refused without being opened; the open then refuses links and must find the same file. The
// agent can still change a file between the checks and the read; what is returned is what was read.
func ReadJob(inbox *os.Root, name string) (Job, error) {
	if !jobName.MatchString(name) {
		return Job{}, errors.New("job name must be lower-case letters, digits and dashes")
	}
	dirInfo, err := inbox.Lstat(name)
	if err != nil || !dirInfo.IsDir() {
		return Job{}, errors.New("job is not a plain directory")
	}
	dir, err := openJobDir(inbox, name, dirInfo)
	if err != nil {
		return Job{}, err
	}
	defer dir.Close() //nolint:errcheck // read-only
	names, err := entries(dir)
	if err != nil {
		return Job{}, err
	}

	data, err := readEntry(dir, RequestFile, MaxRequestBytes)
	if err != nil {
		return Job{}, err
	}
	req, err := ParseRequest(bytes.NewReader(data))
	if err != nil {
		return Job{}, err
	}
	want := []string{RequestFile}
	if req.Kind == KindExec {
		want = append(want, req.Program)
	}
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		return Job{}, errors.New("job directory must hold job.json and, for exec, only the program")
	}
	job := Job{Name: name, Request: req}
	if req.Kind == KindExec {
		if job.Program, err = readEntry(dir, req.Program, MaxProgramBytes); err != nil {
			return Job{}, err
		}
	}
	return job, nil
}

// openJobDir opens name as the directory checked as want. The agent can swap it for something
// else after the Lstat: "name/." makes the open require a directory, so a FIFO fails at once instead
// of blocking (os.Root would otherwise open the last component without O_DIRECTORY), and a symlink
// to another directory, which os.Root follows inside the inbox, fails the SameFile check.
func openJobDir(inbox *os.Root, name string, want fs.FileInfo) (*os.Root, error) {
	dir, err := inbox.OpenRoot(name + "/.")
	if err != nil {
		return nil, errors.New("cannot open the job directory")
	}
	if opened, err := dir.Stat("."); err != nil || !os.SameFile(want, opened) {
		_ = dir.Close()
		return nil, errors.New("job directory changed while it was opened")
	}
	return dir, nil
}

// entries returns at most three names in dir: enough to see more than job.json and a program.
func entries(dir *os.Root) ([]string, error) {
	f, err := dir.Open(".")
	if err != nil {
		return nil, errors.New("cannot list the job directory")
	}
	defer f.Close() //nolint:errcheck // read-only
	names, err := f.Readdirnames(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.New("cannot list the job directory")
	}
	return names, nil
}

// readEntry reads at most limit bytes of the regular file name in dir, checked before and after
// the open; the error names the entry, never its content.
func readEntry(dir *os.Root, name string, limit int64) ([]byte, error) {
	label := "program"
	if name == RequestFile {
		label = RequestFile
	}
	before, err := dir.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("%s: missing", label)
	}
	if err := plainFile(before, limit); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	f, err := dir.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot open", label)
	}
	defer f.Close() //nolint:errcheck // read-only
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("%s: changed while it was opened", label)
	}
	if err := plainFile(after, limit); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: cannot read", label)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: over %d bytes", label, limit)
	}
	return data, nil
}

func plainFile(fi fs.FileInfo, limit int64) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return errors.New("not a regular file")
	case !ok || st.Nlink != 1:
		return errors.New("must have exactly one link")
	case fi.Size() > limit:
		return fmt.Errorf("over %d bytes", limit)
	}
	return nil
}
