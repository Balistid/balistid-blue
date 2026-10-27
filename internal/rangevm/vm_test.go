package rangevm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// The sandbox is an allowlist: any added mount, share or capability must change this test.
func TestSandboxArgvIsExactlyTheAllowlist(t *testing.T) {
	got := sandboxArgv("/img/base.raw", "/cache/run-1", 123, false, "/usr/bin/true")
	want := []string{
		"/usr/bin/prlimit", "--fsize=123", "--core=0", "--",
		"/usr/bin/bwrap",
		"--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
		"--clearenv", "--setenv", "PATH", "/usr/bin",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib", "/lib64",
		"--symlink", "usr/bin", "/bin",
		"--proc", "/proc",
		"--dev", "/dev",
		"--dev-bind", "/dev/kvm", "/dev/kvm",
		"--ro-bind", "/img/base.raw", "/range/base.raw",
		"--ro-bind", "/cache/run-1", "/range/run",
		"--bind", "/cache/run-1/overlay.qcow2", "/range/run/overlay.qcow2",
		"--bind", "/cache/run-1/results.raw", "/range/run/results.raw",
		"--bind", "/cache/run-1/vars.fd", "/range/run/vars.fd",
		"--remount-ro", "/dev",
		"--remount-ro", "/",
		"--", "/usr/bin/true",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("sandbox argv changed:\n got %q\nwant %q", got, want)
	}
}

// The job disk is the only addition a job makes, and it is read-only.
func TestQemuArgvWithAJob(t *testing.T) {
	plain, job := qemuArgv(false, false, "", 0), qemuArgv(true, false, "", 0)
	want := append(slices.Clone(plain[:len(plain)-2]),
		"-drive", "if=none,id=job,format=raw,readonly=on,file=/range/run/job.raw",
		"-device", "virtio-blk-pci,drive=job,serial=balistid-job",
		"-serial", "stdio")
	if !slices.Equal(job, want) {
		t.Fatalf("job argv:\n got %q\nwant %q", job, want)
	}
}

func TestRunRefusesAJobDiskOfTheWrongSize(t *testing.T) {
	for _, n := range []int{0, 1, rangejob.DiskBytes - 1, rangejob.DiskBytes + 1} {
		if _, err := Run(t.Context(), "/nonexistent", t.TempDir(), &bytes.Buffer{}, make([]byte, n)); err == nil || !strings.Contains(err.Error(), "job disk") {
			t.Errorf("job disk of %d bytes: %v", n, err)
		}
	}
}

// Only a run that ended reports a run directory left behind as ErrCleanup, which keeps its Outcome.
func TestRemoveRunDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes a file from a read-only directory")
	}
	runErr := errors.New("vm failed")
	for _, c := range []struct {
		stuck   bool
		runErr  error
		cleanup bool
	}{
		{false, nil, false},
		{false, runErr, false},
		{true, nil, true},
		{true, runErr, false},
	} {
		runDir := filepath.Join(t.TempDir(), "run-1")
		if err := os.MkdirAll(filepath.Join(runDir, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(runDir, "sub", "f"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if c.stuck {
			sub := filepath.Join(runDir, "sub")
			if err := os.Chmod(sub, 0o500); err != nil { //nolint:gosec // a directory made read-only for the test
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(sub, 0o700) }) //nolint:gosec // restored so TempDir can be removed
		}
		err := removeRunDir(runDir, c.runErr)
		if errors.Is(err, ErrCleanup) != c.cleanup || (c.runErr != nil && !errors.Is(err, c.runErr)) || (err == nil) != (!c.stuck && c.runErr == nil) ||
			c.stuck != errors.Is(err, os.ErrPermission) {
			t.Errorf("stuck %v, run error %v: %v", c.stuck, c.runErr, err)
		}
		if _, statErr := os.Stat(runDir); c.stuck == errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("stuck %v: run directory %v", c.stuck, statErr)
		}
	}
}

// The VM argv is exact as well: no device, NIC or option appears without changing this test.
func TestQemuArgv(t *testing.T) {
	argv := qemuArgv(false, false, "", 0)
	want := []string{
		"/usr/bin/qemu-system-x86_64",
		"-nodefaults", "-nic", "none", "-display", "none", "-no-reboot",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-enable-kvm", "-machine", "q35", "-cpu", "host", "-m", "2048", "-smp", "4",
		"-drive", "if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd",
		"-drive", "if=pflash,unit=1,format=raw,file=/range/run/vars.fd",
		"-fw_cfg", "name=opt/org.tianocore/EFIShellSupport,string=no",
		"-drive", "if=none,id=root,format=qcow2,file=/range/run/overlay.qcow2",
		"-device", "virtio-blk-pci,drive=root,bootindex=0",
		"-drive", "if=none,id=results,format=raw,file=/range/run/results.raw",
		"-device", "virtio-blk-pci,drive=results,serial=balistid-results",
		"-serial", "stdio",
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("qemu argv changed:\n got %q\nwant %q", argv, want)
	}
	drives := 0
	for i := 1; i < len(argv); i++ {
		if argv[i-1] != "-drive" {
			continue
		}
		drives++
		opts := strings.Split(argv[i], ",")
		formats := 0
		for _, o := range opts {
			if strings.HasPrefix(o, "format=") {
				formats++
			}
			if strings.HasPrefix(o, "file=") && !strings.HasPrefix(o, "file=/range/run/") && o != "file="+ovmfCode {
				t.Errorf("drive outside the run directory: %s", argv[i])
			}
		}
		if formats != 1 {
			t.Errorf("drive without exactly one format=: %s", argv[i])
		}
		if strings.Contains(argv[i], "file=/range/run/"+results) && !slices.Contains(opts, "format=raw") {
			t.Errorf("results disk not opened as raw: %s", argv[i])
		}
	}
	if drives != 4 {
		t.Errorf("%d drives, want 4", drives)
	}
	if !slices.Contains(overlayArgv(), "-F") || overlayArgv()[slices.Index(overlayArgv(), "-F")+1] != "raw" {
		t.Errorf("overlay does not pin the backing format: %q", overlayArgv())
	}
}

func sh(script string) []string { return []string{"/usr/bin/sh", "-c", script} }

func TestRunCommand(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		timeout time.Duration
		want    string
	}{
		{"clean exit", "printf booted", time.Minute, ""},
		{"output over budget", "head -c 5000 /dev/zero; sleep 30", time.Minute, "output exceeded"},
		{"no exit in time", "sleep 30", 200 * time.Millisecond, "no exit within"},
		{"descendant keeps the pipe", "sleep 30 & exit 0", 200 * time.Millisecond, "no exit within"},
		{"failure exit", "exit 3", time.Minute, "exit status 3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			start := time.Now()
			why := runCommand(context.Background(), sh(c.script), c.timeout, 1000, &out)
			if c.want == "" && why != "" || c.want != "" && !strings.Contains(why, c.want) {
				t.Fatalf("runCommand = %q, want %q", why, c.want)
			}
			if out.Len() > 1000 {
				t.Errorf("kept %d bytes of output, budget 1000", out.Len())
			}
			if time.Since(start) > 10*time.Second {
				t.Errorf("took %s; the process was not stopped", time.Since(start))
			}
		})
	}
}

func TestRunCommandKeepsOutputWithinBudget(t *testing.T) {
	var out bytes.Buffer
	if why := runCommand(context.Background(), sh("printf booted"), time.Minute, 1000, &out); why != "" {
		t.Fatal(why)
	}
	if out.String() != "booted" {
		t.Fatalf("output = %q", out.String())
	}
}

// Only runCommand's own pipe and start failures are the host's.
func TestHostFailureIsOnlyAStartFailure(t *testing.T) {
	for why, want := range map[string]bool{
		"start: fork/exec /usr/bin/qemu-system-x86_64: no such file or directory": true,
		"pipe: too many open files": true,
		"exit: exit status 1":       false,
		"no exit within 5m0s":       false,
		"":                          false,
		"boot 1: start: x":          false,
	} {
		if got := hostFailure(why); got != want {
			t.Errorf("hostFailure(%q) = %v", why, got)
		}
	}
}
