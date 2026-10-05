package rangevm

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
)

// The sandbox is an allowlist: any added mount, share or capability must change this test.
func TestSandboxArgvIsExactlyTheAllowlist(t *testing.T) {
	got := sandboxArgv("/img/base.raw", "/cache/run-1", 123, "/usr/bin/true")
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
	plain, job := qemuArgv(false), qemuArgv(true)
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

// The VM argv is exact as well: no device, NIC or option appears without changing this test.
func TestQemuArgv(t *testing.T) {
	argv := qemuArgv(false)
	want := []string{
		"/usr/bin/qemu-system-x86_64",
		"-nodefaults", "-nic", "none", "-display", "none", "-no-reboot",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-enable-kvm", "-machine", "q35", "-cpu", "host", "-m", "2048", "-smp", "2",
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
