//go:build rangehost

// These tests start the real sandbox and QEMU tools and need bwrap with user namespaces, /dev/kvm
// and qemu-img, which the CI runners do not offer. Run them on the range host:
// go test -tags rangehost ./internal/rangevm/
package rangevm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// probe exits 10 if it reaches the host listener, 11 if it sees $HOME, 12 if a write over the
// file-size limit succeeds, 13 if it can write the sandbox root, 14 /dev, 15 a new file in the
// run directory; 0 otherwise.
const probe = `
if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then exit 10; fi
if [ -e "$2" ]; then exit 11; fi
head -c 8192 /dev/zero > /range/run/overlay.qcow2 2>/dev/null && exit 12
: > /fill 2>/dev/null && exit 13
: > /dev/fill 2>/dev/null && exit 14
: > /range/run/fill 2>/dev/null && exit 15
exit 0`

func TestSandboxIsolatesHost(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "base.raw")
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	for _, name := range []string{overlay, results, firmVars} {
		if err := os.WriteFile(filepath.Join(runDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prog := []string{"/usr/bin/bash", "-c", probe, "probe", port, home}

	// Positive control: outside the sandbox the same probe reaches the listener.
	if why := runCommand(context.Background(), prog, time.Minute, 1000, io.Discard); !strings.Contains(why, "exit status 10") {
		t.Fatalf("probe outside the sandbox = %q, want exit status 10", why)
	}
	if why := runCommand(context.Background(), sandboxArgv(base, runDir, 4096, prog...), time.Minute, 1000, io.Discard); why != "" {
		t.Fatalf("probe inside the sandbox: %s (see the exit codes on probe)", why)
	}
	if st, err := os.Stat(filepath.Join(runDir, overlay)); err != nil || st.Size() > 4096 {
		t.Fatalf("write over the limit: %v, %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(runDir, "fill")); err == nil {
		t.Fatal("the sandbox created a file in the run directory")
	}
}

// ADR 0009: a planted qcow2 header with a backing file to a host file is never opened. The
// results drive is opened with format=raw, so QEMU's block layer reads the header as data; with
// format probing the same bytes name the host file (positive control).
func TestPlantedQcow2HeaderIsData(t *testing.T) {
	dir := t.TempDir()
	canary := filepath.Join(dir, "host-secret")
	if err := os.WriteFile(canary, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, results)
	if out, err := exec.CommandContext(t.Context(), qemuImgPath, "create", "-q", "-f", "qcow2", "-b", canary, "-F", "raw", planted).CombinedOutput(); err != nil { //nolint:gosec // test temp paths
		t.Fatalf("plant: %v %s", err, out)
	}
	info := func(args ...string) map[string]any {
		out, err := exec.CommandContext(t.Context(), qemuImgPath, append([]string{"info", "--output=json", "-U"}, args...)...).Output() //nolint:gosec // test temp paths
		if err != nil {
			t.Fatalf("qemu-img info %v: %v", args, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if probed := info(planted); probed["backing-filename"] != canary {
		t.Fatalf("control: probing should follow the planted backing file, got %v", probed["backing-filename"])
	}
	if pinned := info("-f", "raw", planted); pinned["format"] != "raw" || pinned["backing-filename"] != nil {
		t.Fatalf("format=raw followed the planted header: %v", pinned)
	}
}
