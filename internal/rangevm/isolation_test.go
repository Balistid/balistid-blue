//go:build rangehost

// These tests start the real sandbox and need bwrap with user namespaces and /dev/kvm, which the
// CI runners do not offer. Run them on the range host: go test -tags rangehost ./internal/rangevm/
package rangevm

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// probe exits 10 if it reaches the host listener, 11 if it sees $HOME, 12 if a write over the
// file-size limit succeeds; 0 otherwise.
const probe = `
if (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null; then exit 10; fi
if [ -e "$2" ]; then exit 11; fi
head -c 8192 /dev/zero > /range/run/big 2>/dev/null && exit 12
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
	prog := []string{"/usr/bin/bash", "-c", probe, "probe", port, home}

	// Positive control: outside the sandbox the same probe reaches the listener and sees $HOME.
	if why := runCommand(context.Background(), prog, time.Minute, 1000, io.Discard); !strings.Contains(why, "exit status 10") {
		t.Fatalf("probe outside the sandbox = %q, want exit status 10", why)
	}
	if why := runCommand(context.Background(), sandboxArgv(base, runDir, 4096, prog...), time.Minute, 1000, io.Discard); why != "" {
		t.Fatalf("probe inside the sandbox: %s (10 listener reached, 11 $HOME visible, 12 size limit not enforced)", why)
	}
	if st, err := os.Stat(filepath.Join(runDir, "big")); err != nil || st.Size() > 4096 {
		t.Fatalf("write over the limit: %v, %v", st, err)
	}
}
