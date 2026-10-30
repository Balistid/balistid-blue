package main

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A reach child tells an open port from a refused one and a sent datagram; anything it cannot name fails it.
func TestReach(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if v, err := reach(t.Context(), "tcp", open); err != nil || v != "refused" {
		t.Errorf("closed port: %q, %v", v, err)
	}
	l, err = (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // test listener
	if v, err := reach(t.Context(), "tcp", l.Addr().String()); err != nil || v != "open" {
		t.Errorf("open port: %q, %v", v, err)
	}
	if v, err := reach(t.Context(), "udp", "127.0.0.1:9"); err != nil || v != "sent" {
		t.Errorf("datagram: %q, %v", v, err)
	}
	if v, err := reach(t.Context(), "tcp", "not an address"); err == nil {
		t.Errorf("bad address: %q", v)
	}
	if err := reachMain([]string{"icmp", "127.0.0.1:9"}); err == nil {
		t.Error("icmp accepted")
	}
}

// The ledger's namespace is read from /proc/net/dev's table: names only, sorted, headers skipped.
func TestNetDevNames(t *testing.T) {
	dev := "Inter-|   Receive                            |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes\n" +
		"balistid0:       0       0    0    0    0     0          0         0        0\n" +
		"    lo:    1234      10    0    0    0     0          0         0     1234\n"
	if got := netDevNames(dev); got != "balistid0,lo" {
		t.Errorf("names %q", got)
	}
	if got := netDevNames("Inter-|\n face |\n"); got != "" {
		t.Errorf("empty table: %q", got)
	}
}

// The range's keys are what each end needs: the host's private key and net.env for balistid-net, the Pi's
// private key and the host's public one for its namespace; private files 0600, public ones 0644.
func TestNetKey(t *testing.T) {
	dir, rangeDir := t.TempDir(), filepath.Join(t.TempDir(), "range")
	if err := netKey(dir, rangeDir); err != nil {
		t.Fatal(err)
	}
	read := func(path string, mode os.FileMode) string {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v, %v", path, info, err)
		}
		b, err := os.ReadFile(path) //nolint:gosec // the test's own temporary directory
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSuffix(string(b), "\n")
	}
	public := func(private string) string {
		raw, err := base64.StdEncoding.DecodeString(private)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	}
	host, pi := read(filepath.Join(dir, "wg-key"), 0o600), read(filepath.Join(rangeDir, "pi-wg-key"), 0o600)
	if got, want := read(filepath.Join(dir, "net.env"), 0o644), "BALISTID_PI_ENDPOINT=192.0.2.2\nBALISTID_PI_KEY="+public(pi); got != want {
		t.Errorf("net.env %q, want %q", got, want)
	}
	if got, want := read(filepath.Join(rangeDir, "pi-net.env"), 0o644), "BALISTID_HOST_KEY="+public(host); got != want {
		t.Errorf("pi-net.env %q, want %q", got, want)
	}
	if host == pi {
		t.Error("one key for both ends")
	}
	if err := netKey(dir, rangeDir); err == nil {
		t.Error("keys made twice")
	}
}

// The refusals' log check needs each reason with the table's version and decision, the to-pi one with the
// job's uid, and ends at once when the log cannot be read: a failed read is never "missing".
func TestLoggedIn(t *testing.T) {
	const uid = " UID=1001 "
	full := "nf: balistid-net 1 drop to-pi-not-relay: IN= OUT=balistid0 SYN URGP=0 UID=1001 GID=1001 \n" +
		"balistid-net 1 drop to-endpoint-not-wireguard: OUT=balistid-lan\n" +
		"balistid-net 1 drop host-address-off-tunnel: IN=lo\nbalistid-net 1 drop from-tunnel-not-relay-port: IN=balistid0\n"
	read := func(log string, err error) func(context.Context) (string, error) {
		return func(context.Context) (string, error) { return log, err }
	}
	reads := 0
	failing := func(context.Context) (string, error) { reads++; return "", errors.New("journal gone") }
	for name, c := range map[string]struct {
		read func(context.Context) (string, error)
		want string
	}{
		"every reason":     {read(full, nil), "yes"},
		"another uid":      {read(strings.Replace(full, "UID=1001", "UID=0", 1), nil), "missing to-pi-not-relay"},
		"no decision word": {read(strings.ReplaceAll(full, " drop ", " "), nil), "missing to-pi-not-relay+to-endpoint-not-wireguard+host-address-off-tunnel+from-tunnel-not-relay-port"},
		"unreadable":       {failing, "error: journal gone"},
	} {
		ctx, cancel := context.WithCancel(t.Context())
		if name != "every reason" && name != "unreadable" {
			cancel() // no waiting for records that will not come
		}
		if got := loggedIn(ctx, c.read, uid); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
		cancel()
	}
	if reads != 1 {
		t.Errorf("a failed read was retried: %d reads", reads)
	}
}
