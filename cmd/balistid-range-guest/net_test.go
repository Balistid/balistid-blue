package main

import (
	"crypto/ecdh"
	"encoding/base64"
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
	if v, err := reach("tcp", open); err != nil || v != "refused" {
		t.Errorf("closed port: %q, %v", v, err)
	}
	l, err = (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // test listener
	if v, err := reach("tcp", l.Addr().String()); err != nil || v != "open" {
		t.Errorf("open port: %q, %v", v, err)
	}
	if v, err := reach("udp", "127.0.0.1:9"); err != nil || v != "sent" {
		t.Errorf("datagram: %q, %v", v, err)
	}
	if v, err := reach("tcp", "not an address"); err == nil {
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
