package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The range's stand-in for the Pi (ADR 0032, point 4): a network namespace behind a veth, its LAN address in
// TEST-NET-1, reached through the product's tunnel, whose addresses and port deploy/net fixes.
const (
	netKeyArg  = "net-key"
	reachArg   = "reach"
	piTunnel   = "10.207.57.2"
	hostTunnel = "10.207.57.1"
	relayPort  = "7381"
	// closedPort is a host port nothing listens on; piNS runs a reach child in the Pi's namespace.
	closedPort  = "7399"
	piNS        = "the Pi's namespace"
	piLAN       = "192.0.2.2"
	wgPort      = "51820"
	netEnv      = "/etc/balistid/net.env"
	piNetEnv    = "/etc/balistid-range/pi-net.env"
	reachWait   = 2 * time.Second
	relayUser   = "balistid-relay"
	jobUser     = "balistid-job"
	ledgerUnit  = "balistid-ledger.service"
	witnessPort = "7380"
)

// netKey writes both ends' WireGuard keys before balistid-net starts (range unit balistid-range-net-key): the
// host's as root's 0600 file balistid-net loads as a credential and net.env as the install would write it, the
// Pi's as root's 0600 file and the host's public key for the namespace's unit.
func netKey(dir, rangeDir string) error {
	host, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("net key: %w", err)
	}
	pi, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("net key: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString
	for _, d := range []string{dir, rangeDir} {
		if err := mkdirOpen(d); err != nil {
			return fmt.Errorf("net key: %w", err)
		}
	}
	for _, f := range []struct {
		path, body string
		mode       os.FileMode
	}{
		{filepath.Join(dir, "wg-key"), b64(host.Bytes()), 0o600},
		{filepath.Join(dir, "net.env"), "BALISTID_PI_ENDPOINT=" + piLAN + "\nBALISTID_PI_KEY=" + b64(pi.PublicKey().Bytes()), 0o644},
		{filepath.Join(rangeDir, "pi-wg-key"), b64(pi.Bytes()), 0o600},
		{filepath.Join(rangeDir, "pi-net.env"), "BALISTID_HOST_KEY=" + b64(host.PublicKey().Bytes()), 0o644},
	} {
		if err := writeNew(f.path, f.body+"\n", f.mode); err != nil {
			return fmt.Errorf("net key: %w", err)
		}
	}
	return nil
}

func netKeyMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + netKeyArg + " (no arguments): " + strings.Join(args, " "))
	}
	return netKey(filepath.Dir(netEnv), filepath.Dir(piNetEnv))
}

// piReach is what each uid's packets to the Pi met, and the Pi's to the host (T21, ADR 0032): the relay's TCP
// reaches its witness, while TCP from root and the job's uid is dropped (a dropped SYN waits out the timeout)
// and their UDP, to the Pi's tunnel and to its LAN endpoint without WireGuard's mark, is refused at once. The
// job's uid cannot fetch the relay's bundles, and the Pi reaches no host port but the relay's: without the
// input rule a closed port would answer refused.
func piReach(ctx context.Context) string {
	var parts []string
	for _, p := range []struct{ name, account, proto, addr string }{
		{"relay_tcp", relayUser, "tcp", net.JoinHostPort(piTunnel, witnessPort)},
		{"job_tcp", jobUser, "tcp", net.JoinHostPort(piTunnel, witnessPort)},
		{"job_udp", jobUser, "udp", net.JoinHostPort(piTunnel, witnessPort)},
		{"job_endpoint", jobUser, "udp", net.JoinHostPort(piLAN, wgPort)},
		{"root_tcp", "root", "tcp", net.JoinHostPort(piTunnel, witnessPort)},
		{"job_bundles", jobUser, "tcp", net.JoinHostPort(hostTunnel, relayPort)},
		{"pi_host_port", piNS, "tcp", net.JoinHostPort(hostTunnel, closedPort)},
	} {
		parts = append(parts, p.name+"="+reachAs(ctx, p.account, p.proto, p.addr))
	}
	// The output rule drops the host's answers to the Pi too, so the input rules show only in their counters.
	parts = append(parts, "tunnel_refused="+refusals(ctx, `iifname "balistid0" counter`),
		"host_refused="+refusals(ctx, `ip daddr 10.207.57.1 counter`))
	return strings.Join(parts, ",")
}

// refusals is "counted" when the input chain's rule starting with rule has refused a packet, "none" when not.
func refusals(ctx context.Context, rule string) string {
	chain := output(ctx, "/usr/bin/nft", "list", "chain", "inet", "balistid", "input")
	for _, line := range strings.Split(chain, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), rule+" packets "); ok {
			n, _, _ := strings.Cut(rest, " ")
			switch v, err := strconv.ParseUint(n, 10, 64); {
			case err != nil:
				return "error: counter not a number"
			case v == 0:
				return "none"
			}
			return "counted"
		}
	}
	return "error: no rule " + rule
}

// reachAs runs a reach child as account's uid and gid, with no supplementary group, or as root in the Pi's
// namespace for piNS, and returns its verdict.
func reachAs(ctx context.Context, account, proto, addr string) string {
	self, err := os.Executable()
	if err != nil {
		return "error: " + err.Error()
	}
	ctx, cancel := context.WithTimeout(ctx, reachWait+5*time.Second)
	defer cancel()
	if account == piNS {
		out, err := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/run/netns/balistid-pi", self, reachArg, proto, addr).Output() //nolint:gosec // our own binary, fixed argv
		if err != nil {
			return "error: " + err.Error()
		}
		return strings.TrimSpace(string(out))
	}
	cred, err := credential(account)
	if err != nil {
		return "error: " + err.Error()
	}
	child := exec.CommandContext(ctx, self, reachArg, proto, addr) //nolint:gosec // our own binary, fixed argv
	child.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	out, err := child.Output()
	if err != nil {
		return "error: " + err.Error()
	}
	return strings.TrimSpace(string(out))
}

func credential(account string) (*syscall.Credential, error) {
	u, err := user.Lookup(account)
	if err != nil {
		return nil, fmt.Errorf("user %s: %w", account, err)
	}
	uid, uerr := strconv.ParseUint(u.Uid, 10, 32)
	gid, gerr := strconv.ParseUint(u.Gid, 10, 32)
	if uerr != nil || gerr != nil {
		return nil, fmt.Errorf("user %s: ids %q %q", account, u.Uid, u.Gid)
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}, nil
}

// reachMain is a reach child: one TCP connect or one UDP datagram to addr, printed as open, sent, timeout,
// EPERM or refused; anything else is an error the self-test fails on.
func reachMain(args []string) error {
	if len(args) != 2 || (args[0] != "tcp" && args[0] != "udp") {
		return errors.New("usage: " + reachArg + " tcp|udp addr:port")
	}
	verdict, err := reach(context.Background(), args[0], args[1])
	if err != nil {
		return err
	}
	_, err = fmt.Println(verdict)
	return err //nolint:wrapcheck // the child's last word
}

func reach(ctx context.Context, proto, addr string) (string, error) {
	verdict := "open"
	ctx, cancel := context.WithTimeout(ctx, reachWait)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, proto, addr)
	if err == nil && proto == "udp" {
		verdict = "sent"
		_, err = c.Write([]byte("balistid-range reach\n"))
	}
	if c != nil {
		_ = c.Close()
	}
	var ne net.Error
	switch {
	case err == nil:
	case errors.Is(err, syscall.EPERM):
		verdict = "EPERM"
	case errors.Is(err, syscall.ECONNREFUSED):
		verdict = "refused"
	case errors.As(err, &ne) && ne.Timeout():
		verdict = "timeout"
	default:
		return "", fmt.Errorf("%s %s: %w", proto, addr, err)
	}
	return verdict, nil
}

// ledgerNet lists the interfaces in the ledger's network namespace, as its process sees them: PrivateNetwork
// leaves only loopback (ADR 0007), whatever a drop-in changed.
func ledgerNet(ctx context.Context) string {
	pid := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "--property=MainPID", "--value", ledgerUnit))
	if n, err := strconv.Atoi(pid); err != nil || n <= 0 {
		return "no ledger process"
	}
	dev, err := os.ReadFile("/proc/" + pid + "/net/dev") //nolint:gosec // a pid systemd reported, a fixed file
	if err != nil {
		return "error: " + err.Error()
	}
	return netDevNames(string(dev))
}

// netDevNames are the interface names of a /proc/net/dev table, sorted, joined by commas.
func netDevNames(dev string) string {
	var names []string
	for _, line := range strings.Split(dev, "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && !strings.Contains(name, "|") {
			names = append(names, strings.TrimSpace(name))
		}
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// netDiag is the state of the tunnel's units and balistid-net's last journal lines, bounded, for a fact that
// failed through the tunnel: the range keeps no guest journal.
func netDiag(ctx context.Context) string {
	state := output(ctx, "/usr/bin/systemctl", "show", "--value", "-p", "Id,ActiveState,Result", "balistid-net.service",
		"balistid-range-pi-net.service", "balistid-range-witness.service")
	journal := output(ctx, "/usr/bin/journalctl", "-u", "balistid-net.service", "-u", "balistid-range-pi-net.service",
		"-o", "cat", "--no-pager", "-n", "6")
	d := strings.Join(strings.Fields("net: "+state+" | "+journal), " ")
	return d[:min(len(d), 1500)]
}
