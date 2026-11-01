package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

const (
	auditSetArg = "audit-set"
	// auditSetWait bounds the child: fifteen requests of at most a second each, and its start.
	auditSetWait = 30 * time.Second
	// auditFeatureVersion and loginuidImmutable are linux/audit.h's AUDIT_FEATURE_VERSION and the mask of
	// AUDIT_FEATURE_LOGINUID_IMMUTABLE, which x/sys does not name.
	auditFeatureVersion = 1
	loginuidImmutable   = 1 << 1
	// auditRuleDataBytes is struct audit_rule_data without its strings: the kernel checks that size before the lock.
	auditRuleDataBytes = 1040
)

// runAuditSet runs the audit-set child as balistid-auditstat with CAP_AUDIT_CONTROL as its one ambient
// capability, as auditstat's unit does, between two reads of the kernel's enabled flag, and reports what the
// kernel answered each of its requests (ADR 0038, Consequences).
func runAuditSet(ctx context.Context, r *report) error {
	enabled := func() string {
		return valueOr(rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))["enabled"])
	}
	before := enabled()
	cred, err := credential("balistid-auditstat")
	if err != nil {
		return r.fail(err.Error())
	}
	self, err := os.Executable()
	if err != nil {
		return r.fail(err.Error())
	}
	cctx, cancel := context.WithTimeout(ctx, auditSetWait)
	defer cancel()
	child := exec.CommandContext(cctx, self, auditSetArg) //nolint:gosec // our own binary, fixed argv
	child.SysProcAttr = &syscall.SysProcAttr{Credential: cred, AmbientCaps: []uintptr{unix.CAP_AUDIT_CONTROL}}
	out, err := child.Output()
	if err != nil {
		return r.fail("audit-set child: " + err.Error())
	}
	lines := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		lines[k] = v
	}
	r.add(rangevm.FactAuditSetCaps, lines["caps"])
	r.add(rangevm.FactAuditSetUser, lines["user"])
	r.add(rangevm.FactAuditSet, lines["ops"])
	r.add(rangevm.FactAuditSetEnabled, before+","+enabled())
	return r.send(r.facts)
}

// auditSetMain is the audit-set child: its own capability sets and user, then one line of what the kernel
// answered each of rangevm.AuditSetOps.
func auditSetMain(args []string) error {
	if len(args) != 0 {
		return errors.New("audit-set takes no arguments")
	}
	prm, eff, amb := rangeguest.Caps(readTrim("/proc/self/status"))
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd) //nolint:errcheck // a probe's socket, nothing to lose
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fmt.Errorf("receive timeout: %w", err)
	}
	asks := auditAsks(&auditAsker{fd: fd})
	results := make([]string, 0, len(rangevm.AuditSetOps))
	for _, op := range rangevm.AuditSetOps {
		results = append(results, op+"="+asks[op]())
	}
	fmt.Printf("caps=%s,%s,%s\nuser=%s\nops=%s\n", prm, eff, amb,
		rangeguest.UserName(readTrim("/etc/passwd"), strconv.Itoa(os.Getuid())), strings.Join(results, ","))
	return nil
}

// auditAsks are the requests of rangevm.AuditSetOps through a, by name: each gate with a valid value, so that
// only the lock can refuse it, and the rules and equiv with the least payload the kernel parses before the lock.
func auditAsks(a *auditAsker) map[string]func() string {
	status := func(mask uint32, field int, value uint32) []byte {
		b := make([]byte, 11*4) // struct audit_status
		binary.NativeEndian.PutUint32(b, mask)
		binary.NativeEndian.PutUint32(b[4*field:], value)
		return b
	}
	pid := uint32(os.Getpid()) //nolint:gosec // a pid fits
	return map[string]func() string{
		"get":         func() string { return a.ask(unix.AUDIT_GET, nil) },
		"enabled":     func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_ENABLED, 1, 1)) },
		"failure":     func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_FAILURE, 2, 1)) },
		"rate":        func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_RATE_LIMIT, 4, 100)) },
		"backlog":     func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_BACKLOG_LIMIT, 5, 8192)) },
		"wait":        func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_BACKLOG_WAIT_TIME, 9, 1000)) },
		"pid":         func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_PID, 3, pid)) },
		"lost":        func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_LOST, 6, 0)) },
		"wait_actual": func() string { return a.ask(unix.AUDIT_SET, status(unix.AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL, 10, 0)) },
		"rule_add":    func() string { return a.ask(unix.AUDIT_ADD_RULE, make([]byte, auditRuleDataBytes)) },
		"rule_del":    func() string { return a.ask(unix.AUDIT_DEL_RULE, make([]byte, auditRuleDataBytes)) },
		"trim":        func() string { return a.ask(unix.AUDIT_TRIM, nil) },
		"equiv":       func() string { return a.ask(unix.AUDIT_MAKE_EQUIV, []byte{1, 0, 0, 0, 1, 0, 0, 0, 'a', 'b'}) },
		"feature":     a.toggleLoginuid,
		"user":        func() string { return a.ask(unix.AUDIT_USER, []byte("balistid range audit-set\x00")) },
	}
}

// auditAsker sends audit requests with NLM_F_ACK and reads the kernel's answer to each by its seq.
type auditAsker struct {
	fd  int
	seq uint32
}

// ask is the kernel's answer to one request: ok for an acknowledgement of zero or more, else the errno's
// name, or timeout when no acknowledgement came within the socket's second.
func (a *auditAsker) ask(typ uint16, payload []byte) string {
	res, _ := a.exchange(typ, payload)
	return res
}

// exchange sends a request and returns its answer, and the first other message of its seq, the reply.
func (a *auditAsker) exchange(typ uint16, payload []byte) (string, []byte) {
	a.seq++
	msg := make([]byte, unix.SizeofNlMsghdr+len(payload))
	binary.NativeEndian.PutUint32(msg[0:], uint32(len(msg))) //nolint:gosec // at most a rule's size
	binary.NativeEndian.PutUint16(msg[4:], typ)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(msg[8:], a.seq)
	copy(msg[unix.SizeofNlMsghdr:], payload)
	if err := unix.Sendto(a.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return errnoResult(err), nil
	}
	var reply []byte
	buf := make([]byte, 8192)
	for range 16 {
		n, _, err := unix.Recvfrom(a.fd, buf, 0)
		if err != nil {
			return "timeout", reply
		}
		if n < unix.SizeofNlMsghdr+4 || binary.NativeEndian.Uint32(buf[8:]) != a.seq {
			continue
		}
		if binary.NativeEndian.Uint16(buf[4:]) != unix.NLMSG_ERROR {
			if reply == nil {
				reply = append([]byte(nil), buf[unix.SizeofNlMsghdr:n]...)
			}
			continue
		}
		code := int32(binary.NativeEndian.Uint32(buf[unix.SizeofNlMsghdr:])) //nolint:gosec // the kernel's signed errno
		if code >= 0 {
			return "ok", reply
		}
		return errnoResult(syscall.Errno(-code)), reply
	}
	return "timeout", reply
}

// toggleLoginuid reads the audit features and asks to flip loginuid_immutable, then flips it back: the
// first answer is whether -e 2 still lets the capability change a feature without its own lock.
func (a *auditAsker) toggleLoginuid() string {
	res, reply := a.exchange(unix.AUDIT_GET_FEATURE, nil)
	if res != "ok" {
		return res
	}
	if len(reply) < 16 {
		return "ENODATA"
	}
	features := binary.NativeEndian.Uint32(reply[8:]) ^ loginuidImmutable
	set := func(f uint32) string {
		b := make([]byte, 16)
		binary.NativeEndian.PutUint32(b[0:], auditFeatureVersion)
		binary.NativeEndian.PutUint32(b[4:], loginuidImmutable)
		binary.NativeEndian.PutUint32(b[8:], f)
		return a.ask(unix.AUDIT_SET_FEATURE, b)
	}
	res = set(features)
	if res == "ok" {
		set(features ^ loginuidImmutable)
	}
	return res
}

func errnoResult(err error) string {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return "EIO"
	}
	if name := unix.ErrnoName(e); name != "" {
		return name
	}
	return "E" + strconv.Itoa(int(e))
}
