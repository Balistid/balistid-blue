package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// A record trial's limits (ADR 0023, point 3): the collector's socket, the stack limits its execs run
// under (ARG_MAX is a quarter of it), how long the injector may take to connect and to finish, and the
// wait for the stats record after the malformed lines (the collector writes one every 60 s).
const (
	collectorSocket = "/run/balistid/collector.sock"
	defaultStack    = 8 << 20
	largeStack      = 32 << 20
	connectWait     = 5 * time.Second
	injectWait      = 30 * time.Second
	statsWait       = 70 * time.Second
	injectArg       = "inject"
	longMalformed   = 3 << 20
)

// argvCase is one exec of a record trial: n arguments of size bytes each under stack.
type argvCase struct {
	fact     string
	n, size  int
	stack    uint64
	minBytes uint64 // a truncated record's original length at least
}

var argvCases = []argvCase{
	{rangevm.FactRecord131K, 1024, 128, defaultStack, 0},      // 131 072 B, as xargs fills a command line
	{rangevm.FactRecord2M, 16, 125000, defaultStack, 0},       // 2 000 000 B under the default 8 MiB stack
	{rangevm.FactRecord6M, 48, 125000, largeStack, 6_000_000}, // over the record limit, so stored truncated
}

// args are the arguments of case c: each starts with the token, the case and its index, so no two
// are alike and each is found in a stored record as a JSON string without escapes.
func (c argvCase) args(token string) []string {
	out := make([]string, c.n)
	for i := range out {
		a := fmt.Sprintf("%s-%s-%04d-", token, strings.ReplaceAll(c.fact, "_", "-"), i)
		out[i] = a + strings.Repeat(string(rune('a'+i%26)), c.size-len(a))
	}
	return out
}

// malformedLines are what the injector sends: text, JSON without an ID, and a line over the record
// limit, each with its marker near its start, where a truncated record keeps it.
func malformedLines(token string) []string {
	m := malformedMarkers(token)
	return []string{m[0] + " not json", `{"note":"` + m[1] + `"}`, m[2] + strings.Repeat("x", longMalformed)}
}

func malformedMarkers(token string) []string {
	return []string{token + "-malformed-text", token + "-malformed-json", token + "-malformed-long"}
}

// runRecord execs the three argv cases, has a child with Laurel's uid send the malformed lines while
// Laurel's connection is ended by SIGHUP, waits for the next stats record and reports what the store
// holds (ADR 0023, point 3).
func runRecord(ctx context.Context, r *report) error {
	token, err := token("balistid-record")
	if err != nil {
		return r.fail(err.Error())
	}
	for _, c := range argvCases {
		if err := execArgv(ctx, c, token); err != nil {
			return r.fail(err.Error())
		}
	}
	if err := inject(ctx, token); err != nil {
		return r.fail(err.Error())
	}
	time.Sleep(statsWait)
	scan := newRecordScan(token)
	if err := readStore(ctx, scan.add, nil); err != nil {
		return r.fail("store: " + err.Error())
	}
	scan.report(r)
	return r.send(r.facts)
}

// execArgv execs /usr/bin/true with case c's arguments and no environment under its stack limit.
func execArgv(ctx context.Context, c argvCase, token string) error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_STACK, &lim); err != nil {
		return fmt.Errorf("stack limit: %w", err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_STACK, &syscall.Rlimit{Cur: c.stack, Max: max(lim.Max, c.stack)}); err != nil {
		return fmt.Errorf("stack limit: %w", err)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/true", c.args(token)...) //nolint:gosec // a fixed program, arguments from the trial's own token
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec of %s: %w", c.fact, err)
	}
	return nil
}

// laurelAccount is the uid and gid of _laurel.
func laurelAccount() (uid, gid uint32, err error) {
	u, err := user.Lookup("_laurel")
	if err != nil {
		return 0, 0, fmt.Errorf("_laurel: %w", err)
	}
	id, errU := strconv.ParseUint(u.Uid, 10, 32)
	g, errG := strconv.ParseUint(u.Gid, 10, 32)
	if errU != nil || errG != nil {
		return 0, 0, errors.New("_laurel: uid or gid not a number")
	}
	return uint32(id), uint32(g), nil
}

// inject starts a child with Laurel's uid that connects to the collector, waits until it is connected,
// then sends Laurel SIGHUP: Laurel's re-exec ends its connection, so the collector reads the child's
// before Laurel's next one (it reads one connection at a time to EOF), and the child's lines arrive while
// the collector runs, counted in its next stats record.
func inject(ctx context.Context, token string) error {
	uid, gid, err := laurelAccount()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("injector: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, injectWait)
	defer cancel()
	child := exec.CommandContext(ctx, self, injectArg, token) //nolint:gosec // our own binary
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	out, err := child.StdoutPipe()
	if err != nil {
		return fmt.Errorf("injector: %w", err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return fmt.Errorf("injector: %w", err)
	}
	connected := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(out).ReadString('\n')
		if err == nil && line != "connected\n" {
			err = fmt.Errorf("said %q", line)
		}
		connected <- err
		_, _ = io.Copy(io.Discard, out)
	}()
	select {
	case err = <-connected:
	case <-time.After(connectWait):
		err = errors.New("not connected in time")
	}
	if err == nil {
		err = hupLaurel()
	}
	if err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		return fmt.Errorf("injector: %w", err)
	}
	if err := child.Wait(); err != nil {
		return fmt.Errorf("injector: %w", err)
	}
	return nil
}

func hupLaurel() error {
	pid, err := strconv.Atoi(laurelPID())
	if err != nil {
		return errors.New("laurel is not running under auditd")
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("SIGHUP Laurel: %w", err)
	}
	return nil
}

// injectMain is the injector's process: it connects to the collector's socket, says so, and sends the
// malformed lines of token.
func injectMain(args []string) error {
	if len(args) != 1 {
		return errors.New("want the token")
	}
	c, err := (&net.Dialer{Timeout: connectWait}).DialContext(context.Background(), "unix", collectorSocket)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer c.Close() //nolint:errcheck // the lines are written or the write fails
	if _, err := os.Stdout.WriteString("connected\n"); err != nil {
		return fmt.Errorf("say connected: %w", err)
	}
	for _, l := range malformedLines(args[0]) {
		if _, err := io.WriteString(c, l+"\n"); err != nil {
			return fmt.Errorf("send: %w", err)
		}
	}
	return nil
}

// recordScan is what a record trial finds in the store: per argv case how its record was stored, the
// malformed lines found, and per record whether it is truncated or malformed, up to the last stats
// record before the barrier.
type recordScan struct {
	token     string
	cases     map[string]string
	ours      uint64 // the highest seq of a record of this trial
	malformed map[string]bool
	records   []scanned
	stats     scanned
	statsSeen bool
	truncated uint64 // of the stats record
	malCount  uint64
}

type scanned struct {
	seq                  uint64
	truncated, malformed bool
}

func newRecordScan(token string) *recordScan {
	return &recordScan{token: token, cases: map[string]string{}, malformed: map[string]bool{}}
}

func (s *recordScan) add(x rawrecord.Record) error {
	switch x.Provider {
	case store.SensorProvider:
		malformed := x.ProviderSeq == 0
		s.records = append(s.records, scanned{seq: x.Seq, truncated: x.Truncated(), malformed: malformed})
		if !bytes.Contains(x.Data, []byte(s.token)) {
			return nil
		}
		s.ours = max(s.ours, x.Seq)
		for _, m := range malformedMarkers(s.token) {
			if malformed && bytes.Contains(x.Data, []byte(m)) {
				s.malformed[m] = true
			}
		}
		for _, c := range argvCases {
			if a := c.args(s.token); bytes.Contains(x.Data, []byte(`"`+a[0]+`"`)) {
				s.cases[c.fact] = s.argvStored(c, a, x)
			}
		}
	case store.HealthProvider:
		var rec struct {
			Kind      string  `json:"kind"`
			Truncated *uint64 `json:"truncated"`
			Malformed *uint64 `json:"malformed"`
		}
		if json.Unmarshal(x.Data, &rec) == nil && rec.Kind == "stats" && rec.Truncated != nil && rec.Malformed != nil {
			s.stats, s.statsSeen = scanned{seq: x.Seq}, true
			s.truncated, s.malCount = *rec.Truncated, *rec.Malformed
		}
	}
	return nil
}

// argvStored says how the record x of case c with arguments a was stored: a second record of the case
// is "twice", one within the limit "whole" when it holds every argument, one over it "truncated" when
// cut with its original length.
func (s *recordScan) argvStored(c argvCase, a []string, x rawrecord.Record) string {
	switch {
	case s.cases[c.fact] != "":
		return "twice"
	case x.Truncated() && x.OrigLen >= c.minBytes && c.minBytes > 0:
		return rangevm.RecordTruncated
	case x.Truncated():
		return "truncated within the limit"
	}
	for _, arg := range a {
		if !bytes.Contains(x.Data, []byte(`"`+arg+`"`)) {
			return "cut"
		}
	}
	return rangevm.RecordWhole
}

func (s *recordScan) report(r *report) {
	var truncated, malformed uint64
	for _, x := range s.records {
		if s.statsSeen && x.seq < s.stats.seq {
			truncated += b2u(x.truncated)
			malformed += b2u(x.malformed)
		}
	}
	for _, c := range argvCases {
		r.add(c.fact, valueOr(s.cases[c.fact]))
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactMalformedStored, u(uint64(len(s.malformed))))
	r.add(rangevm.FactStatsAfter, yesNo(s.statsSeen && s.stats.seq > s.ours))
	r.add(rangevm.FactStatsTruncated, u(s.truncated))
	r.add(rangevm.FactStoredTruncated, u(truncated))
	r.add(rangevm.FactStatsMalformed, u(s.malCount))
	r.add(rangevm.FactStoredMalformed, u(malformed))
}

func b2u(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
