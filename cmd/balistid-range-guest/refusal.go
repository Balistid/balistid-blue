package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

// A refusal trial's flooders (ADR 0023, point 4): root, whom the socket's mode does not stop, and
// nobody in _laurel's group, whom it lets connect; the collector must refuse both by uid. drainWait is
// how long the acceptor gets for connections still in the backlog before the store is read.
const (
	floodArg     = "flood"
	nobodyUID    = 65534
	drainWait    = 2 * time.Second
	floodTimeout = time.Minute // past the flood's own seconds
)

// floodKinds are the health records a flood may leave besides its summaries: stats, health state and
// lag come at their own pace; anything else during the flood grew because of it.
var floodKinds = map[string]bool{"refused": true, "stats": true, "health": true, "lag": true}

// runRefusal floods the collector's socket from root and from nobody in _laurel's group at the trial's
// rate, then reports how the collector's refusal summaries count them.
func runRefusal(ctx context.Context, tr rangejob.Trial, r *report) error {
	_, gid, err := laurelAccount()
	if err != nil {
		return r.fail(err.Error())
	}
	creds := []*syscall.Credential{{Uid: 0, Gid: 0, Groups: []uint32{}}, {Uid: nobodyUID, Gid: gid, Groups: []uint32{}}}
	start := time.Now()
	type result struct {
		ok  uint64
		err error
	}
	results := make(chan result, len(creds))
	for _, c := range creds {
		go func() {
			ok, err := flood(ctx, c, tr.Load.Rate, tr.Load.Seconds)
			results <- result{ok, err}
		}()
	}
	var ok []uint64
	var errs []error
	for range creds {
		res := <-results
		ok, errs = append(ok, res.ok), append(errs, res.err)
	}
	if err := errors.Join(errs...); err != nil {
		return r.fail("flood: " + err.Error())
	}
	end := time.Now()
	time.Sleep(drainWait)
	scan := refusalScan{from: start.UnixNano(), to: end.UnixNano()}
	if err := readStore(ctx, scan.before, scan.after); err != nil {
		return r.fail("store: " + err.Error())
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	r.add(rangevm.FactAttemptsRoot, u(ok[0]))
	r.add(rangevm.FactAttemptsOther, u(ok[1]))
	r.add(rangevm.FactRefusedCount, u(scan.count))
	r.add(rangevm.FactRefusedUID, u(scan.uid))
	r.add(rangevm.FactSummaries, u(scan.summaries))
	r.add(rangevm.FactMaxLatencyMS, u(scan.latency/uint64(time.Millisecond)))
	r.add(rangevm.FactSummaryFields, valueOr2(scan.missing, "ok"))
	r.add(rangevm.FactOtherRecords, u(scan.other))
	return r.send(r.facts)
}

// flood runs a flooder child with cred and returns how many connections it made.
func flood(ctx context.Context, cred *syscall.Credential, rate, seconds int) (uint64, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("flooder: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second+floodTimeout)
	defer cancel()
	child := exec.CommandContext(ctx, self, floodArg, strconv.Itoa(rate), strconv.Itoa(seconds)) //nolint:gosec // our own binary
	child.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	child.Stderr = os.Stderr
	out, err := child.Output()
	if err != nil {
		return 0, fmt.Errorf("flooder uid %d: %w", cred.Uid, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("flooder uid %d said %q", cred.Uid, bytes.TrimSpace(out))
	}
	return n, nil
}

// floodMain is a flooder's process: rate connections a second to the collector's socket for seconds,
// each closed at once, on the generator's schedule; it prints how many connected.
func floodMain(args []string) error {
	if len(args) != 2 {
		return errors.New("want rate and seconds")
	}
	rate, errR := strconv.Atoi(args[0])
	seconds, errS := strconv.Atoi(args[1])
	if errR != nil || errS != nil || rate < 1 || seconds < 1 {
		return errors.New("rate and seconds must be positive numbers")
	}
	var ok uint64
	d := net.Dialer{Timeout: time.Second}
	start := time.Now()
	for i := range rate * seconds {
		if due := time.Duration(i) * time.Second / time.Duration(rate); due > time.Since(start) {
			time.Sleep(due - time.Since(start))
		}
		if c, err := d.DialContext(context.Background(), "unix", collectorSocket); err == nil {
			ok++
			_ = c.Close()
		}
	}
	_, err := fmt.Fprintln(os.Stdout, ok)
	return err //nolint:wrapcheck // the process's own output
}

// refusalScan is what the refusal summaries in the store count, and the other health records stored
// between from and to, the flood.
type refusalScan struct {
	from, to              int64
	count, uid, summaries uint64
	latency               uint64 // the longest from a summary's first refusal to its record, ns
	missing               string // the first field a summary lacks
	other                 uint64
}

func (s *refusalScan) before(x rawrecord.Record) error {
	if x.Provider != store.SensorProvider && x.Received >= s.from && x.Received <= s.to && !floodKinds[healthKind(x)] {
		s.other++
	}
	return s.after(x)
}

// after counts every summary, also the one the read's stop stores behind the barrier.
func (s *refusalScan) after(x rawrecord.Record) error {
	if healthKind(x) != "refused" {
		return nil
	}
	var rec struct {
		Count       *uint64           `json:"count"`
		Causes      map[string]uint64 `json:"causes"`
		Socket      string            `json:"socket"`
		RuleVersion string            `json:"rule_version"`
		FirstAt     *int64            `json:"first_at"`
		At          *int64            `json:"at"`
		LastUID     *int64            `json:"last_uid"`
	}
	s.summaries++
	err := json.Unmarshal(x.Data, &rec)
	switch {
	case err != nil:
		s.firstMissing("a readable record")
	case rec.Count == nil:
		s.firstMissing("count")
	case rec.Causes == nil:
		s.firstMissing("causes")
	case rec.Socket == "":
		s.firstMissing("socket")
	case rec.RuleVersion == "":
		s.firstMissing("rule_version")
	case rec.LastUID == nil:
		s.firstMissing("last_uid")
	case rec.FirstAt == nil || rec.At == nil || *rec.At < *rec.FirstAt:
		s.firstMissing("first_at before at")
	default:
		s.count += *rec.Count
		s.uid += rec.Causes["uid"]
		s.latency = max(s.latency, uint64(*rec.At-*rec.FirstAt)) //nolint:gosec // checked not negative
	}
	return nil
}

func (s *refusalScan) firstMissing(field string) {
	if s.missing == "" {
		s.missing = field
	}
}

// healthKind is the kind of a health record of the known schema, "" for any other record.
func healthKind(x rawrecord.Record) string {
	if x.Provider != store.HealthProvider {
		return ""
	}
	h, ok := decodeHealth(x.Data)
	if !ok {
		return "unreadable"
	}
	return h.kind
}

func valueOr2(v, absent string) string {
	if v == "" {
		return absent
	}
	return v
}
