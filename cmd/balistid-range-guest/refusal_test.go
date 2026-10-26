package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

func healthAt(received int64, data string) rawrecord.Record {
	return rawrecord.New(1, store.HealthProvider, 0, received, []byte(data))
}

// startedRecord is the collector's started record as writer.go writes it: its argv facts under info.
const startedRecord = `{"schema_version":1,"kind":"started","info":{"version":"v","boot_id":"b","rule_version":"adr-0004-v2"},"at":1,"note_seq":1}`

func refusedAt(received, firstAt int64, count int) rawrecord.Record {
	return healthAt(received, fmt.Sprintf(`{"schema_version":1,"kind":"refused","socket":"collector.sock","count":%d,`+
		`"causes":{"uid":%d},"first_at":%d,"last_at":%d,"at":%d,"rule_version":"adr-0004-v2","last_uid":0,"last_error":""}`,
		count, count, firstAt, firstAt, firstAt))
}

// Summaries before and behind the barrier add up; the longest from a first refusal to the store
// receiving its summary counts; health records of other kinds during the flood are counted, before or
// after it they are not.
func TestRefusalScan(t *testing.T) {
	s := refusalScan{from: 1000, to: 2000}
	for _, x := range []rawrecord.Record{
		healthAt(900, startedRecord),
		refusedAt(1500, 1000, 10),
		healthAt(1600, `{"schema_version":1,"kind":"stats","lost":0,"lost_health":0}`),
		healthAt(1700, `{"schema_version":1,"kind":"connection","causes":{"start":1}}`),
		healthAt(1800, `{"schema_version":1,"event":"recovered"}`),
		rawrecord.New(1, store.LossProvider, 0, 1900, []byte(`{}`)),
		rawrecord.New(1, store.SensorProvider, 1, 1900, []byte(`{"ID":"1.0:1"}`)),
		healthAt(2500, `{"schema_version":1,"kind":"connection","causes":{"eof":1}}`),
	} {
		_ = s.before(x)
	}
	_ = s.after(refusedAt(2600, 1450, 5))
	_ = s.after(healthAt(2700, `{"schema_version":1,"kind":"stopping"}`))
	if s.count != 15 || s.uid != 15 || s.summaries != 2 || s.latency != 1150 || s.missing != "" || s.other != 3 {
		t.Errorf("scan %+v", s)
	}
}

// A summary that is not whole is reported by its first fault and not counted.
func TestRefusalScanNamesAFault(t *testing.T) {
	const ok = `"socket":"collector.sock","count":2,"causes":{"uid":2},"first_at":1,"rule_version":"adr-0004-v2","last_uid":0`
	for _, c := range []struct{ want, data string }{
		{"rule_version", strings.Replace(ok, `"adr-0004-v2"`, `"adr-0004-v1"`, 1)},
		{"socket", strings.Replace(ok, `"collector.sock"`, `"other.sock"`, 1)},
		{"causes", strings.Replace(ok, `{"uid":2}`, `{"uid":1,"peer_error":1}`, 1)},
		{"count", strings.Replace(ok, `"count":2`, `"count":0`, 1)},
		{"last_uid", strings.Replace(ok, `,"last_uid":0`, ``, 1)},
		{"first_at before it was stored", strings.Replace(ok, `"first_at":1`, `"first_at":9`, 1)},
		{"first_at before it was stored", strings.Replace(ok, `"first_at":1`, `"first_at":-9223372036854775808`, 1)},
	} {
		s := refusalScan{}
		_ = s.after(healthAt(1, startedRecord))
		_ = s.after(healthAt(5, `{"schema_version":1,"kind":"refused",`+c.data+`}`))
		if s.missing != c.want || s.count != 0 || s.summaries != 1 {
			t.Errorf("%s: %+v", c.want, s)
		}
	}
	s := refusalScan{}
	_ = s.after(healthAt(5, `{"schema_version":1,"kind":"refused",`+ok+`}`))
	if s.missing != "rule_version" {
		t.Errorf("a summary without its run's started record: %+v", s)
	}
}

func TestCeilMS(t *testing.T) {
	for ns, want := range map[uint64]uint64{0: 0, 1: 1, 1_000_000: 1, 60_250_000_001: 60_251, math.MaxUint64: math.MaxUint64/1_000_000 + 1} {
		if got := ceilMS(ns); got != want {
			t.Errorf("ceilMS(%d) = %d, want %d", ns, got, want)
		}
	}
}

// listen is a unix socket in a fresh directory, skipped where the sandbox denies unix sockets.
func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		if errors.Is(err, syscall.EPERM) && os.Getenv("CI") != "true" {
			t.Skipf("unix sockets denied here: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, path
}

// A flooder connects at its rate and counts each connection; it stops on time with what it made.
func TestFloodSocket(t *testing.T) {
	ln, path := listen(t)
	var accepted atomic.Uint64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	start := time.Now()
	if n := floodSocket(path, 50, 2); n != 100 || time.Since(start) > 2*time.Second+floodGrace {
		t.Errorf("made %d of 100 in %s", n, time.Since(start))
	}
	if n := floodSocket(filepath.Join(t.TempDir(), "none"), 50, 1); n != 0 {
		t.Errorf("made %d connections to no socket", n)
	}
}

// The injector says it is connected before it writes, and the peer reads every malformed line whole.
func TestInjectLines(t *testing.T) {
	ln, path := listen(t)
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close() //nolint:errcheck // test peer
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(c)
		got <- buf.Bytes()
	}()
	var said bytes.Buffer
	if err := injectLines(path, "balistid-record0f", &said); err != nil {
		t.Fatal(err)
	}
	want := strings.Join(malformedLines("balistid-record0f"), "\n") + "\n"
	if data := <-got; said.String() != "connected\n" || string(data) != want {
		t.Errorf("said %q, peer read %d bytes, want %d", said.String(), len(data), len(want))
	}
	if err := injectLines(filepath.Join(t.TempDir(), "none"), "t", &said); err == nil {
		t.Error("connected to no socket")
	}
}
