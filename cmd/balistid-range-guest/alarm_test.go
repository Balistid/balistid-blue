package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/shard"
)

func TestSinkPostsCountsOnlyTheRangeToken(t *testing.T) {
	posts, refused, err := sinkPosts(strings.NewReader(sinkHeader + "\n1000 start ok\n2000 silence bad\n3000 - ok\n4000 silence ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []rangevm.Post{{MS: 1000, Tag: "start"}, {MS: 3000, Tag: "-"}, {MS: 4000, Tag: "silence"}}
	if fmt.Sprint(posts) != fmt.Sprint(want) || refused != 1 {
		t.Errorf("posts %v, refused %d", posts, refused)
	}
	for _, bad := range []string{"1000 start\n", "x start ok\n", "1000 start maybe\n", "-1 start ok\n", strings.Repeat("1 a ok\n", postsMax)} {
		if _, _, err := sinkPosts(strings.NewReader(sinkHeader + "\n" + bad)); err == nil {
			t.Errorf("%.40q read", bad)
		}
	}
	for _, header := range []string{"", "balistid-range-ntfy 2 token=bearer-range-only", "1000 start ok"} {
		if _, _, err := sinkPosts(strings.NewReader(header + "\n1000 start ok\n")); err == nil {
			t.Errorf("header %q read", header)
		}
	}
}

// The posts fact keeps what the judge reads and parses back as the judge reads it.
func TestPostsFactKeepsStartSilenceAndAfter(t *testing.T) {
	posts := []rangevm.Post{{MS: 1000, Tag: "start"}, {MS: 2000, Tag: "daily"}, {MS: 3000, Tag: "start"}, {MS: 4000, Tag: "silence"},
		{MS: 9000, Tag: "freshness"}, {MS: 9500, Tag: "silence"}}
	got := postsFact(posts, 5000)
	if got != "1000:start,4000:silence,9000:freshness,9500:silence" {
		t.Errorf("posts fact %q", got)
	}
	if _, err := rangevm.ParsePosts(got); err != nil {
		t.Errorf("the judge cannot read %q: %v", got, err)
	}
	// a post without an alert key is no alert, and the judge must still read the fact
	if got := postsFact([]rangevm.Post{{MS: 1000, Tag: "start"}, {MS: 6000, Tag: "-"}, {MS: 7000, Tag: "silence"}}, 5000); got != "1000:start,7000:silence" {
		t.Errorf("posts fact with an untagged post %q", got)
	}
	if postsFact(nil, 0) != "none" {
		t.Error("no posts is not none")
	}
	many := make([]rangevm.Post, 100)
	for i := range many {
		many[i] = rangevm.Post{MS: uint64(10_000 + i), Tag: "loss"}
	}
	if p, err := rangevm.ParsePosts(postsFact(many, 5000)); err != nil || len(p) != 64 {
		t.Errorf("100 posts kept as %d (%v)", len(p), err)
	}
}

func TestCosignWatchGapStopsAtTheInjection(t *testing.T) {
	var w cosignWatch
	w.see(5, 10*time.Second)
	w.see(5, 12*time.Second) // the same size is no growth
	w.see(7, 15*time.Second)
	w.see(9, 22*time.Second)
	w.freeze()
	w.see(10, 900*time.Second)
	grew, growths, gap := w.state()
	if grew != 900*time.Second || growths != 4 || gap != 7*time.Second {
		t.Errorf("grew %v, growths %d, gap %v", grew, growths, gap)
	}
}

// The control reports every alert since the watcher's start, a loss trial those after its injection.
func TestLossPostsFactControlFromStart(t *testing.T) {
	posts := []rangevm.Post{{MS: 60000, Tag: "start"}, {MS: 90000, Tag: "loss"}, {MS: 95000, Tag: "unknown"}, {MS: 120000, Tag: "loss"}}
	for inject, want := range map[string]string{
		rangejob.InjectNone:  "60000:start,90000:loss,95000:unknown,120000:loss",
		rangejob.InjectStore: "60000:start,120000:loss",
	} {
		if got := lossPostsFact(rangejob.Trial{Inject: inject}, posts, 100*time.Second); got != want {
			t.Errorf("%s: posts fact %q, want %q", inject, got, want)
		}
	}
}

// A fill is proven only with a WAL left and less than a WAL and the admit slack: less raced the store's writes.
func TestFillLeftNeedsAWALAndNoMore(t *testing.T) {
	for left, ok := range map[int64]bool{
		0: false, shard.WALMaxBytes - 1: false, shard.WALMaxBytes: true, shard.WALMaxBytes + fillSlack - 1: true,
		shard.WALMaxBytes + fillSlack: false, 1 << 30: false,
	} {
		if err := fillLeft(left); (err == nil) != ok {
			t.Errorf("%d bytes left: %v, want ok %v", left, err, ok)
		}
	}
}

// Each collector loss is matched by the entry its cause makes, and by nothing else.
func TestLossMatch(t *testing.T) {
	for inject, cases := range map[string]map[entry.Body]bool{
		rangejob.InjectQueue:  {entry.Loss{Seq: 1, Stage: entry.StageQueue, Records: 3}: true, entry.Loss{Seq: 1, Stage: entry.StageCap, Records: 3}: false},
		rangejob.InjectFullFS: {entry.Loss{Seq: 1, Stage: entry.StageCap, Records: 3}: true, entry.Loss{Seq: 1, Stage: entry.StageStore, Records: 3}: false},
		rangejob.InjectStore: {entry.Loss{Seq: 1, Stage: entry.StageStore, Records: 3}: true,
			entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStoreDown}: true,
			entry.Health{State: entry.StateUnknown, Reason: entry.ReasonStream}:    false},
		rangejob.InjectKernel: {entry.Loss{Seq: 1, Stage: entry.StageQueue, Records: 3}: false},
		rangejob.InjectNone:   {entry.Loss{Seq: 1, Stage: entry.StageQueue, Records: 3}: false},
	} {
		match := lossMatch(inject)
		for b, want := range cases {
			if match(b) != want {
				t.Errorf("%s matches %+v: %v, want %v", inject, b, !want, want)
			}
		}
	}
}

// Every injection of the table has steps; an unknown one fails its first step, so its run is INVALID.
func TestAlarmStepsCoverTheTable(t *testing.T) {
	for _, tr := range rangejob.Trials() {
		if tr.Method() != rangejob.MethodAlarm {
			continue
		}
		steps := alarmSteps(tr.Inject)
		announces := 0
		for _, s := range steps {
			if s.announces {
				announces++
			}
		}
		want := map[string]int{rangejob.MetricSilence: 0, rangejob.MetricQuiet: 1}[tr.Metric]
		if tr.Inject == rangejob.InjectQuietAgain {
			want = 2
		}
		if len(steps) == 0 || announces != want {
			t.Errorf("%s: %d steps, %d announcing, want %d", tr.Name, len(steps), announces, want)
		}
	}
	if err := alarmSteps("power-off")[0].run(context.Background()); err == nil {
		t.Error("an unknown injection ran")
	}
}
