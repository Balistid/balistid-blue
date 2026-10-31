package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
)

const (
	relayUnit      = "balistid-relay.service"
	announceUnit   = "balistid-announce.service"
	collectorSock  = "balistid-collector.socket"
	hostWG         = "balistid0"
	hostLAN        = "balistid-lan"
	alarmReadyWait = 2 * time.Minute
	cosignSample   = 250 * time.Millisecond
	// alarmGrace is how long past its window an alarm trial waits for the alert, so a late one is seen late.
	alarmGrace = 15 * time.Second
	// postsMax bounds the sink's file as read: its 4096 lines of at most a uptime, a tag and a word.
	postsMax = 4096 * 40
	// quietOff and quietBack are quiet-again's ledger stop and its brief return before the second announcement.
	quietOff  = 2 * time.Minute
	quietBack = time.Minute
	// gapWindow is the connected stretch under load the cosign gap trend covers before an injection.
	gapWindow = 90 * time.Second
)

// cosignWatch samples the size the witness cosigned, as the relay keeps it, on the guest's uptime: when it
// last grew and the largest gap between growths before stop is called.
type cosignWatch struct {
	mu      sync.Mutex
	size    uint64
	grew    time.Duration // uptime of the last growth, 0 before the first
	growths int
	maxGap  time.Duration
	frozen  bool
}

func (w *cosignWatch) see(size uint64, at time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if size <= w.size {
		return
	}
	if w.grew > 0 && !w.frozen {
		w.maxGap = max(w.maxGap, at-w.grew)
	}
	w.size, w.grew = size, at
	w.growths++
}

func (w *cosignWatch) state() (grew time.Duration, growths int, maxGap time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.grew, w.growths, w.maxGap
}

// freeze ends the gap trend: after an injection the gap is the silence itself.
func (w *cosignWatch) freeze() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frozen = true
}

func (w *cosignWatch) run(ctx context.Context, keys cosign.Keys) {
	for {
		if cp, err := cosign.Read(filepath.Join(relayState, cosign.Name), keys); err == nil {
			if up, err := uptime(); err == nil {
				w.see(cp.Size, up)
			}
		}
		if !pause(ctx, cosignSample) {
			return
		}
	}
}

// sinkPosts reads the sink's file: the posts with the range token, in file order, and how many came without.
func sinkPosts(r io.Reader) ([]rangevm.Post, int, error) {
	data, err := io.ReadAll(io.LimitReader(r, postsMax+1))
	if err != nil {
		return nil, 0, fmt.Errorf("posts: %w", err)
	}
	if len(data) > postsMax {
		return nil, 0, errors.New("posts: over the sink's cap")
	}
	var posts []rangevm.Post
	refused := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			return nil, 0, fmt.Errorf("posts: line %q", sc.Text())
		}
		ms, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("posts: line %q", sc.Text())
		}
		switch f[2] {
		case "ok":
			posts = append(posts, rangevm.Post{MS: ms, Tag: f[1]})
		case "bad":
			refused++
		default:
			return nil, 0, fmt.Errorf("posts: line %q", sc.Text())
		}
	}
	return posts, refused, nil
}

func readSink() ([]rangevm.Post, int, error) {
	f, err := os.OpenFile(ntfyPosts, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("posts: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	return sinkPosts(f)
}

// postsFact keeps what the judge reads, at most 64 posts in time order: the first start, every silence alert,
// and the rest from the injection on.
func postsFact(posts []rangevm.Post, inject uint64) string {
	var keep []string
	started := false
	for _, p := range posts {
		first := p.Tag == "start" && !started
		started = started || p.Tag == "start"
		if p.Tag != "-" && (first || p.Tag == "silence" || p.MS > inject) && len(keep) < 64 { // "-": no alert key
			keep = append(keep, rangevm.FormatPost(p))
		}
	}
	if len(keep) == 0 {
		return "none"
	}
	return strings.Join(keep, ",")
}

// runAlarm runs alarm trial tr (ADR 0036): with the watcher started through the sink and the cosigned size
// growing under a light load, it injects tr's cause, proves it, and waits for the silence alert at the sink.
func runAlarm(ctx context.Context, tr rangejob.Trial, r *report) error {
	keys, err := rangeKeys()
	if err != nil {
		return r.fail(err.Error())
	}
	wctx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	var cw cosignWatch
	go cw.run(wctx, keys)
	lctx, stopLoad := context.WithCancel(ctx)
	defer stopLoad() // the load runs through the wait: growth the injection did not stop shows as grown_after
	go lightLoad(lctx)
	if why := alarmReady(ctx, &cw); why != "" {
		return r.fail(why)
	}
	pause(ctx, gapWindow) // a connected stretch for the cosign gap trend, under load
	restarts := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "NRestarts", piUnit))
	cw.freeze() // the gap trend ends where the injection begins: quiet-again's ledger stop is no cosign gap
	inject, again, done := injectAlarm(ctx, tr)
	if err := waitAlarm(ctx, tr, &cw, inject); err != nil {
		return r.fail(err.Error())
	}
	grew, _, gap := cw.state()
	stopWatch()
	active := valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", piUnit)))
	after := "no"
	if grew > done+rangevm.SettleAfter {
		after = fmt.Sprintf("yes, at %d ms", grew.Milliseconds())
	}
	posts, refused, err := readSink()
	if err != nil {
		return r.fail(err.Error())
	}
	if !firstAfter(posts, "silence", inject.at) { // the range keeps no guest journal: the console shows why
		fmt.Printf("balistid-range-guest: no silence alert; posts %s; watcher %s\n", postsFact(posts, 0), piDiag(ctx))
	}
	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	r.add(rangevm.FactInject, inject.proof)
	r.add(rangevm.FactInjectMS, ms(inject.from))
	r.add(rangevm.FactInjectEndMS, ms(inject.at))
	r.add(rangevm.FactCosignedMS, ms(grew))
	r.add(rangevm.FactGrownAfter, after)
	r.add(rangevm.FactPosts, postsFact(posts, uint64(inject.from.Milliseconds()))) //nolint:gosec // uptime is positive
	r.add(rangevm.FactRefused, strconv.Itoa(refused))
	r.add(rangevm.FactRestartsPre, valueOr(restarts))
	r.add(rangevm.FactRestartsPost, valueOr(strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "NRestarts", piUnit))))
	r.add(rangevm.FactAgainMS, again)
	r.add(rangevm.FactCosignGapMS, ms(gap))
	r.add(rangevm.FactPiActive, active)
	return r.send(r.facts)
}

// alarmReady waits until the watcher is active, its start reached the sink, accepted or refused for its token
// (the judge makes a refused one a MISS), and the cosigned size grew twice; "" when it did, else why not.
func alarmReady(ctx context.Context, cw *cosignWatch) string {
	for deadline := time.Now().Add(alarmReadyWait); ; {
		posts, refused, err := readSink()
		_, growths, _ := cw.state()
		active := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "is-active", piUnit)) == "active"
		if err == nil && active && growths >= 2 && (slicesHasTag(posts, "start") || refused > 0) {
			return ""
		}
		if time.Now().After(deadline) || !pause(ctx, time.Second) {
			return fmt.Sprintf("not ready: watcher active %v, %d growths, posts %v (%v); %s", active, growths, len(posts), err, piDiag(ctx))
		}
	}
}

func slicesHasTag(posts []rangevm.Post, tag string) bool {
	for _, p := range posts {
		if p.Tag == tag {
			return true
		}
	}
	return false
}

// lightLoad runs /usr/bin/true five times a second until ctx ends, so the log grows up to the injection.
func lightLoad(ctx context.Context) {
	for pause(ctx, 200*time.Millisecond) {
		_ = exec.CommandContext(ctx, "/usr/bin/true", "balistid-alarm-load").Run()
	}
}

// waitAlarm waits until a silence alert after the injection reached the sink, or its window and alarmGrace
// passed: silence counts from the last growth, the quiet cap from the first announcement proven. A clock that
// cannot be read is an error: the run is INVALID, not a MISS.
func waitAlarm(ctx context.Context, tr rangejob.Trial, cw *cosignWatch, in injection) error {
	for {
		grew, _, _ := cw.state()
		end := grew + 845*time.Second + alarmGrace
		if tr.Metric == rangejob.MetricQuiet {
			end = in.at + rangevm.RangeQuiet + time.Minute + alarmGrace
		}
		posts, _, err := readSink()
		now, uerr := uptime()
		switch {
		case uerr != nil:
			return uerr
		case err == nil && firstAfter(posts, "silence", in.from) || now > end || !pause(ctx, time.Second):
			return nil
		}
	}
}

func firstAfter(posts []rangevm.Post, tag string, at time.Duration) bool {
	for _, p := range posts {
		if p.Tag == tag && p.MS > uint64(at.Milliseconds()) { //nolint:gosec // uptime is positive
			return true
		}
	}
	return false
}

// injection is what an alarm trial did: "ok" with its proof held, else why not, and the bracket it counts
// from: the cut for silence (from = at), for the quiet cap the first announcement from before its stop to its
// cosignature proven, as the Pi opens its quiet episode in between.
type injection struct {
	proof    string
	from, at time.Duration
}

// injectAlarm injects tr's cause and returns it, quiet-again's second announcement proven in ms or "none", and
// when the injection's last step ended, after which the cosigned size must not grow.
func injectAlarm(ctx context.Context, tr rangejob.Trial) (injection, string, time.Duration) {
	var in injection
	again := "none"
	fail := func(i int, err error) { in.proof = fmt.Sprintf("error: step %d: %v", i+1, err) }
	for i, s := range alarmSteps(tr.Inject) {
		before, err := uptime()
		if err != nil {
			fail(i, err)
			break
		}
		if err := s.run(ctx); err != nil {
			fail(i, err)
			break
		}
		proven, err := uptime()
		switch {
		case err != nil:
			fail(i, err)
		case s.announces && in.at == 0:
			in.from, in.at = before, proven
		case s.announces:
			again = strconv.FormatInt(proven.Milliseconds(), 10)
		}
		if in.proof != "" {
			break
		}
	}
	done, err := uptime()
	switch {
	case err != nil && in.proof == "":
		in.proof = "error: " + err.Error()
	case in.proof == "":
		in.proof = "ok"
	}
	if tr.Metric == rangejob.MetricSilence {
		in.from, in.at = done, done
	}
	return in, again, done
}

// step is one action of an injection; announces marks an announcement proven cosigned.
type step struct {
	run       func(context.Context) error
	announces bool
}

func alarmSteps(inject string) []step {
	stopHost := step{run: func(ctx context.Context) error {
		return stopUnits(ctx, collectorUnitName, collectorSock, relayUnit, ledgerUnit)
	}}
	announce := step{run: func(ctx context.Context) error {
		prior, err := priorAnnouncement(ctx)
		if err != nil {
			return err
		}
		if got := announced(ctx, "stop", announceUnit, entry.AnnounceShutdown, prior); got != "yes" {
			return errors.New("announce: " + got)
		}
		return nil
	}, announces: true}
	switch inject {
	case rangejob.InjectWireGuard:
		return []step{{run: func(ctx context.Context) error { return linksDown(ctx, hostWG) }}}
	case rangejob.InjectLedger:
		return []step{{run: func(ctx context.Context) error { return killUnits(ctx, ledgerUnit) }}}
	case rangejob.InjectHardStop:
		return []step{{run: func(ctx context.Context) error {
			// one stop with the socket, so it cannot start the killed collector again in between
			if err := systemctl(ctx, "kill", "--signal=KILL", collectorUnitName, relayUnit, ledgerUnit); err != nil {
				return err
			}
			return errors.Join(stopUnits(ctx, collectorSock, collectorUnitName, relayUnit, ledgerUnit), linksDown(ctx, hostWG, hostLAN))
		}}}
	case rangejob.InjectQuietOff:
		return []step{announce, stopHost}
	case rangejob.InjectQuietMasked:
		return []step{announce, stopHost, {run: func(ctx context.Context) error {
			return errors.Join(systemctl(ctx, "mask", "--runtime", ledgerUnit),
				systemctl(ctx, "start", collectorSock, collectorUnitName, relayUnit))
		}}}
	case rangejob.InjectQuietAgain:
		return []step{announce, {run: func(ctx context.Context) error {
			if err := stopUnits(ctx, ledgerUnit); err != nil {
				return err
			}
			if !pause(ctx, quietOff) {
				return ctx.Err()
			}
			if err := systemctl(ctx, "start", ledgerUnit, announceUnit); err != nil {
				return err
			}
			if !pause(ctx, quietBack) {
				return ctx.Err()
			}
			return nil
		}}, announce, stopHost}
	}
	return []step{{run: func(context.Context) error { return fmt.Errorf("no injection %q", inject) }}}
}

func systemctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", args...).CombinedOutput() //nolint:gosec // fixed verbs and units
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out[:min(len(out), 256)]))
	}
	return nil
}

// stopUnits stops units cleanly and proves each inactive.
func stopUnits(ctx context.Context, units ...string) error {
	if err := systemctl(ctx, append([]string{"stop"}, units...)...); err != nil {
		return err
	}
	return inactive(ctx, units...)
}

// killUnits kills units by SIGKILL, as a crash or a power cut leaves them, then keeps them stopped: their
// Restart= would bring them back within a second. No ExecStop of theirs announces anything.
func killUnits(ctx context.Context, units ...string) error {
	if err := systemctl(ctx, append([]string{"kill", "--signal=KILL"}, units...)...); err != nil {
		return err
	}
	return stopUnits(ctx, units...)
}

func inactive(ctx context.Context, units ...string) error {
	for _, u := range units {
		if s := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "ActiveState", u)); s != "inactive" && s != "failed" {
			return fmt.Errorf("%s is %q after its stop", u, s)
		}
	}
	return nil
}

// priorAnnouncement is the index of the log's last shutdown announcement, -1 when it has none: a new one must
// come after it.
func priorAnnouncement(ctx context.Context) (int64, error) {
	keys, err := rangeKeys()
	if err != nil {
		return 0, err
	}
	at, err := lastAnnouncement(ctx, ledgerLog, keys.Log, entry.AnnounceShutdown)
	switch {
	case errors.Is(err, errNoAnnouncement):
		return -1, nil
	case err != nil:
		return 0, err
	}
	return int64(at), nil //nolint:gosec // a log index is far below 2^63
}

// errStillUp is a link whose IFF_UP survived its ip link set down.
var errStillUp = errors.New("IFF_UP still set")

// linksDown sets the host's links down and proves IFF_UP cleared on each.
func linksDown(ctx context.Context, links ...string) error {
	for _, l := range links {
		if out, err := exec.CommandContext(ctx, "/usr/bin/ip", "link", "set", l, "down").CombinedOutput(); err != nil { //nolint:gosec // fixed links
			return fmt.Errorf("ip link set %s down: %w: %s", l, err, bytes.TrimSpace(out))
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(readTrim("/sys/class/net/"+l+"/flags"), "0x"), 16, 32)
		if err != nil || flags&syscall.IFF_UP != 0 {
			return fmt.Errorf("%s still up (flags %#x): %w", l, flags, errors.Join(err, errStillUp))
		}
	}
	return nil
}
