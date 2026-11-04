package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Balistid/balistid-blue/internal/rangeguest"
	"github.com/Balistid/balistid-blue/internal/rangejob"
	"github.com/Balistid/balistid-blue/internal/rangevm"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
)

// rulesSetupArg is how range/balistid-range-rules.service runs the guest before audit-rules.service loads the rules
// (ADR 0059, point 5); rulesFile sorts after balistid.rules, so augenrules appends it before the closing -e 2.
const (
	rulesSetupArg = "rules-setup"
	rulesFile     = "/etc/audit/rules.d/zz-balistid-range.rules"
	// extraKey names the rule the extra file adds, so auditctl -l proves it loaded.
	extraKey = "balistid-range-extra"
	// The collector's health while it waits for the first canary over a connection, and for rules not shipped.
	canaryPending = "UNKNOWN canary-pending"
	rulesDiffer   = "UNKNOWN rules-differ"
)

// injectedRules is the rules file of each rules injection: a rule added, the b32 memfd rule deleted (never the
// canary's watch, without which no canary would end canary-pending), or -b changed.
var injectedRules = map[string]string{
	rangejob.InjectRulesExtra:   "-a always,exit -F arch=b64 -S openat -F uid=4242 -k " + extraKey + "\n",
	rangejob.InjectRulesMissing: "-d always,exit -F arch=b32 -S memfd_create -k balistid-memfd\n",
	rangejob.InjectRulesStatus:  "-b 8192\n",
}

// rulesSetup writes the rules file of a rules trial's boot; any other boot only proves there is none, so no other
// trial runs with rules that are not the repository's.
func rulesSetup() error {
	name, phase, err := rangeguest.TrialCredentials(credentials())
	if err != nil {
		return fmt.Errorf("trial: %w", err)
	}
	tr := rangejob.Trial{}
	if name != "" {
		if tr, _, err = rangeguest.TrialFor(name, phase); err != nil {
			return fmt.Errorf("trial: %w", err)
		}
	}
	text, inject := rulesFor(tr)
	if !inject {
		if _, err := os.Lstat(rulesFile); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s exists outside a rules trial: %w", rulesFile, err)
		}
		return nil
	}
	if err := os.WriteFile(rulesFile, []byte(text), 0o640); err != nil { //nolint:gosec // augenrules' own mode for rules.d
		return fmt.Errorf("rules file: %w", err)
	}
	return nil
}

// rulesFor is the rules file tr's boot writes, if any: only a rules trial's.
func rulesFor(tr rangejob.Trial) (string, bool) {
	text, ok := injectedRules[tr.Inject]
	return text, ok && tr.Method() == rangejob.MethodSensorDownRules
}

// runSensorDownRules measures sensor_down_s's rules shapes (ADR 0059, point 5): it proves the injected rules loaded
// and locked, watches for RulesWatch, then reads the store once for the collector's health states over the watch.
func runSensorDownRules(ctx context.Context, tr rangejob.Trial, r *report) error {
	r.add(rangevm.FactRulesProof, rulesProof(tr.Inject, output(ctx, "/usr/bin/auditctl", "-l"),
		rangeguest.AuditStatus(output(ctx, "/usr/bin/auditctl", "-s"))))
	if !pause(ctx, rangevm.RulesWatch) {
		return r.fail("watch: " + ctx.Err().Error())
	}
	until := time.Now().UnixNano()
	var timeline healthTimeline
	each := func(x rawrecord.Record) error { return timeline.add(x) }
	if err := readStore(ctx, each, each); err != nil {
		return r.fail("store: " + err.Error())
	}
	watch, states, differ := timeline.states(until)
	r.add(rangevm.FactRulesWatchMS, watch)
	r.add(rangevm.FactRulesStates, states)
	r.add(rangevm.FactRulesDifferMS, differ)
	return r.send(r.facts)
}

// rulesProof is "yes" when auditctl -l (list) and -s (status) show inject's rules file loaded, with audit locked;
// else what differs. The shipped file has seven rules, one line each.
func rulesProof(inject, list string, status map[string]string) string {
	lines := 0
	for l := range strings.SplitSeq(strings.TrimSpace(list), "\n") {
		if strings.HasPrefix(l, "-a ") || strings.HasPrefix(l, "-w ") {
			lines++
		}
	}
	want, extra := 7, strings.Contains(list, "-k "+extraKey) || strings.Contains(list, "key="+extraKey)
	memfd32 := strings.Contains(list, "arch=b32 -S memfd_create")
	switch inject {
	case rangejob.InjectRulesExtra:
		want = 8
	case rangejob.InjectRulesMissing:
		want = 6
	}
	switch {
	case status["enabled"] != "2":
		return fmt.Sprintf("audit enabled %q, not locked", status["enabled"])
	case lines != want:
		return fmt.Sprintf("%d rules loaded, not %d", lines, want)
	case extra != (inject == rangejob.InjectRulesExtra):
		return "the extra rule loaded " + yesNo(extra)
	case memfd32 == (inject == rangejob.InjectRulesMissing):
		return "the b32 memfd rule loaded " + yesNo(memfd32)
	case (status["backlog_limit"] == "8192") != (inject == rangejob.InjectRulesStatus):
		return "backlog_limit " + strconv.Quote(status["backlog_limit"])
	}
	return "yes"
}

// states is how long the timeline runs from its first record to until, in ms; its states up to until, each once per
// change, joined by rangevm.StatesSep; and the ms from the first stored canary to the first rules-differ, or
// rangevm.CanaryNone. The canary is stored at the change away from the last canary-pending before that rules-differ:
// the tick that stored it ends the wait.
func (t healthTimeline) states(until int64) (watch, states, differ string) {
	var out []string
	var from, pending, stored int64
	differ = rangevm.CanaryNone
	for _, h := range t {
		if h.at <= 0 || h.at > until {
			continue
		}
		if from == 0 {
			from = h.at
		}
		if len(out) > 0 && out[len(out)-1] == h.state {
			continue
		}
		switch {
		case differ != rangevm.CanaryNone:
		case h.state == canaryPending:
			pending, stored = h.at, 0
		case pending != 0 && stored == 0:
			stored = h.at
		}
		if h.state == rulesDiffer && differ == rangevm.CanaryNone && stored != 0 {
			differ = msString(h.at - stored)
		}
		out = append(out, h.state)
	}
	if from == 0 {
		return rangevm.CanaryNone, "", differ
	}
	return msString(until - from), strings.Join(out, rangevm.StatesSep), differ
}
