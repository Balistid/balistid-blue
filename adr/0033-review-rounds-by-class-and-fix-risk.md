# 0033 — Review rounds by a finding's class and its fix's risk

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R7 and §5 send every defect a fix introduces, and every third round with a finding, to a redesign the
maintainer decides; the reviewer's rubric asks for another round after any finding. Over 125 Codex rounds
(2026-10-05 to 10-30) the rounds after the first cost about 585 points of the 5-hour window, and since 10-24
63 % of them found only MED or LOW; of 53 defects introduced by fixes about 34 were local slips and 19
design flaws. Rounds paid off where a fix touched a decision (PASS recorded on a failed write, a rounding
overflow); churn came from one design flaw found again round after round and from MED findings escalated
by rule. Severity says how much a defect hurts, not whether the design is wrong. The review queue is one
way, so a disagreement could only become another full round or a question to the maintainer.

## Decision

1. Each finding carries severity (the reviewer's), class and fix risk. Severity decides only whether it
   blocks merge: an open CRIT or HIGH inside the change does.
2. Class BUG: a change in one unit restores the named invariant for the reported input and its siblings,
   with no condition keyed on that input. Class DESIGN: no single unit owns the invariant; holding it needs
   a special case, coordinated changes in two or more components, or a changed ADR, threat or acceptance
   assumption. The same invariant failing again after a fix that claimed it, or a fix adding a branch keyed
   on the reported input, is DESIGN. The reviewer proposes the class; an open disagreement counts as
   DESIGN; the author moves a class only toward DESIGN.
3. Fix risk is decision when the fix changes a decision value (PASS, FAIL, deny, allow, UNKNOWN, an exit
   code) or what feeds it (a comparison, threshold, counter), what an error path returns or skips, what is
   permitted (allowlist, mode, uid, capability, sandbox, firewall verdict), where secrets go, a test
   assertion, or makes a check fire less often (§3); otherwise plain. The stricter call of the two wins.
4. One full round per checkpoint (§5 table). The author answers each finding FIXED (commit and a test
   failing on the parent, R4), DISPUTE (evidence by pointer: test and CI run, file:line, range fact and
   run), RESIDUAL (where it is recorded; never for an open CRIT or HIGH) or DESIGN. A plain BUG fix is
   verified by its test. Decision fixes and disputes go back to the reviewer in a reply round on the fix
   range: per finding confirmed, not fixed, conceded or maintained, plus new defects the fix range causes;
   at most two reply rounds. A redesign, or a fix range over about 150 lines outside tests, gets a full round.
5. The author decides a redesign, with one sentence why. The maintainer decides when it changes an ADR, an
   acceptance number or a threat claim, when author and reviewer still disagree after the reply rounds, or
   when an invariant fails again after a redesign.
6. A missing threat-model row is a plain BUG. The pull request keeps a ledger: finding, class, risk,
   answer, commit or test. Every third checkpoint a full round covers a range that had only reply rounds.

## Alternatives considered

- Redesign by severity: a CRIT can be a one-line bug (a key printed to the journal), a MED a design flaw
  (one logger that cannot carry a reason per rule).
- A plain cap on rounds: stops churn and real verification alike.
- Answers in the free text of the next full round: the author could narrow the criteria or misquote the
  findings; a reply round reads them from the queue's own record.

## Consequences

- Amends R7, §5 (its top tier asks for Codex level security), CLAUDE.md's review brief (a reply round
  carries the author's answers per finding, nothing else) and AGENTS.md's output format.
- Outside this repository the queue gains a reply mode and the reviewers' rubrics these fields; the
  maintainer installs them.
- Measured over the next three checkpoints: full and reply rounds per pull request, window spent, findings
  by class, and what the sampled full round finds.
