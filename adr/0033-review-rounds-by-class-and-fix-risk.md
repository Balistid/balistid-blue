# 0033 — Review rounds by a finding's class and its fix's risk

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-30
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

R7 and §5 send every defect a fix introduces, and every third round with a finding, to a redesign the maintainer
decides; the reviewer's rubric asks for another round after any finding. Over 125 Codex rounds the rounds after the
first cost about 585 points of the 5-hour window, and since 10-24 63 % of them found only MED or LOW; of 53 defects
introduced by fixes about 34 were local slips and 19 design flaws. Rounds paid off where a fix touched a decision
(PASS on a failed write); churn came from one design flaw found again and again and from MED findings escalated by
rule. Severity says how much a defect hurts, not whether the design is wrong. A one-way queue left a disagreement
two ways out: another full round or the maintainer.

## Decision

1. Each finding carries severity (the reviewer's), class and fix risk. Severity decides only whether it
   blocks merge: an open CRIT or HIGH inside the change does.
2. Class BUG: a change in one unit restores the named invariant for the reported input and its siblings,
   with no condition keyed on that input. Class DESIGN: no single unit owns the invariant; holding it needs
   a special case, coordinated changes in two or more components, or a changed ADR, threat or acceptance
   assumption. The same invariant failing again after a fix that claimed it, or a fix adding a branch keyed
   on the reported input, is DESIGN. The reviewer proposes the class; an open disagreement counts as
   DESIGN; the author moves a class only toward DESIGN.
3. Fix risk is decision when the fix changes a decision value (PASS, FAIL, deny, allow, UNKNOWN, an exit code)
   or what feeds it (a comparison, threshold, counter), what an error path returns or skips, what is permitted
   (allowlist, mode, uid, capability, sandbox, firewall verdict), where secrets go, a test assertion, or makes
   a check fire less often (§3), and any fix that differs from the finding's stated fix; otherwise plain. The
   stricter call of the two wins.
4. One full round per checkpoint (§5 table). The author answers each finding FIXED (commit and a test failing on
   the parent, R4), DISPUTE (evidence by pointer: test and CI run, file:line, range fact and run), RESIDUAL
   (where it is recorded; never for an open CRIT or HIGH); a DESIGN finding is redesigned or disputed. A plain
   MED or LOW fix is verified by its test. CRIT and HIGH fixes, decision fixes and disputes go back to the
   reviewer in a reply round on the fix range, a normal review request whose criteria copy the findings verbatim
   and the answers: per finding confirmed, not fixed, conceded or maintained, plus new defects the fix range
   causes. One reply round per full review; one that does not close leads to a full round, or to the maintainer
   on a disagreement. A redesign, or a fix range over about 150 lines outside tests, gets a full round.
5. The author decides a redesign, with one sentence why. The maintainer decides when it changes an ADR, an
   acceptance number or a threat claim, when author and reviewer still disagree after the reply round, or when
   an invariant fails again after a redesign.
6. A missing threat-model row is a plain BUG. The pull request keeps a ledger: finding, class, risk,
   answer, commit or test. Every third checkpoint a full round covers a range that had only reply rounds.

## Alternatives considered

- Redesign by severity: a CRIT can be a one-line bug (a key printed to the journal), a MED a design flaw
  (one logger that cannot carry a reason per rule).
- A plain cap on rounds stops churn and real verification alike. A queue that holds the reply chain itself was
  reviewed twice and dropped: the author still sets each full review, so the trust it added was partial.

## Consequences

- Amends R7, §5 (its top tier asks for Codex level security), CLAUDE.md's review brief (a reply round
  carries the author's answers per finding, nothing else) and AGENTS.md's output format.
- Outside this repository the reviewers' rubrics gain these fields and the reply round; the maintainer
  installs them.
- Measured over three checkpoints: rounds per pull request, window spent, findings by class, the sampled round.
