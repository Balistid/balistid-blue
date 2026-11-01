# 0042 — The maintainer approves gate changes on the summary and the verdicts

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-01
- Decided-by: alex
- Agent: claude/opus-5.5
- Amends ADR 0001's Consequences (the maintainer's line-by-line review of gate changes)

## Context

ADR 0001 says the maintainer reviews every change to `tools/ci/`, `.github/`, `githooks/`, `.gitleaks.toml`
and `.gitattributes` line by line, and that this review stops a determined author of gate code. On 2026-11-01
the maintainer said he does not read them so: he approves an owned pull request on the agent's two-sentence
summary (`CLAUDE.md`) and the reviewers' verdicts in its body. Reviewer briefs had named his reading as the
boundary (#184), so they counted a control that does not run.

## Decision

1. A code owner's approval means the maintainer read the summary, the verdicts and the open findings, and
   accepts the residuals. It is not a line read; no ADR, threat model row or reviewer brief counts it as one.
2. A change to a gate therefore gets one independent review per checkpoint, an Opus critic, as ENGINEERING §5
   asks for a security-relevant gate; its brief names no human reading as a boundary. Codex security stays where
   ENGINEERING §5 puts it (root impact, signing, install path, architecture) and on product security checkpoints.
3. When a few lines decide a gate change (a permission, a trigger, a removed or loosened check), the pull request
   body quotes them for the maintainer, so the approval rests on what will run.

## Alternatives considered

- The maintainer reads every gate diff line by line: what ADR 0001 assumed, not what happens.
- No independent review on gate changes: the bot could weaken a gate under an approval that rests only on its
  own summary.

## Consequences

- An agent that weakens a gate under a misleading summary is stopped by the critic and the gate tests, not by
  the approval; a critic can miss it. This residual stays here, as gates are outside THREAT_MODEL's recorder.
- Each gate checkpoint costs one Opus critic; a Codex round on a gate change needs one of point 2's reasons.
