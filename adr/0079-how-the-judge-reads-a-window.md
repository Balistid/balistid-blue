# 0079 — How the judge reads a window

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-18
- Decided-by: jvc0n (2026-11-18, in session)
- Agent: claude/opus-5.5
- Amends ADR 0077 points 1-4 and 6 (what they left open), ADR 0078 point 3, and the layout's cap for `lab/`.

## Context

Before code, a design review of ADR 0077 and 0078 against the runner at 2c09799 and the window of hard-exec-1 found
readings the two leave open: which files a window holds, what a rule's leaf compares, when an event is the job's,
how the job's name binds content, and how big `lab/` may grow. Two implementations of the judge could disagree on
each, and each could hide a false verdict. Laurel repeats `pid` with the same value inside `SPAWNED_BY` (7 of the 10
records of hard-exec-1), so refusing every repeated key would refuse every window.

## Decision

1. The judge re-implements the runner's contract (escape, content key, result fields, names) and imports no runner
   package: the judge is locked after B1 and the runner has another owner. Tests pin that contract to real bytes:
   hard-exec-1's escaped records and result (ADR 0078 point 3) and its content key.
2. A window holds every file the runner wrote for that result, under the same names, and `verify` compares the
   whole set and each file's bytes. A result with no `job-laurel.txt` (a run, a trial, a failed job) is imported
   all the same and is INVALID for detection.
3. Decoding: `job-laurel.txt` is the runner's escape of the records (bytes 0x20-0x7e but `\` and `"` as they are,
   every other byte `\x` and two lower-case hex digits); it is valid only if escaping its decoding gives the file
   back. Each line decodes as one JSON object of valid UTF-8; a key repeated in one object with a different value
   is INVALID, with the same value it is kept once. Pairs, rules and results decode with exact keys and their closed
   sets; an integer is a JSON number without fraction or exponent. Pairs and rules are printable ASCII and LF only.
4. A leaf's `field` is a list of object keys from the event's top. A step that meets a list goes into each element,
   and a leaf holds if some element holds. `eq` compares a string with a string and an integer with an integer, so
   `"59"` is not `59`; `contains` takes strings only; `has` holds if the path reaches a value that is not null and
   not an empty list. A path that does not reach a value makes the leaf false. A rule with an unknown op, `has` with
   a value, `eq` or `contains` without one, or both `all` and `any`, is INVALID.
5. An event is the job's when its `SYSCALL.UID` is `balistid-job`. A window whose program exec has the job's numeric
   `uid` under another name, or the name under another number, is INVALID, and so is one whose canary (root's
   `/usr/bin/true balistid-canary-<32 hex>`) does not come after the program's exec: before it, Laurel may not
   have written the job's records.
6. The job's name binds `lab/pairs/<pair>.json` and every `lab/rules/<pair>/*.json`: paths relative to `lab/`, in
   byte order, each path and its bytes prefixed by a big-endian 64-bit length, sha256, the first 32 hex digits. A
   pair's runs are `tech-a`, `tech-b`, `twin-a` and `twin-b`. A known image is its commit and its image sha256 both.
7. The base fixture of ADR 0078 point 3 takes a result id after the anchor, as no real result before it can be valid;
   its records, request and program are hard-exec-1's, so its content key and program sha256 are the real ones.
8. `lab/` holds at most 16 MiB in any commit (R5): 23 windows of the largest size would not fit, so `import` prints
   the size and the session stops before the cap. `table` writes nothing; how `lab/results/` binds to its output is
   decided with the report.

## Alternatives considered

- Import `rangerun` to read results: no drift today, but the locked judge would follow code another owner changes.
- Refuse every repeated key: no window of Laurel 0.8.2 would be valid (noted for upstream).

## Consequences

- `internal/detect` and `cmd/balistid-lab` follow this; each point has a fixture that breaks only it.
- The layout gate's 16 MiB cap and the decoded scan of `job-laurel.txt` land in their own `ci:` pull request.
- Revert: with the code it describes.
