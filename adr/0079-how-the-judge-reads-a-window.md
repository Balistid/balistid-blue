# 0079 — How the judge reads a window

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-11-18
- Decided-by: jvc0n (2026-11-18, in session)
- Agent: claude/opus-5.5
- Amends ADR 0077 points 1-6 (what they left open), ADR 0078 point 3, and the layout's cap for `lab/`.

## Context

Reviews of ADR 0077 and 0078 against the runner at 2c09799 and hard-exec-1's window, and of the code, found
readings both leave open (window files, leaves, proof the job ran, binding, counting, read bounds); two judges could
differ on each and hide a false verdict. Laurel repeats `pid` with the same value in `SPAWNED_BY` (7 of 10 records).

## Decision

1. The judge re-implements the runner's contract (escape, content key, result shape and types, names) and imports
   no runner package, as it is locked after B1 and the runner has another owner; tests pin the contract to
   hard-exec-1's real bytes. It reads through `internal/wholefile`, which joins its lock.
2. A window holds every file the runner wrote for the result, under its name; `verify` compares the sets both ways
   and each file's bytes, and a missing window is a finding even against an empty result. A result with no
   `job-laurel.txt` (a run, a trial, a failed job) is imported all the same and is INVALID.
3. `job-laurel.txt` is the runner's escape (0x20-0x7e but `\` and `"` as they are, other bytes `\x` and two
   lower-case hex digits) and valid only if escaping its decoding gives it back. Each line is one JSON object of
   valid UTF-8; a key repeated with another value is INVALID, with the same value kept once. Pairs, rules and
   results decode with exact keys, closed sets and the runner's types; an integer of these has no fraction,
   exponent or `-0`. Pairs and rules are printable ASCII and LF; a rule's `brief_sha256` is its pair's brief's.
4. A leaf's `field` is a list of keys; a step that meets a list goes into each element, and a leaf holds if some
   value reached holds. At the path's end, `has` holds on a value that is not null and not an empty list (a list
   is the value); `eq` and `contains` test each element of a final list. `eq` compares strings as strings and
   integers by value, so `"59"` is not `59` and `-0` in a record is `0`; `contains` takes strings only.
5. An event is the job's when `SYSCALL.UID` is `balistid-job`, and its `SYSCALL.uid` must then be the uid the image
   gives that user (970 in 2c09799), as on every other event. The program's exec and the canary's
   (`/usr/bin/true balistid-canary-<32 hex>` as root, its `exe` `/usr/bin/true`) are each an `execve` (59) with
   `success` yes and exit 0, the canary after the program: before it, Laurel may not have written the job's records.
6. The name binds `lab/pairs/<pair>.json` and every `lab/rules/<pair>/*`: paths relative to `lab/` in byte order,
   each path and its bytes prefixed by a big-endian 64-bit length, sha256, the first 32 hex digits. The runs are
   `tech-a`, `tech-b`, `twin-a`, `twin-b`. A result is judged only from a known runner commit and a known image
   (commit, sha256 and job uid), and its id ends in its job's name.
7. The base fixture of ADR 0078 point 3 takes an id after the anchor; its records, request and program are real.
8. A pair counts only if no window in `lab/` ran other content of it (T39: a rule changed after a run). A rule is
   scored on another pair's valid window only if that window came after its own pair's first, so the rule was bound
   before it existed; this holds whether either pair counts.
9. Reads are bounded (R5): `lab/` holds at most 16 MiB, read or written, and 4096 names a directory; a file over its
   own cap makes its window, pair or rule INVALID with its reason. Directories are opened one name at a time and
   never through a link. `verify` and `import` read the runner's results only as a directory the caller neither owns
   nor can write (R13); `verify` lists them before and after and prints a sha256 of what it compared and the rules'
   version. `import` and `job` publish a directory whole; `job` refuses the runner's inbox, which spends quota on a
   half-written job. `table` writes nothing; how `lab/results/` binds to it is decided with the report.

## Alternatives considered

- Import `rangerun` (the locked judge would follow another owner's code); refuse every repeated key (no window of
  Laurel 0.8.2 would be valid).

## Consequences

- Each point has a fixture breaking only it. Not closed: a result added while `verify` reads is seen only by its
  second listing; host root and its clock (ADR 0077 point 8). The layout cap and the scan of every window file land
  in their own `ci:` pull request, before any window. Revert: with the code it describes.
