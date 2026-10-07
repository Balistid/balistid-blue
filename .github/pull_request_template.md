## What and why

<!-- One logical change. Link the ADR or STATUS.md step it implements. -->

## Evidence (run now, output pasted or linked, not from memory)

- [ ] CI green (all required checks)
- [ ] Behaviour change has a test that fails on the parent commit, or the change has no behaviour change
- [ ] Acceptance numbers for this floor were committed before its first code commit; no `missed` result
- [ ] Attack scenario triggers and legitimate scenario does not, for every new or changed detection (R10)
- [ ] Touched `THREAT_MODEL.md` rows updated
- [ ] No host-specific data (usernames, home paths, hostnames, tokens)
- [ ] `STATUS.md` updated
- [ ] Review level per ENGINEERING.md §5 done; findings inside the change closed
- [ ] Under 100 added lines outside tests and testdata, or the reason it cannot be simpler is above

## Unchecked boxes

<!-- Every unchecked box needs one line explaining why. -->
