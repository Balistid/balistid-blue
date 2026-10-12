# 0020 — Make the failure controls deterministic

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-12
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Review of the failure trials (#101) found that a failure control could give its expected verdict for the wrong
reason. Kernel writeback could save what a last-sync control did not sync. A fail mark that left late carried an H
older than the failure. A writer that had already died could pass for one SIGKILL ended. Synced records above H
could vanish under a PASS. And the stop-sync moment was counted from a different start than the load.

## Decision

1. During a failure trial the guest's scratch disk gets data only from fsync: the guest sets
   `vm.dirty_writeback_centisecs=0` and `vm.dirty_expire_centisecs=360000` and mounts it with `commit=300`.
2. The load, the failure moment and the stop-sync moment share one start. The guest tells the writer when to stop
   syncing on its own clock.
3. H describes the moment it is taken: if the fail mark has not left the console within 100 ms of it, the guest
   reports a trial error instead of failing (INVALID). A kill counts only if SIGKILL ended the writer; a writer that
   ended otherwise, or whose sync reports broke, is a trial error.
4. Every number up to the larger of H and S must survive, else MISS. ADR 0019 point 3 stands for S below H.

## Consequences

- Amends ADR 0018 point 3 and ADR 0019 point 3. These rules hold in the VM only, and only for failure trials. The
  KVM check verifies them on the reference host.
