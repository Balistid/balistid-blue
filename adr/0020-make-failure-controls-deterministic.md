# 0020 — Make the failure controls deterministic

- Status: proposed (accepted when merged with the maintainer's approval)
- Date: 2026-10-12
- Decided-by: alex
- Agent: claude/opus-5.5

## Context

Review of the failure trials (#101) found that a failure control could give its expected verdict for the wrong
reason. Kernel writeback could save what a last-sync control did not sync. A fail mark that left late carried an H
older than the failure. A writer that had already died could pass for one SIGKILL ended. Synced records above H
could vanish under a PASS, and the writer kept syncing while the mark left, so S lagged what was synced. And the
stop-sync moment was counted from a different start than the load.

## Decision

1. During a failure trial the guest keeps the kernel from writing the scratch disk on its own: it sets
   `vm.dirty_writeback_centisecs=0` and `vm.dirty_expire_centisecs=360000` and mounts it with `commit=300`.
   Without memory pressure (`dirty_background_ratio`; a trial writes well under a megabyte in 2 GiB) only fsync
   puts data on it; the KVM check confirms this.
2. The load, the failure moment and the stop-sync moment share one start. The guest tells the writer when to stop
   syncing on its own clock.
3. Before the fail mark the guest freezes the writer: it answers with its final S and then writes, syncs and
   reports nothing more, so S is exactly what an fsync covered when the failure comes. A writer that does not
   answer within a second, or ends before the failure, is a trial error.
4. H describes the moment it is taken: if the fail mark has not left the console within 100 ms of it, the guest
   reports a trial error instead of failing (INVALID). A kill counts only if SIGKILL ended the writer; a writer that
   ended otherwise, or whose sync reports broke, is a trial error.
5. Every number up to the larger of H and S must survive, else MISS. ADR 0019 point 3 stands for S below H.

## Consequences

- Amends ADR 0018 point 3 and ADR 0019 point 3. These rules hold in the VM only, and only for failure trials. The
  KVM check verifies them on the reference host.
