# Static Research TODO

Updated 2026-09-27. Reviewed means a bounded static pass is documented; it does
not mean the fault is fixed or that its lifetime/recovery contract is proven.
No game launch is needed for the current queue.

## First Passes

- [x] H02 / 006421CE: follow the callee, input string and destination context.
  Situation-file write chain mapped; reported read from 0x28 remains unexplained.
- [x] H21 / POI.GHAA - C: inspect the fault routine and recognized callers.
  Geometry/normal calculation identified; pointer lifetime remains unresolved.
- [ ] H06 / RS.HumansOutside: establish null-entry semantics and loop obligations.
- [ ] H23 / World/UI: establish missing-child semantics and string/UI invariants.
- [ ] H05 / AI cleanup: resolve the global owner and exact cleanup continuations.
- [ ] H10-H14 / Direct3D: reconstruct lost/reset state and resource lifecycle.
- [ ] External modules: consolidate required hashes, load bases and fault contexts.

## Deferred Questions

- [ ] H02: reconcile the original exception record and binary identity with the
  local direct CALL and serialization chain before choosing any candidate change.
- [ ] H21: identify the +0xA0 owner, field writers, lifetime and synchronization;
  prove lock/unlock and output obligations before proposing recovery behavior.

## Integration

- [x] Record the first two passes in `ghidra-owner-review-notes.md` and update
  their descriptions in the compiled GUI catalog and full exception audit.
- [x] Reproduce the focused export: all ten decompilations completed.
- [x] Compile the updated x86 GUI without warnings.
- [x] Review this iteration's diff for publication; commits are tracked in Git.

Any unresolved doubt keeps the affected case deferred. Move to the next case
after recording the evidence and what would be needed to reopen it.
