# Public access-violation address analysis

The 2026-09-27 review in [documented-exception-audit.md](documented-exception-audit.md)
supersedes the patch-candidate judgments below. All candidates are deferred;
public reports lack executable hashes, and the correct recovery semantics
remain unresolved. A RET does not prove damaged return state, and the clean
Ghidra listing does not yet decode RVA 0x00429C09 as an instruction.

These notes correlate public OMSI error addresses with the locally analysed
32-bit executable. Absolute addresses assume image base `0x00400000`. They are
diagnostic evidence, not permission to patch an arbitrary OMSI build.

| Public address | RVA | Static finding | Patch status |
|---|---:|---|---|
| `0x006EFD03` | `0x002EFD03` | An array lookup returns `EAX`; `CMP BYTE PTR [EAX+0x5BC],0` follows without an element-null guard. Zero EAX explains read address `0x5BC` on a matching build. | Deferred: advance block mapped, but null validity and insertion rollback are unresolved. See `ghidra-humans-review-notes.md`. |
| `0x00828140` | `0x00428140` | The +0x100 / +0x5C chain reads a signed integer at +0x1F0 and formats decimal text. A null child explains read address 0x1F0 on a matching build. Later parent accesses do not prove lifetime. | Deferred: the earlier string-copy/empty-text recommendation is withdrawn. See `ghidra-world-review-notes.md`. |
| `0x0082ADE3` | `0x0042ADE3` | Compares current map version at +0x20 with 11 after bus cleanup, before car cleanup. A null map explains read address 0x20 on a matching build. | Deferred: skipping to stage 12 is not proven safe without a map. See `ghidra-ai-review-notes.md`. |
| `0x007C400E` | `0x003C400E` | Triangle-normal calculation reloads the mesh-like interface at owner+0xA0 after a buffer call, then reads its vtable. Earlier null checks exist; lock results and output obligations need review. | Deferred: lifetime, lock cleanup and caller output validity are unresolved. See `ghidra-owner-review-notes.md`. |
| `0x005D49B0` | `0x001D49B0` | The reported address is a `RET`, consistent with damaged return state rather than a failing field access. | Do not patch the `RET`; find the corrupting caller. |
| `0x00829C09` | `0x00429C09` | Floating-point update reads object field `+0x304` through a stale-looking pointer. | Insufficient evidence for a safe guard. |
| `0x006421CE` | `0x002421CE` | Direct call to a nested line writer in situation-file serialization; string and destination context are traced through the I/O helper. | Deferred: the local instruction path does not explain the public read from 0x28. See `ghidra-owner-review-notes.md`. |

The low helpers at RVAs `0x00006B14`, `0x00006E6C`, and `0x00008850` are
shared Delphi object/string machinery. Their public failures indicate null,
stale, or mistyped values supplied by callers. Globally changing these helpers
would affect many unrelated systems and is therefore rejected as a patch
strategy.

## Promotion rule

A candidate becomes an applicable patch only after we have an exact target
build hash, PE identity, complete original bytes, same-length replacement bytes,
a justified continuation path, and an offline test of apply and rollback. Until
then it remains analysis documentation and must not enter `patch-manifest.json`.

Research state is mirrored in `patch-candidates.json` so tooling and the future
GUI can display it without treating candidates as applicable patches.
