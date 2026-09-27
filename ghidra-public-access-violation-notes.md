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
| `0x006EFD03` | `0x002EFD03` | A list lookup returns `EAX`; `CMP BYTE PTR [EAX+0x5BC],0` follows without a local null guard. Read address `0x5BC` proves a null element in the reported case (`RS.HumansOutside`). | Strong candidate for an owner-specific null guard. |
| `0x00828140` | `0x00428140` | A global object chain reads `+0x100`, then `+0x5C`, then `+0x1F0`. Read address `0x1F0` identifies a null `+0x5C` subobject. The resulting string updates one UI control; subsequent controls still read valid fields from the `+0x100` parent. | Strong candidate for substituting an empty string through a trampoline; do not skip the remaining parent-object updates. |
| `0x0082ADE3` | `0x0042ADE3` | AI cleanup loads a global owner, dereferences its head, then compares `[head+0x20]` without a visible local guard. | Strong candidate near `P.KillNotNeededBuses`; determine the correct skip target first. |
| `0x007C400E` | `0x003C400E` | Object-owned list entry is dereferenced before a virtual call. Existing entry checks do not establish that the selected object is still valid. | Candidate only after lifetime analysis. |
| `0x005D49B0` | `0x001D49B0` | The reported address is a `RET`, consistent with damaged return state rather than a failing field access. | Do not patch the `RET`; find the corrupting caller. |
| `0x00829C09` | `0x00429C09` | Floating-point update reads object field `+0x304` through a stale-looking pointer. | Insufficient evidence for a safe guard. |
| `0x006421CE` | `0x002421CE` | Call inside the vehicle/script state and string-variable path. | Resolve the callee and owning input before proposing a patch. |

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
