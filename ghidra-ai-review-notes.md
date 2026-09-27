# AI Cleanup Review: H05 and H29 Context

Reviewed 2026-09-27 with Ghidra 12.1.2 in read-only mode and MSVC dumpbin.
**Deferred; no approved fix.** The old "missing list head" interpretation is
withdrawn: the fault reads the map object's version field, not a list count.

Installed Omsi.exe SHA-256:
`7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759`.
Image base: `0x00400000`. Addresses below are RVAs unless marked VA.
The public reporter's binary hash and original fault state are unavailable.

## Owner and Field Identification

VA `0x00859D94` holds VA `0x00861588`, the storage for the current map
pointer. It is not a linked-list head established by the extra indirection.
The recognized storage writes provide lifecycle evidence:

- `0x002E6053`: stores the result of constructor `0x00385ADC` during
  `0x002E5C0C`. Nearby messages say `Map created` and `Map loaded`; loading
  calls parser `0x003860B0` on this object.
- `0x002E5979`: the map-closing path passes the object to disposal helper
  `0x00006B0C`, then explicitly clears its storage at `0x002E5985`.
- Parser `0x003860B0` compares a token with `[version]`, parses the following
  value and stores it at object+0x20 at `0x003871D3`. This identifies the
  field tested at the public fault. The parser also contains `TMap.loadGlobalFile`
  diagnostics. Decompiler class/type guesses are not required for this link.

These are the two WRITE references to the storage recognized by this model,
not a proof that all possible indirect writes have been enumerated. A null
map is an explicit lifecycle state; it has not been shown to be valid at this
particular frame-processing stage.

## Corrected Stage Flow

The fault region is undefined in the Ghidra function model. Linear decoding
of the bytes and explicit branch targets gives the following local sequence:

| RVA | Observation |
| --- | --- |
| `0x0042AD48` | Tests a separate flag through VA 0x00859E30; a nonzero value skips both cleanup stages to 0x0042AE5D. The flag's meaning is unresolved. |
| `0x0042AD56` | Writes stage value 10 through VA 0x00859538 (storage VA 0x0086290C). |
| `0x0042AD74` | Calls 0x002FE6F8 with the object at VA 0x00862F28. Its exception handler appends `: P.KillNotNeededBuses`. |
| `0x0042ADD1` | Writes stage value 11, after bus cleanup and its local handler. |
| `0x0042ADDC` | Loads the map slot and dereferences it. |
| `0x0042ADE3` | `CMP DWORD PTR [EAX+0x20],0x0B`. Zero map pointer explains read address 0x20 on a matching build. |
| `0x0042ADE7` | Signed less-than branch to 0x0042AE5D when map version is below 11. No null-map guard precedes the comparison. |
| `0x0042ADFC` | Otherwise calls 0x002FE85C with the object at VA 0x00862F28. Its local handler appends `: P.KillNotNeededCars`; the string pointer operand is at 0x0042AE2C. |
| `0x0042AE5D` | Writes stage value 12 and starts a different protected operation, calling 0x00246764 at 0x0042AE7B with the object at VA 0x00862F2C. It is after car cleanup, not its entry. |

The comparison occurs before the car operation's local exception frame is
installed. Its AV is therefore not caught by that frame. The bus frame has
already been removed. The containing outer routine and all its recovery
paths are not fully reconstructed in this pass.

The bus wrapper at 0x002FE6F8 gates work through helper 0x00405C78 (argument
0x4E), dispatches a callback via 0x0034C344 and calls 0x0034A630 on the
collection reached through VA 0x00858D28. The car wrapper at 0x002FE85C uses
the same gate, dispatches callback 0x002FE73C and calls 0x0034A630 on the
collection reached through VA 0x00859D88. These collection slots are distinct
from the map pointer that faults.

The next-stage callee's decoded prefix reads UI flags and, conditionally,
its own argument+0x108. Its complete purpose and downstream map dependencies
are unresolved. A null-map branch to stage 12 would only avoid the current
read; it does not prove subsequent work or skipped cleanup is safe.

## H29: P.KNNC.KM Is Present

The byte window at 0x002FE9BC contains UTF-16 `: P.KNNC.KM` followed by a
terminator. It remains undefined as a string in this Ghidra model, explaining
why the defined-string search missed it.

The car wrapper's inner exception handler starts at 0x002FE8E7 and loads
that string at 0x002FE8EF (pointer operand 0x002FE8F0). The protected region
logs a checkpoint and calls 0x0034A630 at 0x002FE8C7. The callee contains
`Kill marked: List locked` diagnostics and substantial collection/object
cleanup. The handler's label covers the protected region, not exclusively
one allocator or one instruction in that callee.

This locates H29's diagnostic context, **not its out-of-memory fault site**.
The GUI retains RVA zero for the unknown fault and labels the context anchor
explicitly. There is no evidence that H29 and H05 have the same root cause.

## Decision and Remaining Doubts

Keep H05 deferred and rename it "AI cleanup missing map owner". Preserve the
stable candidate ID `omsi-ai-cleanup-null-list-head` for compatibility.
The old proposal "null head means no vehicles, skip cleanup" has no basis
in the recovered field or object identity.

- Resolve how map lifetime is coordinated with the outer processing routine,
  especially failed loading, closing and callbacks. A race is not demonstrated.
- Reconstruct outer entry conditions and later stages before deciding what
  a null map should do. Map version below 11 is not equivalent to no map.
- Prove the flag and stage-marker obligations, and the cleanup that would be
  skipped by any proposed recovery branch.
- For H29, identify the actual failing allocation and resource pressure;
  a diagnostic context alone cannot justify suppressing the exception.
- Match the original public fault to its executable build.

Proceed to H10-H14 / Direct3D after recording these questions. No additional
game session is requested.

## Reproduction and Limits

Run `Run-GhidraAiReview.ps1`, optionally providing `-DumpbinPath` to reproduce
the hash-checked linear excerpts. Nine requests intentionally include five
defined functions and four `missing-function` records (fault, bus wrapper,
car wrapper and next-stage callee). Generated exports remain git-ignored.
The parser may take noticeably longer than the other decompilations.

The script reads the existing project without reimporting or repairing it;
it does not authenticate an arbitrary replacement Ghidra project. Linear
output includes exception tables at 0x0042AD88-0x0042AD93,
0x0042AE10-0x0042AE1B and 0x002FE8DB-0x002FE8E6. Those bytes and any decoder
instructions spanning them are data, not control flow. The car handler is
also exported separately from its exact entry to avoid that ambiguity.

No game file was modified, OMSI was not launched, and no excluded content,
Addons or SDK folder was read.
