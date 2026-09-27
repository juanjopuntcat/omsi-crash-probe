# Owner Review: H02 and H21

Reviewed 2026-09-27 using Ghidra 12.1.2 in read-only mode. These are the first
two investigations from `research-todo.md`. Both remain deferred. The findings
refine the execution paths; they do not establish safe replacement behavior.

Installed Omsi.exe SHA-256 remains
`7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759`.
Comparisons with public addresses assume this build and image base 0x00400000;
the reporters' original executable hashes and exception records are unavailable.
Decompiler types and Delphi calling conventions are treated as hypotheses and
cross-checked against instruction exports.

## H02: 006421CE, Read From 00000028

### Recovered Chain

The following are RVAs, not absolute addresses:

| RVA | Observation |
| --- | --- |
| `0x002427B8` | Outer routine writes a structured situation file. Literals include `test.osn`, `[name]`, `[map]`, `[egopos]`, `[myvehicle]` and `[view]`. It creates a stack-local file record and passes it as callback context. |
| `0x00242CF7` | Loads callback address `0x00641C38`; this reference is a function-pointer argument, not a direct call. |
| `0x0034C4F8` | Iterates a collection and calls that callback with the element in EAX, index in EDX and context in ECX. The indirect call is at `0x0034C552`. |
| `0x00241C38` | Callback saves the incoming context in its frame at EBP-4. It emits vehicle data through a nested writer. |
| `0x002421CE` | Direct CALL to absolute address `0x00641BEC`. The preceding code converts an integer to a string and loads the resulting string into EAX. The caller's EBP was pushed as the nested routine's frame link. |
| `0x00241BEC` | Retains the string, retrieves the parent's EBP-4 destination through the frame link, and passes destination/string in EAX/EDX to `0x003EFA4C`. |
| `0x003EFA4C` | Iterates UTF-16 code units and writes them, followed by CR and LF. Null input is explicitly handled as an empty line. |
| `0x000052C0` | Write wrapper forwarding to `0x00005210` with operation parameters. |
| `0x00005210` | Checks file-record mode at +4, uses record size at +8 and handle at +0, invokes the low-level operation, and checks its result. |
| `0x00002888` | Ghidra identifies this operation's import thunk as `WriteFile`; the export confirms the indirect jump through its import slot. |

The xref export finds 44 direct calls to `0x00241BEC`, all in the same
`0x00241C38` owner. The lower line writer and write wrapper are broadly shared
(421 and 75 references respectively in this Ghidra model), so their behavior
cannot be changed only for this report by patching the common helpers.

### What This Resolves

The immediate path is situation-file serialization, rather than evidence of
a script-variable lookup failing at +0x28. The nested writer's source string
and destination context can now be traced through the register/frame chain.
Null string input is already accepted on the identified normal path.

### Remaining Doubts and Decision

- The exact reported instruction is a direct CALL on this build, not a field
  read at +0x28. Neither that fact nor the recovered helper chain reproduces
  the public exception's address pair.
- No register snapshot or original binary proves that the report corresponds
  to this code layout. A different build, reported caller location or damaged
  state remain possibilities, not conclusions.
- A stack-local destination is passed through the visible dispatcher; there
  is no demonstrated missing-null check to fix at the reported CALL.
- Silently dropping a line would change the saved situation. Its format and
  recovery contract do not justify that behavior.

**Decision: deferred.** Do not replace the CALL or modify shared string/I/O
helpers. Further work needs matching-build fault evidence that reconciles the
reported address and read target. No new game session is required or requested
as part of this static review.

## H21: POI.GHAA - C / 007C400E

### Corrected Owner Identification

`FUN_007C3FA8` at RVA `0x003C3FA8` reads a triangle's indices and vertices,
optionally transforms coordinates, then subtracts vectors, computes a cross
product and normalizes the result. Calling it an object-list lookup was too
imprecise. It is a geometry/normal calculation using an interface at owner+0xA0.

The vtable calls are consistent with an ID3DXBaseMesh-style interface: face and
vertex counts, options, index/vertex buffer locks and unlocks. This interface
identification is an inference from the sequence and data use; method names
are not symbols recovered from the indirect calls. Microsoft's
[ID3DXBaseMesh documentation](https://learn.microsoft.com/en-us/windows/win32/direct3d9/id3dxbasemesh)
provides the corresponding API contract.

### Instruction Evidence

| RVA | Observation |
| --- | --- |
| `0x003C3FBB` | Tests owner+0xA0 for null and exits if absent. |
| `0x003C3FCF` | Reads the interface vtable before a call at slot +0x18. |
| `0x003C3FEA` | Calls slot +0x10, then checks the supplied face index against the result. |
| `0x003C4004` | Calls slot +0x44 with flag 0x10 and a pointer to local EBP-8, consistent with an index-buffer lock. |
| `0x003C4007` | Reloads the interface from owner+0xA0, overwriting the preceding call's return value. |
| `0x003C400E` | Reads `[EAX]` before the slot +0x24 call. This is the reported null-read site. |
| `0x003C4023` | Tests the returned buffer pointer on the 32-bit-index branch; the other branch has its own buffer test. |
| `0x003C40E8` | Calls slot +0x3C with the same local output slot, consistent with a vertex-buffer lock. |
| `0x003C40EB` | Tests the output pointer, without checking the return HRESULT. |
| `0x003C4111` | Uses a vertex stride of 0x28 before copying each vertex record. |

Thus the interface is checked earlier but reloaded after an indirect call.
On a matching build, the null read at 007C400E means that this later reload
produced zero. The static path does not show who changed the field or prove
that concurrency, reentrancy, corruption, or a different build is responsible.

The lock-like calls' return values are not checked. The local buffer slot is
not explicitly initialized at function entry and is reused for both locks.
The vertex-lock path tests the pointer left in that slot; this is a separate
failure-path concern, not proof of the reported null-interface AV's cause.

Microsoft documents that
[LockIndexBuffer](https://learn.microsoft.com/en-us/windows/win32/direct3d9/id3dxbasemesh--lockindexbuffer)
and
[LockVertexBuffer](https://learn.microsoft.com/en-us/windows/win32/direct3d9/id3dxbasemesh--lockvertexbuffer)
return HRESULTs and require matching unlocks. This is why inserting a return
after an attempted lock requires proving both acquisition state and cleanup.

### Callers and Output Obligations

Three direct caller sites are present in the current reference model:

- `0x003BAB9D` in owner `0x003BA930`: a path-deformation calculation uses the
  resulting vector, including components in later divisions.
- `0x003A074B` in owner `0x003A03F8`: tile-collision code copies the returned
  vector to its output and transforms it.
- `0x003AB7BE`: containing function is not defined in the clean database;
  surrounding instructions also copy three output components after the call.

The routine has existing early exits, but that does not prove another exit is
safe. The visible callers consume the output without a newly added success
indicator. Returning zero, leaving output untouched, or skipping an unlock
requires a caller-specific contract that is not established here.

The POI.GHAA - C log pointer remains at RVA `0x003AEEDC`, separate from the
fault RVA. A complete call chain linking that diagnostic context to this
routine is not yet established.

### Remaining Doubts and Decision

- The exact class owning +0xA0, all writers to that field, its reference-count
  ownership and synchronization are not resolved.
- The interface's original DLL implementation and the public build are not
  identified; the COM method naming remains a well-supported inference.
- Lock failure, cleanup obligations and caller output validity must be proved
  together before designing a guard or buffer-error fix.

**Decision: deferred.** Retain the null-interface observation and unchecked
lock-result concern as separate findings. Do not install a null-skip patch.

## Reproduction and Boundaries

Run `Run-GhidraOwnerReview.ps1`. It exports ten decompilations, focused
instruction windows and references from the existing OmsiStatic project using
`-readOnly -noanalysis`. Outputs remain local and git-ignored:

- `ghidra-decompile-owner-review.tsv` and `ghidra-decompile-owner-review/`
- `ghidra-owner-review-context.tsv`
- `ghidra-owner-review-callers.tsv`

The stored project was not reimported or repaired at undefined addresses.
No game binary was patched, no game session was started, and none of the
excluded content, Addons or SDK directories was read.
