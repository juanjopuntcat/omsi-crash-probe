# OMSI Bug Fixability Audit

Historical 17-family audit. The complete 39-signature review plus three
additional families is now in [documented-exception-audit.md](documented-exception-audit.md).
Its uncertainty decisions supersede patch-readiness claims below. All entries,
including the three former patch candidates, are deferred.

This audit covers every bug currently shown by the GUI. It combines the clean
Ghidra project, focused RVA exports, decompilation, Delphi resource records,
import references, and linear x86 disassembly. OMSI was not launched and no
excluded content directory was scanned.

`Candidate` means that a defensible engine-side behavior is visible. It does
not mean that an applicable patch exists. A candidate may enter
`patch-manifest.json` only after its continuation path, original bytes, target
hash, offline apply, and rollback have all been verified.

## Results

| GUI bug | Ghidra result | Decision | Required proof or implementation |
| --- | --- | --- | --- |
| RS.HumansOutside null list entry (`0x002EFD03`) | Zero EAX at `CMP BYTE PTR [EAX+0x5BC],0` explains the read on a matching build. The target `0x002EFEFC` advances the index and remaining count. Writers compact removals and grow the array before storing new objects. | **Deferred.** Null-as-rejected-element is not an established contract. | Audit insertion rollback, lifetime and mutation ordering. See `ghidra-humans-review-notes.md`; do not design a trampoline yet. |
| World/UI missing numeric-field owner (`0x00428140`) | The +0x100 / +0x5C chain reads a signed integer at +0x1F0 and formats decimal text. The old string-copy interpretation was incorrect. Selection membership does not validate the child. | **Deferred.** Zero and blank text have different effects; neither is an established fallback. | Resolve field meaning, child lifetime, callbacks and UI-state recovery. See `ghidra-world-review-notes.md`. |
| AI cleanup missing map owner (`0x0042ADE3`) | Reads the map's +0x20 version field. Versions below 11 skip car cleanup to stage 12 at 0x0042AE5D. The list-head interpretation was incorrect. | **Deferred.** A missing map is not an empty vehicle list. | Resolve outer processing conditions, map lifetime and downstream dependencies. See `ghidra-ai-review-notes.md`. |
| Direct3D device lost or reset (`0x00429FD8`) | Logs DEVICENOTRESET recovery, also reached through reset_graphic_device. Unforced DEVICELOST bypasses Reset at `0x0042A386`. Local release/restoration handlers can log and continue. | **Deferred.** Neither a particular root cause nor safe recovery behavior is established. Do not force success or suppress the report. | Prove resource coverage, full parameters, thread/reentrancy and partial-failure invariants. See `ghidra-d3d-review-notes.md`. |
| Direct3D texture allocation failure (`0x0024307C`) | Texture owners call `D3DXCreateTextureFromFileExW/A`; runtime failures match `E_OUTOFMEMORY`. Release paths exist but static symmetry cannot distinguish retention, delayed cleanup, or VAS fragmentation. | **Mitigation candidate, no byte patch yet.** | Audit texture lifetime/accounting and consider bounded cache eviction or allocation fallback after ownership is proven. |
| Systemfehler Code 8 (`0x0002A000`) | This is a generic OS-error wrapper. Code 8 can reflect VAS, GDI/USER, or other resource exhaustion and is observed by several owners. | **No global patch.** Resource-pressure mitigation belongs in the failing owner. | Correlate owner, largest free VAS block, GDI/USER counts, and texture pressure before selecting a subsystem fix. |
| Invalid bitmap or image (`0x00070890`) | The anchor is the Delphi/VCL bitmap-invalid raiser. Separate paths cover unsupported extensions, invalid images, DC creation, and exhausted graphics resources. | **No global patch.** Several distinct failures share this visible family. | Identify the caller and failure class; harden a specific loader or resource allocation path only. |
| Range-check error (`0x0004DD85`) | This is an explicit Delphi range exception site; related range helpers are shared by strings, arrays, and lists. | **Never disable globally.** The exception prevents silent corruption. | Use the caller above the helper to find the invalid OMSI index/value and patch that owner. |
| List index exceeds maximum (`0x000B57F4`) | The anchor is a generic Delphi list-bounds helper with broad fan-out. A narrower OMSI list path exists at `0x00120818`. | **Never clamp globally.** | Recover a stable owner and decide whether skip, resize, or rejecting malformed input is semantically correct there. |
| Argument outside range (`0x0011FF8C`) | Hundreds of `EArgumentOutOfRangeException` sites share the same resource text; the anchor is one bounds-check cluster. | **No generic patch.** | Require an owner stack/RVA and its argument contract before proposing a guard. |
| Invalid floating-point value (`0x00024F68`) | The generic string-to-float parser has many large callers across object, vehicle, script, and texture configuration loading. | **Input validation/logging opportunity, not parser suppression.** | Capture the offending token and owning key/file, then validate or default only in that caller. |
| Floating-point division by zero (`0x00011610`) | The anchor belongs to Delphi floating-point exception machinery, not one simulation formula. | **Never suppress globally.** | Identify the owner calculation and prove a physically meaningful zero-denominator policy. |
| Stream read or write failure (`0x0004DF1C`) | The generic exact-read helper has 42 references and 16 recognized owners; related read/write helpers are similarly shared. | **No generic patch.** Returning success would consume incomplete/corrupt data. | Use the next OMSI frame and logfile load context to harden one concrete loader. |
| Invalid script variable or command (`0x001D378D`) | The script compiler intentionally reports negative lookups for variables, macros, constants, and functions. | **Correct diagnostic, normally content-side.** | Improve source diagnostics if useful; change engine behavior only for a demonstrated parser compatibility defect. |
| Map or vehicle update failure (`0x003D5374`) | This broad calculation owner includes many guarded stages; `CV.Calculate - J2` is a narrow checkpoint at `0x003D61F8`. Map translation and tile refresh are separate owners. | **Insufficiently specific.** | Split by exact checkpoint/caller and recover the invalid state before considering a guard. |
| DirectSound access violation (`0x00405D60`) | The loader validates WAV chunks, creates and locks DirectSound buffers through COM vtables, and has explicit HRESULT error paths. A DLL AV can still arise from a null/stale interface or buffer. | **Owner-specific hardening possible, not yet localized.** | Map the public `DSound.dll` fault to the preceding OMSI call and prove which interface/buffer lifetime failed. |
| External exception C06D007E (`0x00028E06`) | The anchor is Delphi's external-exception constructor. `C06D007E` commonly crosses a native dependency/delayed-import boundary; the constructor is only formatting it. | **External boundary; do not patch the constructor.** | Record the throwing module and caller, then repair dependency loading or isolate the specific optional component. |

## Current Patch Boundary

HumansOutside, World/UI and AI cleanup remain research hypotheses. The missing
proof is semantic, not merely a limitation of the patch transport. A trampoline
or successful offline apply/rollback cannot establish whether skipping a null
entry or substituting an empty string is valid. Resolve the uncertainties in
the complete audit before doing further patch engineering for these cases.

The remaining bugs still matter, but most should produce owner-specific fixes,
resource-policy mitigations, or better diagnostics. Patching their shared
Delphi exception helpers, forcing HRESULT success, or ignoring failed reads
would hide corruption and make OMSI less reliable.
