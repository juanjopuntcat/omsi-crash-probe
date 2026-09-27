# Documented Exception Audit

Reviewed 2026-09-27. This is the complete reconciliation of the user's 39
reported signatures with the GUI catalog, plus three previously documented
families (E01-E03). It supersedes the patch-readiness conclusions of the
earlier 17-row audit.

## Decision

All 42 entries are deferred. No proposed game fix is approved. Every case below
has an explicit unresolved question, including the three earlier null-guard
candidates. High evidence confidence means a local instruction or diagnostic
has been identified; it does not establish the root cause, correct recovery,
or safety of a proposed patch.

A null dereference does not by itself justify skipping an object. A log
checkpoint is not necessarily the faulting instruction. A reporting helper is
not the owner that supplied invalid state. Offline apply/rollback tests prove
patch transport behavior, not simulation correctness.

The rule for this project is to document each remaining doubt and move to the
next case. Patch work may resume for a case only once those doubts have been
resolved with evidence. Absolute certainty about arbitrary executions cannot
be established merely by recognizing instructions in a disassembler.

## Scope and Provenance

- Installed Omsi.exe SHA-256:
  `7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759`.
- Local Ghidra 12.1.2 project: OmsiStatic / Omsi.exe, processed with
  `-readOnly -noanalysis`. The game was not started or modified.
- Fresh exports: `ghidra-history-20260927-rva-context.tsv` and
  `ghidra-history-20260927-string-xrefs.tsv` (local, ignored by git).
  `Run-GhidraHistoryAudit.ps1` reproduces the focused pass, writing undated
  `ghidra-history-*.tsv` outputs.
- Prior evidence: `ghidra-public-access-violation-notes.md`,
  `ghidra-range-list-notes.md`, `ghidra-memory-bitmap-notes.md`,
  `ghidra-texture-memory-notes.md`, `ghidra-weak-bucket-notes.md`,
  `ghidra-script-parser-notes.md`, `ghidra-stream-callers-notes.md`.
- Public Omsi.exe absolute addresses are compared using image base 0x00400000.
  The reporters' binary hashes are unknown, so local matches remain conditional.
- DLL addresses lack the reporters' module versions and load bases. This audit
  does not claim to have mapped or decompiled those fault sites in DSound.dll,
  d3d9.dll or nvd3dum.dll.
- The string exporter searches defined strings and pointer references. A
  missing result is not proof that a literal or code path does not exist.
- SceneryObjects, Splines, maps, OmniNavigation, Vehicles, Addons and SDK were
  excluded. No asset content was inspected.

## Full History Reconciliation

Each H identifier corresponds to one original line, in its original order.
Reported spelling is preserved. Context variants remain distinct even when
they use the same helper or error formatter.

### H01: DirectSound AV at 6738C862

Reported:

> Zugriffsverletzung bei Addresse 6738C862 in Modul 'DSound.dll'. Lesen von Adresse 00000000.

Evidence: The OMSI WAV/DirectSound loader is mapped at RVA 0x00405D60 (context only).

Unresolved: The reported DLL build, load base, registers and caller are unknown; the DLL address cannot be mapped to this OMSI RVA.

Decision: **Deferred; no approved fix.**

### H02: Omsi AV at 006421CE

Reported:

> Zugriffsverletzung bei Addresse 006421CE in Modul 'Omsi.exe'. Lesen von Adresse 00000028.

Evidence: The direct CALL reaches a nested line writer in a situation-file
serialization callback. The source string, parent-frame link and file-record
destination have been traced through the lower write helper. See
[the owner review](ghidra-owner-review-notes.md#h02-006421ce-read-from-00000028).

Unresolved: The reported read from 0x28 still does not match the identified
local instruction path. The original build and fault registers are missing;
dropping a serialized line has no established recovery contract.

Decision: **Deferred; no approved fix.**

### H03: Invalid floating-point value

Reported:

> '{value}' ist kein gültiger Gleitkommawert.

Evidence: The shared text-to-float parser has numerous loader callers.

Unresolved: The token, locale, field contract and owning loader are missing; a default value has no justified semantics.

Decision: **Deferred; no approved fix.**

### H04: Unmapped AV at 3212AF30

Reported:

> Zugriffsverletzung bei Addresse 3212AF30. Lesen von Adresse 4D60323C.

Evidence: The report supplies an instruction address and a read address only.

Unresolved: The containing module, image base and binary version are absent. No local RVA can be assigned.

Decision: **Deferred; no approved fix.**

### H05: AI cleanup missing list head

Reported:

> Zugriffsverletzung bei Addresse 0082ADE3 in Modul 'Omsi.exe'. Lesen von Adresse 00000020.

Evidence: Prior disassembly reads [head+0x20] after a global dereference; a branch reaches RVA 0x0042AE5D.

Unresolved: The owner's lifetime and null-state contract are unproven. The car log pointer at 0x0042AE2C precedes that target; calling the target the car-cleanup entry was unjustified.

Decision: **Deferred; no approved fix.**

### H06: RS.HumansOutside null list entry

Reported:

> Zugriffsverletzung bei Addresse 006EFD03 in Modul 'Omsi.exe'. Lesen von Adresse 000005BC: RS.HumansOutside

Evidence: Prior disassembly reads [EAX+0x5BC] after selecting a list entry. Zero EAX explains the reported access on a matching build.

Unresolved: It remains unproven that null is a valid skippable entry rather than broken ownership. Complete loop invariants and the continuation at 0x002EFEFC are unresolved.

Decision: **Deferred; no approved fix.**

### H07: visu drivers translate 2 AV

Reported:

> Zugriffsverletzung bei Addresse 00406E6C in Modul 'Omsi.exe'. Lesen von Adresse 00000000: visu drivers translate 2

Evidence: Ghidra confirms MOV EAX,[EAX] inside the shared helper at RVA 0x00006E68.

Unresolved: The originating object and caller are unknown; the context literal was not found by the focused string pass.

Decision: **Deferred; no approved fix.**

### H08: External exception C06D007E

Reported:

> Externe Exception C06D007E.

Evidence: RVA 0x00028E06 is associated with generic external-exception formatting.

Unresolved: The throwing module and actual dependency failure are not established. A dependency-load explanation remains a hypothesis.

Decision: **Deferred; no approved fix.**

### H09: The requested resource is in use

Reported:

> The requested resource is in use.

Evidence: The supplied text has no module, numeric error code or stack; the focused string pass found no match.

Unresolved: Resource contention, an API failure and its owner cannot be distinguished from this text.

Decision: **Deferred; no approved fix.**

### H10: Reset failed: D3DERR_DEVICELOST

Reported:

> Fatal Error occoured! OMSI will be closed. Direct-3D-Device-Reset schlug fehl, Fehler: D3DERR_DEVICELOST

Evidence: Prior analysis maps the reset call/result branch near RVA 0x0042A386.

Unresolved: The device state, reset preconditions, resource ownership and correct retry policy are unproven.

Decision: **Deferred; no approved fix.**

### H11: Reset failed: Unknown

Reported:

> Fatal Error occoured! OMSI will be closed. Direct-3D-Device-Reset schlug fehl, Fehler: Unknown

Evidence: The reset error formatter is mapped, but this report only contains Unknown.

Unresolved: The original numeric HRESULT is missing; it cannot be assumed to equal DEVICELOST or INVALIDCALL.

Decision: **Deferred; no approved fix.**

### H12: Reset failed: D3DERR_INVALIDCALL

Reported:

> Fatal Error occoured! OMSI will be closed. Direct-3D-Device-Reset schlug fehl, Fehler: D3DERR_INVALIDCALL

Evidence: The mapped reset-result branch formats this reported HRESULT.

Unresolved: The violated reset precondition is unknown; retained resources and invalid parameters have not been distinguished.

Decision: **Deferred; no approved fix.**

### H13: Range-check error

Reported:

> Fehler bei Bereichsprüfung

Evidence: The exception catalog and explicit range-check raise path are mapped.

Unresolved: The failing index/value and OMSI owner are absent. Suppressing this guard has no established valid result.

Decision: **Deferred; no approved fix.**

### H14: Direct3D device lost notification

Reported:

> Direct3D-Device lost!

Evidence: RVA 0x00429FD8 is a logging/dispatch path for the device-lost message.

Unresolved: The notification alone does not establish a fatal error or a defective recovery branch.

Decision: **Deferred; no approved fix.**

### H15: Invalid bitmap

Reported:

> Bitmap ist ungültig.

Evidence: The bitmap-invalid helper is mapped.

Unresolved: Invalid input, an allocation failure and invalid object state remain distinct possible causes; the loader is unknown.

Decision: **Deferred; no approved fix.**

### H16: Argument outside range

Reported:

> Argument außerhalb des Bereichs.

Evidence: The message is shared by many argument checks; the RVA is one diagnostic cluster.

Unresolved: The specific method and argument contract are missing.

Decision: **Deferred; no approved fix.**

### H17: Missing context-sensitive help

Reported:

> Keine kontextsensitive Hilfe installiert.

Evidence: Ghidra finds the PascalUnicode resource at data RVA 0x004CB6BE, with no useful xref in this pass.

Unresolved: A help-provider registration or missing installation component is possible; no failing engine instruction is identified.

Decision: **Deferred; no approved fix.**

### H18: Delphi helper AV at 00408850

Reported:

> Zugriffsverletzung bei Addresse 00408850 in Modul 'Omsi.exe'. Lesen von Adresse 3F7FFFF8.

Evidence: Ghidra confirms MOV EDX,[EAX-8] in shared helper FUN_0040884C.

Unresolved: The report is consistent with EAX=0x3F800000 on this build, but neither value origin nor object type is known.

Decision: **Deferred; no approved fix.**

### H19: Systemfehler Code 8

Reported:

> Systemfehler. Code: 8. Not enough memory resources are available to process this command.

Evidence: The system-error wrapper is mapped. The trailing OS message is localized and is not a stable identifier.

Unresolved: Code 8 does not distinguish address-space pressure, fragmentation, graphics resources or the owning allocation.

Decision: **Deferred; no approved fix.**

### H20: Floating-point division by zero

Reported:

> Gleitkommadivision durch Null.

Evidence: The generic floating-point exception path is mapped.

Unresolved: The originating arithmetic operation and a valid zero-denominator policy are unknown.

Decision: **Deferred; no approved fix.**

### H21: POI.GHAA - C access violation

Reported:

> Zugriffsverletzung bei Addresse 007C400E in Modul 'Omsi.exe'. Lesen von Adresse 00000000: POI.GHAA - C ({vehiclepath})

Evidence: The fault occurs in a triangle-normal calculation after reloading
the interface at owner+0xA0 following a mesh-buffer call. Earlier null checks
exist, and lock-like call results are unchecked. Three direct caller sites
consume the resulting vector. The POI.GHAA - C log pointer remains separately
at RVA 0x003AEEDC. See [the owner review](ghidra-owner-review-notes.md#h21-poighaa---c--007c400e).

Unresolved: The diagnostic context is not the fault instruction. The field's
ownership, writers and lifetime remain unresolved, as do lock cleanup and a
valid output contract for callers. Skipping the calculation is not justified.

Decision: **Deferred; no approved fix.**

### H22: List index exceeds maximum

Reported:

> Listenindex überschreitet das Maximum ({value})

Evidence: The shared list-error machinery is mapped.

Unresolved: The list owner, index and expected behavior for a missing element are absent.

Decision: **Deferred; no approved fix.**

### H23: World/UI missing text subobject

Reported:

> Zugriffsverletzung bei Addresse 00828140 in Modul 'Omsi.exe'. Lesen von Adresse 000001F0.

Evidence: Prior Ghidra analysis maps the +0x100 / +0x5C / +0x1F0 object chain.

Unresolved: A null child explains this access on a matching build; an empty Delphi string is still an unproven fallback with unresolved ownership and later UI invariants.

Decision: **Deferred; no approved fix.**

### H24: T.PlugInRefrVars zero-address AV

Reported:

> Zugriffsverletzung bei Addresse 00000000. Lesen von Adresse 00000000: T.PlugInRefrVars

Evidence: Ghidra finds the context literal at data RVA 0x002F5F2C and a pointer at 0x002F4F1D.

Unresolved: A null callback is only a hypothesis. Address zero is not a module RVA; the callback contract, plugin and stack are unknown.

Decision: **Deferred; no approved fix.**

### H25: d3d9 AV: CMOI.R.3

Reported:

> Zugriffsverletzung bei Addresse 725B1BDF in Modul 'd3d9.dll'. Lesen von Adresse 00000008: CMOI.R.3 ({vehiclepath})

Evidence: The report identifies d3d9.dll and a CMOI.R.3 context. The focused string pass found no exact CMOI.R.3 literal.

Unresolved: The original DLL hash/load base and OMSI caller are missing; a DLL RVA and object lifetime cannot be inferred.

Decision: **Deferred; no approved fix.**

### H26: d3d9 AV: RS.SkyLights

Reported:

> Zugriffsverletzung bei Addresse 725B1BDF in Modul 'd3d9.dll'. Lesen von Adresse 00000008: RS.SkyLights

Evidence: Ghidra finds RS.SkyLights at data RVA 0x002F27BC and a log pointer at 0x002F166D.

Unresolved: The log pointer is not the d3d9 fault location. The DLL build, load base and calling object are unknown.

Decision: **Deferred; no approved fix.**

### H27: EZeroDivide reported at offset 00004911

Reported:

> Exception EZeroDivide in Modul Omsi.exe bei 00004911. Gleitkommadivision durch Null.

Evidence: Treating 00004911 as an RVA yields FILD qword ptr [EAX] in FUN_004048B4 in the local binary.

Unresolved: That instruction is not a division. The report's address convention, build and original floating-point fault context are unverified.

Decision: **Deferred; no approved fix.**

### H28: Out of memory: P.KillNotNeededBuses

Reported:

> Zu wenig Arbeitsspeicher: P.KillNotNeededBuses

Evidence: Ghidra reconfirms the log pointer at RVA 0x0042ADA0.

Unresolved: This is an OOM report, distinct from the head-null AV. The failing allocation and cleanup owner's full state are unknown.

Decision: **Deferred; no approved fix.**

### H29: Out of memory: P.KNNC.KM

Reported:

> Zu wenig Arbeitsspeicher: P.KNNC.KM

Evidence: The context is recorded verbatim; the focused defined-string pass found no exact match.

Unresolved: The label's owner and failing allocation remain unresolved. A negative string search does not prove absence from the executable.

Decision: **Deferred; no approved fix.**

### H30: Out of memory: CV.Calculate - I

Reported:

> Zu wenig Arbeitsspeicher: CV.Calculate - I ()

Evidence: Ghidra finds the context string at RVA 0x003D8DA0 and a log pointer at 0x003D60A4.

Unresolved: The checkpoint is not an allocation site; the allocator, requested size and cause of failure are unknown.

Decision: **Deferred; no approved fix.**

### H31: Range check: CV.Calculate - J2

Reported:

> Fehler bei Bereichsprüfung: CV.Calculate - J2 ()

Evidence: Ghidra reconfirms the log pointer at RVA 0x003D620D inside the wider calculation region.

Unresolved: The specific checked index and exception origin are unknown; nearby exception-handling code cannot be treated as the failing operation.

Decision: **Deferred; no approved fix.**

### H32: Range check: CMO.UnschedClearSteuerl

Reported:

> Fehler bei Bereichsprüfung: CMO.UnschedClearSteuerl

Evidence: Ghidra finds the context at RVA 0x003032F0 with pointers at 0x003013E9, 0x00301468, 0x003014E7 and 0x00301566.

Unresolved: Four log sites do not identify which bounds check failed or the correct scheduling-state recovery.

Decision: **Deferred; no approved fix.**

### H33: Unknown image extension (.png)

Reported:

> Unbekannte Bilddateiweiterung (.png)

Evidence: The unsupported-extension path is mapped separately from the invalid-bitmap helper.

Unresolved: The active loader and its registered decoders are unknown. Extension acceptance alone cannot provide PNG decoding.

Decision: **Deferred; no approved fix.**

### H34: NVIDIA driver AV at 5FC7184E

Reported:

> Zugriffsverletzung bei Addresse 5FC7184E in Modul 'nvd3dum.dll'. Lesen von Adresse FFFF0010.

Evidence: The report names the NVIDIA user-mode driver and two addresses.

Unresolved: The driver version, hash, base address and preceding graphics calls are missing; responsibility cannot be assigned to the driver or OMSI.

Decision: **Deferred; no approved fix.**

### H35: Unmapped AV at 7CC92950

Reported:

> Zugriffsverletzung bei Addresse 7CC92950. Lesen von Adresse 7CC92950.

Evidence: The report gives equal instruction/read addresses without a module.

Unresolved: Equality alone does not establish an execution violation. The exception record, memory map and module are unknown.

Decision: **Deferred; no approved fix.**

### H36: Invalid script variable or command

Reported:

> Fehler: im Befehl "({omsivariable})" ({vehiclepath}) ist der Variablenname ungültig!

Evidence: Prior Ghidra analysis maps negative symbol lookups in the script parser.

Unresolved: A parser defect has not been demonstrated; the command, declaration and script compatibility contract are unknown.

Decision: **Deferred; no approved fix.**

### H37: Omsi AV at 005D49B0

Reported:

> Zugriffsverletzung bei Addresse 005D49B0 in Modul 'Omsi.exe'. Lesen von Adresse 000009D9.

Evidence: Ghidra confirms RET at the reported local-build address.

Unresolved: A RET alone does not prove stack corruption or explain this read. The report's build and exception registers are absent.

Decision: **Deferred; no approved fix.**

### H38: Omsi AV at 00829C09

Reported:

> Zugriffsverletzung bei Addresse 00829C09 in Modul 'Omsi.exe'. Lesen von Adresse 421E12E4.

Evidence: The clean Ghidra listing still marks byte D8 as undefined here. Older linear-disassembly notes suggest a floating-point field access.

Unresolved: Instruction boundaries, pointer ownership and the public report's build are unresolved; a stale pointer has not been proven.

Decision: **Deferred; no approved fix.**

### H39: Delphi helper AV at 00406B14

Reported:

> Exception EAccessViolation in Modul Omsi.exe bei 00006B14. Zugriffsverletzung bei Adresse 00406B14 in Modul 'Omsi.exe'. Lesen von Adresse FFFFFFFC.

Evidence: Ghidra confirms CALL dword ptr [ECX-4] in FUN_00406B0C.

Unresolved: Zero ECX explains the read on this build, but its producing caller, object contract and valid recovery are unknown.

Decision: **Deferred; no approved fix.**

## Previously Documented Additional Families

### E01: Direct3D texture allocation failure

Evidence: Prior analysis maps the D3DX texture loaders and release paths.

Unresolved: Allocation pressure, retained references and address-space fragmentation are not distinguished.

Decision: **Deferred; no approved fix.**

### E02: Stream read or write failure

Evidence: Prior analysis maps shared stream helpers with many independent callers.

Unresolved: The loader, requested byte count and source-data validity are unknown; successful recovery is unproven.

Decision: **Deferred; no approved fix.**

### E03: Map or vehicle update failure

Evidence: The existing catalog includes a broad simulation owner and separate map/tile contexts.

Unresolved: This family is broader than the individual CV.Calculate checkpoints; the failing operation is unresolved.

Decision: **Deferred; no approved fix.**

## Corrections to Earlier Interpretations

- H05: the car-cleanup message pointer is at RVA 0x0042AE2C, before the
  proposed continuation 0x0042AE5D. The latter is not proven to be the entry to
  car cleanup. A null head's meaning remains unresolved.
- H06 and H23: skipping a null human or supplying an empty UI string are
  hypotheses about intended behavior, not established fixes.
- H21: POI.GHAA - C has a log pointer at 0x003AEEDC, separate from the public
  fault RVA 0x003C400E. Preserve that distinction.
- H27: the local instruction at RVA 0x00004911 is FILD, not a division. The
  exception's original context is required before attributing causality.
- H37: a RET at the reported location does not prove damaged return state.
- H38: the clean project does not decode the fault byte as an instruction;
  the older linear-disassembly interpretation is not enough to prove a stale
  pointer or authorize a guard.
- The OS suffix after Systemfehler Code 8 can be localized. The numeric code
  and context identify this report, not an English substring.
- Shared context RVAs cannot safely identify fixes. GUI binding now requires
  an explicit candidate ID, target name and matching nonzero RVA.
