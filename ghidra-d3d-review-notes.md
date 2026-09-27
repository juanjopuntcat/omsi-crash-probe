# Direct3D Recovery Review: H10-H12 and H14

Reviewed 2026-09-27 with Ghidra 12.1.2 in read-only mode and MSVC dumpbin.
**Deferred; no approved fix.** This pass identifies state dispatch and local
cleanup/recreation stages, not the cause of an individual reported failure.
H13 is a generic Delphi range-check case, not part of this Direct3D group.

Installed Omsi.exe SHA-256:
`7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759`.
Image base: `0x00400000`. Addresses below are RVAs unless marked VA.
Public reporter hashes, original HRESULT records and resource states are absent.

## State Dispatch

The containing routine begins at 0x00429E84 but is not a defined function
in the current Ghidra model. Decoding its bytes from explicit entry points:

| RVA | Observation |
| --- | --- |
| 0x00429F67 | Calls device vtable+0x0C, the x86 IDirect3DDevice9 TestCooperativeLevel slot. Device pointer is reached through VA 0x00858824. |
| 0x00429F6C | Tests byte at VA 0x00862F24. If nonzero, 0x00429F75 replaces the result with 0x88760869 (DEVICENOTRESET). |
| 0x00429F91 | A nonfailed result bypasses the recovery region to 0x0042A5E8. |
| 0x00429FB5 | DRIVERINTERNALERROR (0x88760827): logs, calls 0x004298A4 and exits through routine cleanup. Callee effects remain unresolved. |
| 0x00429FAC | DEVICELOST (0x88760868): sets local byte [EBP-0x1D] and bypasses Reset. Its downstream consumers are not exhaustively reviewed here. |
| 0x00429FD8 | DEVICENOTRESET (0x88760869): logs the device-lost notification, then begins release/recovery. Other failed results skip this region. |
| 0x0042A386 | Calls device vtable+0x40, the x86 Reset slot, with presentation parameters at VA 0x00862EEC. |
| 0x0042A38D | Zero result takes the restoration path; a nonzero result takes the error-formatting path. |
| 0x0042A3DF | Reset failure leaves this region for cleanup at 0x0042B5CD, which releases local temporaries and returns at 0x0042B833. There is no retry on this local path. |
| 0x0042A5E1 | After restoration stages, clears the forced-reset byte and continues outside the recovery region. |

Method slots and HRESULT constants were checked against the installed Microsoft
Windows Kits 10.0.19041.0 `shared/d3d9.h`, not the game's excluded SDK directory.

The recognized writer at 0x00306631 sets the forced-reset byte after matching
the input token `reset_graphic_device` in function 0x00306354. The pointer
slot at VA 0x00859244 refers to VA 0x00862F24. Thus the notification does
not prove that TestCooperativeLevel itself returned DEVICENOTRESET: an explicit
reset request can reach the same branch even with a different actual result.
The defined-reference search is incomplete because the main recovery region
is undefined in the model; the reads/clear above were recovered from bytes.

Microsoft documents DEVICELOST as not yet recoverable and DEVICENOTRESET as
the point to attempt Reset. The normal, unforced dispatch distinguishes them.
This does not prove the forced path is faulty: its allowed invocation states
and surrounding coordination have not been established.
[TestCooperativeLevel contract](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-testcooperativelevel).

## Resource Stages

Each stage below has a local exception handler that logs and rejoins the
following stage when the handler completes normally. An exception raised by
the handler itself could instead propagate. Logging is not proof of successful
cleanup or recreation.

| Call RVA | Operation observed |
| --- | --- |
| 0x00429FF2 | Calls 0x003FA44C: conditionally disposes the global object at VA 0x00861BD8, clearing its storage before the disposal helper. |
| 0x0042A064 / 0x0042A0D6 | Calls 0x003F7258 on managers reached through VA 0x0085989C / 0x008594C4. Iterates 0x68-byte entries at owner+8, calling 0x003F9C48 only when entry+0x3A is zero. The flag is not yet identified as a resource-pool property. |
| 0x0042A16E / 0x0042A189 | Clears/releases interfaces from the array reached through VA 0x008590D8, then resizes it to zero. |
| 0x0042A200 | Clears/releases the interface slot reached through VA 0x00858E30. |
| 0x0042A274 | Calls 0x002E6D48 on the object at VA 0x00862F28; disposes fields +0x0C and +0x10. Full ownership and destructor behavior remain unresolved. |
| 0x0042A2E3 onward | Copies UI child+0x50/+0x54 into the presentation width/height after signed nonnegative checks. This is not validation of the entire presentation structure. |
| 0x0042A405 | After successful Reset, calls 0x00400CAC on the object reached through VA 0x00858CE4. Function body is undefined in this model. |
| 0x0042A480 | Calls 0x003FA488: conditionally constructs the global object at VA 0x00861BD8 and sets its +0x44/+0x48 fields. |
| 0x0042A500 / 0x0042A580 | Calls 0x002E6D64 and 0x004257CC, respectively. Bodies are undefined in this model. |

Interface helper 0x0000C050 zeros a nonnull interface slot before calling
vtable+8 (Release). Manager entry helper 0x003F9C48 checks the index, samples
the interface reference count with AddRef/Release, can log a texture release
counter, then clears/releases entry+0x18 and resets several entry flags.
This is not proof that all references, default-pool resources, state blocks,
render targets or additional swap chains have been released.

The dimensions handler at 0x0042A336 can rejoin directly at the Reset argument
push (0x0042A377). Likewise, the final restoration handler at 0x0042A5A0 can
reach the forced-reset flag clear. These are concrete continuation paths;
whether a failure leaves usable state is a separate, unresolved question.

Microsoft requires appropriate resource release before Reset and constrains
calls after a failed Reset. Reset also mutates its presentation parameters and
must run on the device-creation thread; it may dispatch window messages.
Those obligations require a broader ownership/thread/reentrancy analysis than
this local sequence provides.
[Reset contract](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/nf-d3d9-idirect3ddevice9-reset).

## Error Formatting and Decisions

On Reset failure, 0x0042A39D passes the original result to thunk 0x00162A84.
That thunk jumps through IAT VA 0x008647FC: `DXGetErrorString9A` from
`dxerr9.dll` (verified with the PE import table). The returned text is joined
to the fatal-reset message and logged at 0x0042A3CE with severity argument 4.
The logger's full shutdown behavior is outside this pass; do not infer a
specific process-termination mechanism from the text alone.

- H10: reset result site confirmed. The unforced DEVICELOST state bypasses
  Reset, but a forced reset or a state change could lead to a different result.
  Neither is established as the cause of the public report. Retry safety is
  unproven, particularly after partial release/recreation.
- H11: formatter and original-result argument confirmed. `Unknown` is not
  a numeric HRESULT; it cannot identify the failed precondition or justify
  treating the failure as DEVICELOST or INVALIDCALL.
- H12: common failure branch confirmed. Resource coverage, complete parameter
  validity, thread identity and reentrancy remain unresolved. No single cause
  of INVALIDCALL has been demonstrated for this installation or public report.
- H14: the notification marks entry to recovery, including explicit reset
  requests. It is not itself a fatal error or proof of a Direct3D defect.

No retry loop, result suppression, forced-flag change or skipped cleanup is
approved. Reopen only after proving the affected owners and continuation
invariants. Proceed to the external-module evidence inventory meanwhile.

## Reproduction and Limits

Run `Run-GhidraD3dReview.ps1`, optionally with `-DumpbinPath`. This run produced
seven successful decompilations and six explicit `missing-function` records:
recovery owner, Reset site, world restoration, manager restoration, UI
restoration and formatter thunk. The thunk was decoded separately and is not
an unexplained missing implementation.

The script reads the existing project without repairing or reimporting it.
The optional byte excerpts check the installed binary hash; that does not
authenticate an arbitrary replacement Ghidra project. Generated exports are
git-ignored. For the formatter identity, also run dumpbin `/imports` on the
same executable and inspect the dxerr9 import table (W at VA 0x008647F8,
A at VA 0x008647FC).

Embedded exception-table RVA intervals are 0x0042A006-0x0042A011,
0x0042A078-0x0042A083, 0x0042A0EA-0x0042A0F5,
0x0042A1A0-0x0042A1AB, 0x0042A214-0x0042A21F,
0x0042A288-0x0042A293, 0x0042A32A-0x0042A335,
0x0042A419-0x0042A424, 0x0042A494-0x0042A49F,
0x0042A514-0x0042A51F, 0x0042A594-0x0042A59F and
0x0042A5F7-0x0042A602. Linear decoder output across those data intervals
is not executable flow. Separate exact-handler excerpts avoid misalignment;
truncated final bytes at range boundaries are not complete instructions.

No game file was modified, OMSI was not launched, and no excluded game
content, Addons or SDK folder was read. The patch manifest remains empty.
