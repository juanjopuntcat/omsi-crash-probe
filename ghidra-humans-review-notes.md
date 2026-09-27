# HumansOutside Review: H06

Reviewed 2026-09-27 with Ghidra 12.1.2 (read-only, no analysis) and MSVC
dumpbin 14.29.30159.0. **Deferred; no approved fix.** High confidence in the
local instruction decoding is not high confidence in a safe recovery policy.

Installed Omsi.exe SHA-256:
`7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759`.
Image base: `0x00400000`. All addresses below are RVAs unless marked VA.
The public reporter's binary identity and register snapshot are unavailable.

## Loop and Diagnostic Context

Ghidra has no function at the decoded entry `0x002EF9E4` or fault
`0x002EFD03`; its reference export also misses a direct call visible in the
binary. Missing model references must not be interpreted as unreachable code.
Linear decoding from the prologue and explicit branch targets establishes:

| RVA | Observation |
| --- | --- |
| `0x002F19C3` | Calls VA `0x006EF9E4` inside a local exception frame. Its handler loads the `: RS.HumansOutside` string at `0x002F19EE` (pointer operand begins at `0x002F19EF`). This links the diagnostic context to the routine containing the reported fault. |
| `0x002EF9E4` | Prologue initializes locals and installs an outer cleanup frame targeting `0x002EFF7F`. A first loop uses a different global array slot, VA `0x00858CD8`. |
| `0x002EFCC8` | The second loop loads the array through VA `0x00859E58`. That slot contains VA `0x00861730`, the array-pointer storage, in this image. |
| `0x002EFCCF` | Calls `0x0000A804`, which returns length minus one. Its helper `0x0000A7FC` returns zero for a null array, otherwise reads the length at array-4. |
| `0x002EFCD4` | Negative high index exits to `0x002EFF08`; otherwise EBP-8 receives the initial count and EBP-4 starts at zero. |
| `0x002EFCE7` | Reloads the current array; tests array existence and current index against current length before loading the element at `0x002EFD00`. Bounds failure calls `0x0000695C`. This does not validate the element pointer. |
| `0x002EFD03` | `CMP BYTE PTR [EAX+0x5BC],0`. A zero element produces read address `0x5BC` on this build. No element-null guard precedes it. |
| `0x002EFD0A`, `0x002EFD33` | Failed predicates at object+0x5BC and object+0x2DD branch to `0x002EFEFC`. |
| `0x002EFD55` onward | Reads +0x6B4 and, when nonzero, follows +0x258. Writes byte 1 or 4 through object+0x214 at child+0x24. The element is repeatedly reloaded from the array. |
| `0x002EFE08` | Calls `0x003BC3C0`, which conditionally passes object+0x214 to `0x001FD600`, after a test through `0x00405C78` with argument 0x5F. Exact method semantics are unresolved. |
| `0x002EFE9A` | Calls virtual slot +0x0C on another reload of the element, with EDX zero. Do not label this a destructor or update method without resolving the vtable. |
| `0x002EFEFC` | Increments EBP-4, decrements EBP-8, branches back to `0x002EFCE7` while the initial count is not exhausted. No object access occurs in this advance block. |
| `0x002EFF08` | Normal loop exit unlinks the outer frame and runs local-string cleanup. The normal epilogue at `0x002EFF86` restores registers and returns at `0x002EFF8C`. |

The two calls within the loop have separate local exception frames beginning
at `0x002EFDDE` and `0x002EFE6C`. The existing predicate skips occur before
those frames are installed. Thus the advance target is structurally understood;
an added branch there would not bypass unlinking an already active inner frame
at the first predicate. This is not proof that dropping the object is valid.

The loop's initial iteration count is fixed, but subsequent bounds checks use
the currently loaded array. No stable retained element or array snapshot is
visible in this path. This identifies invariants to prove, not evidence that
concurrent mutation actually occurs.

## Writers and Lifecycle Clues

These functions are defined in Ghidra and decompile successfully. Their
inferred roles come from data flow; they are not recovered source names.

- `0x00303D2C`: calls a per-element routine, tests object+0x6B4 and, when
  zero, calls `0x00006B0C` on the element. It shifts subsequent pointers left
  (store at `0x00303DF4`) and passes length-1 to `0x0000A9B0`. This is
  consistent with disposal and dense-array removal, not permanent null holes.
- `0x00309E3C`: passes length+1 to `0x0000A9B0` at `0x00309E7D`, then makes
  several calls including virtual calls and the constructor-like `0x00225808`.
  Only later does `0x00309F0C` store that result into the last array slot.
  A later false result from `0x002267EC` leads to disposal and length-1.
  The visible exception cleanup at `0x00309FC7` releases local strings; it
  does not establish rollback of the earlier array growth.
- `0x002E57B0`: map-closing path iterates this array, passes each element to
  `0x00006B0C`, then passes zero length to `0x0000A9B0`.
- `0x0034AEC4`: clears per-element +0x6B4 and +0x610 state and invokes
  the removal routine. It is not an insertion routine.

The helper at `0x0000A9B0` is consistent with Delphi dynamic-array resizing;
its allocation/exception internals were not audited in this bounded pass.
Growth-before-initialization is therefore a concrete failure-path concern,
but a surviving zero slot after an exception is still a hypothesis. We have
not proved which intervening call can fail, whether an outer owner rolls back,
or whether the rendering path can observe the intermediate state.

Other readers also dereference elements without null checks. Skipping a null
only at the reported rendering predicate would not repair those readers or
reestablish collection ownership.

## Decision and Reopening Criteria

**Keep H06 deferred. Do not implement a null-skip trampoline.** The old
description that the continuation itself was unknown is now outdated, but
the intended semantics and root cause remain unresolved.

- Establish whether null elements are ever a valid persistent state. Dense
  compaction suggests otherwise, but does not prove a global invariant.
- Audit insertion failure rollback, all writers, object lifetime and ordering
  between mutation and iteration. Neither a race nor reentrancy is established.
- Resolve the virtual +0x0C call and nested-object obligations before changing
  which work executes for an element.
- Match the original exception to a binary build before attributing its cause
  to this local implementation.

Following the agreed policy, record these doubts and move to H23 / World/UI.
No additional game session is required for this handoff.

## Reproduction and Limits

Run `Run-GhidraHumansReview.ps1`. Supply `-DumpbinPath` with the local MSVC
dumpbin path to also reproduce the linear excerpts. The latter step checks
the installed executable hash before decoding the hard-coded VA ranges.
The Ghidra step reads the existing project; it does not reimport the installed
binary or prove that an arbitrary replacement project matches this hash.

Nine decompilation requests are intentional: seven defined functions plus two
`missing-function` records for the loop entry and fault. The context, reference
and string TSVs supplement them. Generated TSV/C/log outputs remain ignored
by Git; this report records the interpretation.

Linear output includes embedded Delphi exception tables at
`0x002EFE1C`-`0x002EFE27` and `0x002EFEAC`-`0x002EFEB7`.
Do not interpret their printed pseudo-instructions as control flow. Decoder
function boundaries and decompiler calling conventions are not source proof.

No executable was patched, no game was started, and no excluded content,
Addons or SDK directory was read.
