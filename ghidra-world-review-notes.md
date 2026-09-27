# World/UI Review: H23

Reviewed 2026-09-27 with Ghidra 12.1.2 in read-only mode. **Deferred; no
approved fix.** This pass corrects the earlier description of a string field
at child+0x1F0. The field is consumed as a signed integer and formatted into
decimal text; it is not copied as a Delphi string.

Installed Omsi.exe SHA-256:
`7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759`.
Image base: `0x00400000`. Addresses below are RVAs unless marked VA.
The public reporter's executable hash and register snapshot are unavailable.

## Fault and Value Flow

The containing function is `0x0042695C`, a large UI refresh routine. At
`0x00428132` it loads global state from VA `0x00862F28`, follows +0x100 to
a parent and +0x5C to a child. The reported instruction at `0x00428140` reads
the DWORD at child+0x1F0. Zero EAX explains read address 0x1F0 on this build.
There is no child-null check in this immediate chain.

| RVA | Recovered behavior |
| --- | --- |
| `0x0042812C` | EDX receives the address of managed-string local EBP-0x3C8. |
| `0x00428140` | EAX receives the value at child+0x1F0, not a string copied to the control. |
| `0x00428146` | Calls `0x00022180` with that value and the output-local address. |
| `0x00022180` | Tests the integer sign; passes magnitude, sign flag and output address to `0x00021D74`. |
| `0x00021D74` | Counts decimal digits, allocates output length, writes a minus sign when required and fills UTF-16 decimal digits using divisions by 100 and a digit-pair table. Zero becomes the one-character string `0`. |
| `0x0042814B` | Loads the generated string into EDX. |
| `0x00428151` | Loads the UI control from EBX+0x484. |
| `0x00428157` | Calls the text setter at `0x0008F12C`. |
| `0x0008F12C` | Retrieves existing text, compares it with the supplied string and dispatches an update when different. Instruction `0x0008F159` branches on the comparison flags; the decompiler's synthetic boolean is not a recovered source variable. |
| `0x0008E4F8` | Dispatches message values 0x0C and 0xB012 through control helpers. The complete message-handler/callback graph is not resolved. |

Thus replacing the field load with integer zero would display `0`, not blank
text. Bypassing formatting and supplying a null/empty managed string is a
different behavioral change. Neither policy follows from the observed fault.

The prologue zeroes 0x460 bytes of locals. The formatter's output local is
within this initialized area. Cleanup at `0x004292A1` passes EBP-0x460 and
count 0x2A to the managed-string-array cleanup helper, covering EBP-0x3C8.
The setter also has cleanup for its own temporary existing-text string.
These observations clarify local string storage; they do not establish the
owner's missing-value semantics or the effect of updating this control.

## Selection Is Not Child Validation

At `0x0042785F`, a negative selection value at VA `0x00862F78` bypasses lookup.
Otherwise `0x0042787D` calls `0x00383BB8` with the current +0x100 parent.
That helper iterates a collection at its context+0x118 and delegates to
`0x00391918`, which searches an array at element+0x54 by pointer equality.
It returns an index or -1. It does not validate the parent's +0x5C child.

`0x0042789B` sends a negative lookup result to `0x004281D5`, an existing
no-selection path that changes many controls. A nonnegative result enters
the long populated-state path containing the fault. Array membership does
not establish that the child exists, is alive, or remains consistent.

After the fault's text update, the routine reloads the parent for fields
+0x58, +0x50, +0x34 and +0x35 and calls virtual control methods at slot +0xFC.
The populated branch joins at `0x004283CD`. Earlier reports described these
later parent fields as valid; only the accesses are established. Their
lifetime and consistency across intervening calls have not been proved.

There are many control calls between the initial lookup and the failing read.
No retained parent/child snapshot is visible in that path. Reentrancy or
mutation could matter, but this pass does not demonstrate either occurring.
The no-selection path is not an established recovery target for a selected
parent with a missing child, particularly after partial UI updates.

## Callers and Additional State

Four direct callers appear in the current reference model:

- `0x002E6278` in owner `0x002E5C0C`.
- `0x0030778D` in owner `0x00307454`.
- `0x0043C559` and `0x00305C05`, with no containing function in the model.

This is a bounded caller inventory, not a complete event/callback graph.
No concrete parent/child class, all +0x5C writers, destruction ordering, or
consumer of the displayed number has been established in this pass.

The refresh routine sets byte EBX+0x8FC to one at `0x0042697E`. It resets it
at `0x0042928D`, before the local-string finalizer, rather than in that
finalizer. Its precise meaning and outer recovery behavior are unproven.
An exception or added early exit therefore needs a separate state audit;
string cleanup alone must not be mistaken for complete UI-state recovery.

## Decision

**Keep H23 deferred. Withdraw the earlier empty-string patch recommendation.**
Rename the catalog entry to "World/UI missing numeric-field owner" while
keeping the stable candidate ID `omsi-world-ui-null-subobject` unchanged.

Before proposing any fix, establish:

- The meaning of child+0x1F0 and whether the +0x5C child may legitimately be absent.
- Parent/child construction, writes, destruction and ordering across UI calls.
- Whether blank text, zero, a disabled control, or rejection of the selection
  is the intended policy, including callbacks and later consumers.
- The EBX+0x8FC flag's obligations and outer exception recovery.
- The original reported binary identity.

These are open questions, not reasons to install a speculative guard. Proceed
to H05 / AI cleanup after recording them; no new game session is requested.

## Reproduction and Limits

Run `Run-GhidraWorldReview.ps1` against the existing OmsiStatic project. It
exports nine functions, focused instruction windows and references using
`-readOnly -noanalysis`. Outputs under `ghidra-decompile-world-review/` and
the corresponding TSV files stay local and git-ignored.

The large owner's decompilation contains incorrect-looking string types for
code/stack values. This report uses cross-checked instructions and narrowly
traced helpers, not those synthetic literals as source evidence. Function
names, class names and message-handler semantics are not recovered source.
The script does not import a new binary or authenticate a replacement project.

No game binary was changed, OMSI was not started, and no excluded content,
Addons or SDK directory was read.
