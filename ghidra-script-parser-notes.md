# Ghidra Script Parser Notes

## Scope

This pass inspected only `Omsi.exe` in the existing Ghidra project. It did not
scan `SDK`, `Addons`, or any excluded OMSI content directory.

## Command Parser

The four resource keys used for invalid script identifiers all resolve to one
function:

```text
Omsi.exe+0x001D1E68..0x001D4076
```

That function is called at `0x003B5DE4` by the larger load/compile owner at
`0x003B432C..0x003B90B0`. The decompiler shows that it classifies tokenized
commands and searches separate symbol tables. A negative lookup result selects
one of the following error paths:

| Resource key | String RVA | Xref RVA | Error path | Confidence |
| --- | ---: | ---: | ---: | --- |
| `SC_ErrorInCommand_varinvalid` | `0x001D462C` | `0x001D37A0` | `0x001D378D..0x001D37E3` | High |
| `SC_ErrorInCommand_macroinvalid` | `0x001D4658` | `0x001D390B` | `0x001D38D1..0x001D394E` | High |
| `SC_ErrorInCommand_macroinvalid` | `0x001D4658` | `0x001D3A79` | `0x001D3A3F..0x001D3ABC` | High |
| `SC_ErrorInCommand_constantinvalid` | `0x001D4684` | `0x001D3BE4` | `0x001D3BAA..0x001D3C27` | High |
| `SC_ErrorInCommand_functioninvalid` | `0x001D46B4` | `0x001D3E1B` | `0x001D3DE1..0x001D3E52` | High |

The paths combine the generic `SC_ErrorInCommand` text, the offending token,
source context, and the type-specific resource before logging or raising the
error. This means an invalid variable-name message is an explicit parser
diagnostic, not a generic Delphi range or access violation.

## Direct3D Cross-check

The same pass reconfirmed these function boundaries:

- `0x002793A8..0x002799BE`: Direct3D device creation owner.
- `0x004029AC..0x00402A98`: Direct9 HRESULT formatter using
  `DXGetErrorString9W`.
- `0x00429FD8..0x0042A412`: embedded device-lost/reset block.

Ghidra does not model the reset block as a standalone function, but its string
xrefs and instructions remain unambiguous. The reset COM call stores its result
in `EBX`, branches on zero, and passes failures to the Direct9 formatter. This
supports keeping reset failures separate from texture allocation failures.

## Generated Evidence

The ignored local artifacts are:

- `ghidra-script-parser-string-xrefs.tsv`
- `ghidra-decompile-priority.tsv`
- `ghidra-decompile-priority/`
- `ghidra-priority-callers.tsv`
- `ghidra-priority-function-ranges.tsv`
