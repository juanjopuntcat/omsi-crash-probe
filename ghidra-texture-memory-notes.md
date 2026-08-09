# OMSI texture memory and Direct9 error notes

Generated from static Ghidra analysis of `Omsi.exe`; OMSI was not launched.
No content folders were scanned. Asset paths mentioned in
`last-crash-session-analysis.md` came only from OMSI's existing `logfile.txt`.

## Why this pass

`last-crash-session-analysis.md` showed the latest session was dominated by
texture/resource pressure:

- `DirectX/texture out of memory`: 195 hits
- `Texture load Direct9 error`: 195 hits
- `Texture failed`: 195 hits
- `Systemfehler Code 8 / OS memory resources`: 62 hits

The probe was noisy with handled Delphi numeric conversions, but the OMSI log
points more directly at texture allocation pressure.

## New artifacts

- `Run-GhidraOmsiTextureStringXrefs.ps1`
- `ghidra-texture-string-xrefs.tsv`
- `Run-GhidraOmsiTextureRvaContext.ps1`
- `ghidra-texture-rva-context.tsv`

`ExportOmsiStringXrefs.java` was also generalized so focused runs can pass
`name=needle` or `name needle` target pairs instead of editing the Java source.

## String xrefs

| String / family | String RVA | Xref RVA | Function RVA | Interpretation |
| --- | ---: | ---: | ---: | --- |
| `Speicherbedarf Texturmanager:` | `0x002FBDA4` | `0x002F9FE5` | unknown | Texture manager memory/accounting output. |
| `Fehlercode beim Texturenladen - und trotzdem nicht nil?` | `0x003F9378` | `0x003F91FB` | `0x003F891C` | Texture load error wrapper; checks texture slot/error state and logs a diagnostic if an error code exists despite a non-null texture. |
| `Too high texture stage index!` | `0x003FCC3C` | `0x003FCC24` | `0x003FCC08` | Guard that reports texture stage index >= 8. |
| `PIDirect3DTexture9` type metadata | `0x001ED9B3` | `0x001ED8BC` | none | Delphi RTTI/type metadata for Direct3D texture lists. |

## Important code paths

`0x0024307C..0x00244AB3` is the wide texture load/numeric parser path already
known from float cluster analysis. The sharper call site is:

```text
0x00243F42  PUSH EAX
0x00243F43  PUSH 0
...
0x00243F62  MOV EAX,[0x00858824]
0x00243F67  MOV EAX,[EAX]
0x00243F69  PUSH EAX
0x00243F6A  CALL 0x00568068
```

Ghidra decompilation identifies the call at `0x00243F6A` as
`D3DXCreateTextureFromFileExW`. This is the strongest static match for the
runtime `Texturladen - Direct9 Error: E_OUTOFMEMORY` cascade.

`0x003F891C..0x003F933B` is the ANSI texture/image load path. The xref at
`0x003F91FB` loads the diagnostic string and calls a logging/error path:

```text
0x003F91F2  CMP [EAX + EDX*8 + 0x18],0
0x003F91F7  JZ 0x007f9222
0x003F91FB  MOV EAX,0x7f9378
0x003F9200  CALL 0x00802794
```

Later in the same function, the path calls the Direct9 formatter:

```text
0x003F9224  MOV EDX,0x7f93bc
0x003F9229  MOV EAX,EDI
0x003F922B  CALL 0x00802aec
```

`0x003FCC08..0x003FCC2F` increments/checks a texture stage counter and reports
`Too high texture stage index!` when the counter reaches 8:

```text
0x003FCC0E  ADD [EAX - 0x44],1
0x003FCC1C  CMP [EAX - 0x44],8
0x003FCC20  JL 0x007fcc2e
0x003FCC24  MOV EAX,0x7fcc3c
0x003FCC29  CALL 0x008022c0
```

## Probe labels added

| RVA range | Label |
| --- | --- |
| `0x002F9F89..0x002FA083` | Texture manager memory report path |
| `0x00243F10..0x00243F7B` | D3DX texture creation call site |
| `0x003FCC08..0x003FCC2F` | Texture stage limit guard |

Because `0x00243F10..0x00243F7B` sits inside the larger
`0x0024307C..0x00244AB3` path, it is placed before the broad range in the
`KnownRva` table so future probe logs get the more specific label.

## Interpretation

The static path supports this model for the current session:

1. OMSI requests many texture allocations through D3DX/Direct3D 9.
2. The D3DX texture creation path begins returning `E_OUTOFMEMORY`.
3. OMSI logs paired `Texturladen - Direct9 Error` and `Texture "... " failed!`
   lines.
4. Nearby `Systemfehler Code 8` events suggest process/resource pressure is
   visible outside only Direct3D, so we should correlate future sessions with
   VAS, largest free VAS block, GDI handles, and USER handles.

This does not yet prove whether the primary limit is video memory, 32-bit
address-space fragmentation, GDI handles, or a leak in OMSI's texture manager.
It does give us concrete code regions to label in future crash/probe logs.
