# Ghidra Delphi Helper Caller Notes

Generated from `Omsi.exe` with Ghidra headless on 2026-08-08.

Source outputs:

- `ghidra-omsi-helper-callers.tsv`
- `omsi-string-pointer-refs.tsv`

## Negative String-Pointer Result

`Find-OmsiStringPointerRefs.ps1` scanned `Omsi.exe` for absolute little-endian
pointers to the Delphi/VCL error strings that had no Ghidra xrefs. It found no
matches.

Interpretation: strings such as `Fehler bei Bereichsprüfung`,
`Bitmap ist ungültig`, `Zu wenig Arbeitsspeicher`, and
`'%s' ist kein gültiger Gleitkommawert` are not referenced through a simple
absolute pointer table. Treat them as Delphi runtime/resource strings and follow
the helper functions that raise or format them instead.

## `Systemfehler. Code: %d.`

Helper:

```text
Omsi.exe+0x0002A000
```

Confirmed callers:

| Caller RVA | Function RVA | Notes |
| ---: | ---: | --- |
| `0x0002A0AB` | `0x0002A0A4` | Generic wrapper: raises if `EAX`/saved value is zero. |
| `0x00076F82` | `0x00076C10` | BMP/GDI path, after a failed guarded API call. |
| `0x00077026` | `0x00076C10` | BMP/GDI path, second failure branch. |
| `0x00093F95` | `0x00093E70` | Unknown resource/object path; follows `CALL 0x00410d84` and `TEST AX,AX`. |
| `0x00093FB9` | `0x00093E70` | Same function; checks `[EDI+0x260]` after a virtual call. |
| `0x000C1617` | `0x000C1590` | Unknown path; follows `CALL 0x004c0280`. |
| `0x0002297A` | `0x00022898` | Delphi/runtime conversion or stream flag path. |
| `0x00164528` | `0x00164528` | Tiny wrapper that immediately raises system error. |
| `0x00094361` | `0x00094318` | Unknown resource/object path; follows `CALL 0x004109a4` and `TEST EAX,EAX`. |
| `0x00055557` | `0x00055528` | Initializes global `[0x0085eff4]`; raises if allocation/init returned null. |

The two BMP/GDI callers are the current high-confidence explanation for observed
`Systemfehler. Code: 8` when bitmap/GDI allocation fails.

## BMP/GDI Bitmap Loader

Main range now labeled in the probe:

```text
Omsi.exe+0x000769E4..0x0007720C
```

Confirmed callers of the loader:

| Caller RVA | Function RVA | Notes |
| ---: | ---: | --- |
| `0x00076A2A` | `0x000769E4` | Wrapper around `0x00076C10`. |
| `0x00077202` | `0x000771A0` | Second wrapper around `0x00076C10`. |

## String-To-Float Parser

Parser:

```text
Omsi.exe+0x00024F68
```

Top caller-function clusters:

| Function RVA | Calls |
| ---: | ---: |
| `0x001EFB98` | 92 |
| `0x003B432C` | 78 |
| `0x003860B0` | 35 |
| `0x003922A0` | 32 |
| `0x00224B40` | 31 |
| `0x001AB9B8` | 28 |
| `0x0024307C` | 25 |
| `0x001CE730` | 21 |
| `0x0034D878` | 15 |
| `0x00353658` | 14 |
| `0x0042F7D0` | 10 |

Known overlap:

- `0x0024307C` is already labeled as the wide texture load path.
- `0x001D78D0` appears lower in the list and is already labeled as the
  `helper\stars.dat` parser.

These clusters are better patch/probe candidates than the generic
`'%s' ist kein gültiger Gleitkommawert` string itself.

## Probe Impact

`OmsiCrashProbe.cpp` now expands the BMP/GDI bitmap label from
`0x00076C10..0x00077133` to `0x000769E4..0x0007720C` so wrapper frames around
the loader are classified too.
