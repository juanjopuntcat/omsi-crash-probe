# Ghidra Float Parser Cluster Notes

Generated from `Omsi.exe` with Ghidra headless on 2026-08-08.

Source outputs:

- `ghidra-decompile-float-clusters.tsv`
- `ghidra-decompile-float-clusters\*.c`
- `ghidra-float-cluster-ranges.tsv`
- `ghidra-omsi-helper-callers.tsv`

## Why This Exists

The user-visible `'%s' ist kein gültiger Gleitkommawert` text is a Delphi/VCL
runtime/resource string, so direct string xrefs are not useful. The useful path
is to follow callers of the parser at:

```text
Omsi.exe+0x00024F68
```

The top callers are not isolated one-off conversions. They are large parser
clusters that repeatedly trim/extract strings, pass the decimal separator/global
format value at `0x00859840`, call the string-to-float parser, and then store
parsed values into object fields.

## Decompilation Result

| Cluster | Range | Parser calls in decompiled C | Result |
| --- | ---: | ---: | --- |
| `float_cluster_001EFB98` | `0x001EFB98..0x001F80B7` | 92 from caller table | Decompiler response buffer overflowed. Treat as very large numeric parser. |
| `float_cluster_003B432C` | `0x003B432C..0x003B90B0` | 78 | Decompiled. |
| `float_cluster_003860B0` | `0x003860B0..0x0038AE21` | 35 | Decompiled. |
| `float_cluster_003922A0` | `0x003922A0..0x00395FCF` | 32 | Decompiled. |
| `float_cluster_00224B40` | `0x00224B40..0x002256FC` | 31 | Decompiled; writes parsed floats into object-field offsets such as `[EDI+0x26c]`. |
| `float_cluster_001AB9B8` | `0x001AB9B8..0x001AEA0D` | 28 | Decompiled. |
| `float_cluster_0024307C` | `0x0024307C..0x00244AB2` | 25 | Already overlaps the wide texture load path; also parses many float fields. |
| `float_cluster_001CE730` | `0x001CE730..0x001CFC4F` | 5 in decompiled C, 21 in caller table | Decompiled; grouped float conversion pattern. |
| `float_cluster_0034D878` | `0x0034D878..0x0034F188` | 15 | Decompiled; parsed values are compared against bounds. |
| `float_cluster_00353658` | `0x00353658..0x00353CEE` | 14 | Decompiled; compact object float table parser. |

Some parser-call counts differ between caller-table and decompiled C because
Ghidra simplifies or loses some calls during decompilation. The caller table is
the source of truth for raw xrefs.

## Probe Labels Added

`OmsiCrashProbe.cpp` now labels these high-volume string-to-float caller ranges:

- `0x001AB9B8..0x001AEA0D`: `High-volume numeric parser cluster A`
- `0x001CE730..0x001CFC4F`: `High-volume numeric parser cluster B`
- `0x001EFB98..0x001F80B7`: `Very large numeric parser cluster`
- `0x00224B40..0x002256FC`: `Object float property parser`
- `0x0024307C..0x00244AB3`: `Wide texture load/numeric parser path`
- `0x0034D878..0x0034F188`: `Numeric bounds/parser cluster`
- `0x00353658..0x00353CEE`: `Compact object float table parser`
- `0x003860B0..0x0038AE21`: `High-volume numeric parser cluster C`
- `0x003922A0..0x00395FCF`: `High-volume numeric parser cluster D`
- `0x003B432C..0x003B90B0`: `High-volume numeric parser cluster E`

## Interpretation

These labels do not mean the parser clusters are inherently wrong. They mean
that future `Gleitkommawert`, range-check, or access-violation stack candidates
inside these ranges should be interpreted as data/config numeric parsing paths.

The likely mitigation direction is not patching Delphi's generic parser. It is
identifying which source string/key/file produced an invalid numeric token, then
deciding whether we can safely enrich logging, validate earlier, or harden the
caller-specific parsing path.
