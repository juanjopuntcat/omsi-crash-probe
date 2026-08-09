# Ghidra Stream Caller Notes

## Scope

This pass inspected only `Omsi.exe` in the existing Ghidra project. It did not
scan `SDK`, `Addons`, or any excluded OMSI content directory.

## Generic Read Helpers

The two central stream-read helpers have broad caller fan-out:

| Helper | Direct references | Distinct recognized owners | Interpretation |
| --- | ---: | ---: | --- |
| `0x0004DF1C` | 42 | 16 | Generic exact/read-buffer helper used by runtime, image and OMSI loaders. |
| `0x0004DF7C` | 31 | 12, plus four unbounded call sites | Alternate generic read path used by multiple binary loaders. |

This rules out treating either helper as a subsystem owner. A runtime exception
there must use the next OMSI frame and adjacent `logfile.txt` load text.

Confirmed nearby owners include the existing BMP/GDI loader at
`0x00076C10..0x0007720C`; another graphics path at `0x000771A0` validates the
`BM` signature. These remain graphics evidence rather than general stream
labels.

## Narrow Chains

- `0x0004FF2C` calls the fill/read-error helper at `0x0004FF78`.
- `0x0005284C` calls validation at `0x00052684` and is itself called from
  `0x00051094`.
- `0x00054924` calls the write-error path at `0x00054ADC`.
- `0x0004EB15` has no direct code reference because it is an internal branch in
  the memory-stream expansion function rather than a standalone callable.

These are runtime/library chains. They should keep caller-context priority and
must not receive speculative OMSI subsystem labels.

## Generated Evidence

The ignored local artifacts are:

- `ghidra-stream-helper-callers.tsv`
- `ghidra-decompile-stream-owners.tsv`
- `ghidra-decompile-stream-owners/`
