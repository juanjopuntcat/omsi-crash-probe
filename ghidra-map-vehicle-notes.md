# Ghidra Map and Vehicle Calculation Notes

## Scope

This pass inspected only `Omsi.exe` in the existing Ghidra project. It did not
scan `SDK`, `Addons`, or any excluded OMSI content directory.

## Static checkpoints

| Diagnostic | String RVA | Embedded pointer RVA | Probable owner |
| --- | --- | --- | --- |
| `: map.translate` | `0x002F5C50` | `0x002F37FF` | `0x002F359C..0x002F3981` |
| `CV.Calculate - J2` | `0x003D8E00` | `0x003D620D` | `0x003D61F8..0x003D6221`, inside `0x003D5374..0x003D8B20` |
| `: P.KillNotNeededBuses` | `0x0042C3EC` | `0x0042ADA0` | narrow checkpoint around `0x0042AD90..0x0042ADB0` |
| `: P.KillNotNeededCars` | `0x0042C428` | `0x0042AE2C` | narrow checkpoint around `0x0042AE20..0x0042AE40` |

`CV.Calculate` contains static checkpoints A through Y. J2 is therefore a
guarded stage inside the vehicle calculation routine, not part of
`TMap.RefreshObjectsKacheln`. The last runtime session shows both owners during
the same VAS collapse, so they should be treated as separate failing consumers
or observers until a caller relationship is demonstrated.

The runtime `TUV <number>` contexts were not resolved to a unique literal. A
plain `TUV` search matches alphabet/encoding tables, so assigning those hits to
an OMSI subsystem would be misleading. Keep `TUV` classified as a map/visibility
context based on the runtime neighborhood, with ownership still unresolved.

## Tooling correction

`ExportOmsiRvaContext.java` previously cleared and disassembled from a requested
RVA when no instruction contained it. String-pointer RVAs can sit in the middle
of an instruction, so that behavior could damage the analysis database. The
exporter is now read-only; the Ghidra project was rebuilt from `Omsi.exe` after
the correction.
