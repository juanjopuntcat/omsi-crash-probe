# OMSI weak-bucket static notes

Generated from static Ghidra analysis of `Omsi.exe`; OMSI was not launched.
No content folders were scanned.

## Why this pass

The roadmap still had lower-confidence buckets for:

- DirectSound / audio access violations
- invalid variable or command-name messages
- `Externe Exception C06D007E` / resource contention-style messages

The focused xref pass used `ExportOmsiStringXrefs.java` with targeted needles
through `Run-GhidraOmsiWeakBucketStringXrefs.ps1`.

Generated local artifacts:

- `ghidra-weak-bucket-string-xrefs.tsv`
- `ghidra-weak-bucket-rva-context.tsv`

These TSVs are intentionally ignored by git.

## DirectSound / WAV findings

The strongest result is the existing sound loader function:

```text
Omsi.exe+0x00405D60..0x004060DE
```

Focused string xrefs resolved sharper subpaths inside that function:

| String | String RVA | Xref RVA | Interpretation |
| --- | ---: | ---: | --- |
| `Sound load: Error while searching RIFF-chunk; MMSYSERR-Code =` | `0x0040611C` | `0x00405E32` | WAV RIFF chunk search error path. |
| `Sound load: Error while searching fmt-chunk; MMSYSERR-Code =` | `0x004061A8` | `0x00405E86` | WAV format chunk search error path. |
| `Sound load: Error while searching data-chunk; MMSYSERR-Code =` | `0x004062A4` | `0x00405F1B` | WAV data chunk search error path. |
| `Sound load: Error while creating DS Sound Buffer,` | `0x00406330` | `0x00405FC4` | DirectSound buffer creation failure path. |
| `Sound load: Error while locking DS Sound Buffer,` | `0x004063B4` | `0x00406046` | DirectSound buffer lock failure path. |

The buffer creation path calls through a COM-style vtable method at:

```text
0x00405F9A  MOV EAX,dword ptr [EAX]
0x00405F9C  CALL dword ptr [EAX + 0xc]
```

On failure it converts the HRESULT-style value and logs the `creating DS Sound
Buffer` message.

The buffer lock path calls another COM-style vtable method at:

```text
0x00406019  MOV EAX,dword ptr [EAX]
0x0040601B  PUSH EAX
0x0040601C  MOV EAX,dword ptr [EAX]
0x0040601E  CALL dword ptr [EAX + 0x2c]
```

On failure it logs the `locking DS Sound Buffer` message.

## DirectSound import resolver

The pass also found the dynamic import table setup around:

```text
Omsi.exe+0x0044E383..0x0044E483
```

That code references `DSound.dll`, `DirectSoundCreate`, `DirectSoundCreate8`,
and related capture/enumeration exports, and stores resolved addresses into
global slots. It is useful context when a stack points at DirectSound startup or
initialization, but it is less likely to be the owner of per-sound runtime
failures.

## Variable / command messages

This focused pass did not find a direct `Variablenname` xref in `Omsi.exe`.
The only command-related hit from the selected needles was:

```text
0x004322A8  Tastaturbefehle laden...
```

So the invalid variable-name bucket still needs either a resource-record pass or
a broader script/parser string search. It is not resolved by this xref pass.

The `T.PlugInRefrVars` text appears as data around:

```text
0x002F5F2C  : T.PlugInRefrVars
```

The pointer/context around `0x002F4F1D` did not produce a clean function in this
pass, so it should not become a precise label yet.

## External/resource-in-use messages

`Externe Exception %x` exists as a string at:

```text
0x004CD5FC
```

but Ghidra did not report a useful code xref in this pass. Treat this as Delphi
runtime exception formatting, not an OMSI subsystem owner.

The `Ressource` hits were mostly generic Delphi/VCL resource strings such as
`Systemressourcen erschopft` and `Ressource %s nicht gefunden`. The useful
graphics/resource-exhaustion paths are already covered in
`ghidra-memory-bitmap-notes.md`.

## Probe labels added

`OmsiCrashProbe.cpp` now labels:

- `0x00405E32..0x00405F1B`: WAV chunk validation path.
- `0x00405F84..0x00405FC9`: DirectSound buffer creation failure path.
- `0x00405FFE..0x0040604B`: DirectSound buffer lock failure path.
- `0x0044E383..0x0044E483`: DirectSound dynamic import resolver.

These are context labels only. The probe remains passive and does not hook,
patch, suppress, or handle any exception.
