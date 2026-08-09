# OmsiCrashProbe

`OmsiCrashProbe` is a minimal OMSI 2 diagnostic plugin for engine-side crash
attribution. It does not patch OMSI and does not try to handle exceptions. It
only installs a vectored exception handler, logs interesting first-chance
exceptions, then returns `EXCEPTION_CONTINUE_SEARCH` so OMSI and Windows keep
their normal behavior.

The source code is heavily commented because this tool is meant to become a
shared debugging base, not a black box.

## Scope and Ownership

This repository contains only the probe source code, helper scripts, and
project-authored analysis notes. It does not contain OMSI 2, `Omsi.exe`, DirectX
runtime DLLs, Ghidra projects, decompiled game code, or extracted bulk string
dumps from proprietary binaries.

OMSI 2 and all related game assets remain the property of their respective
rights holders. This project is an independent diagnostic tool and does not
grant any license to redistribute or modify OMSI 2.

## What It Logs

The plugin writes to:

```text
<OMSI root>\OmsiCrashProbe\probe.log
```

For relevant exceptions it records:

- exception code and friendly name
- exception address
- faulting module
- module base
- RVA / `module+offset`
- raw exception parameters
- best-effort Delphi exception class/message decoding for `0x0EEDFADE`
- access type and target for access violations
- x86 registers
- module path
- known OMSI RVA labels for Ghidra-inspected engine/runtime hotspots
- stack values that look like return addresses, resolved to `module+RVA`
- repeated exception signatures grouped by owner-like OMSI frames when possible,
  skipping generic Delphi helper frames when deeper OMSI stack candidates exist
- sparse memory/resource snapshots at plugin start, plugin shutdown, and selected
  full exception captures
- repeated exception signatures are rate-limited after the first few full
  captures, then logged only at count milestones

It also logs the loaded module list when the plugin starts.

Memory snapshots include process private memory, working set, pagefile usage,
available system commit/physical memory, total free 32-bit virtual address
space, largest free virtual address block, and current GDI/USER object counts.
The largest free virtual block is especially useful for OMSI because a patched
32-bit executable can still fail when the address space becomes fragmented.
New snapshots include a local timestamp so the analyzer can correlate resource
pressure with logfile events such as texture `E_OUTOFMEMORY` bursts.

The session analyzer also includes a known-error catalog for recurring OMSI
messages such as Direct3D reset failures, range/list checks, invalid float
conversions, Systemfehler Code 8, bitmap/image failures, and access violations
in OMSI or DirectX/audio modules. These labels are triage hints that should be
cross-checked against RVAs, stack candidates, and memory snapshots.

The current investigation map lives in `known-error-roadmap.md`. It lists which
common OMSI error families already have static RVA anchors and which ones still
need focused Ghidra passes.

Focused Ghidra notes are kept as small project-authored markdown files. For
example, `ghidra-weak-bucket-notes.md` documents the DirectSound/WAV subpaths
used to sharpen audio crash attribution.

Known RVA labels are context hints only. For example, an exception inside a
Delphi managed-string helper usually means the useful owner is the caller that
passed the bad string, not the helper itself.

Some Delphi exception parameters point at exception-class stubs rather than
normal code. For example, local Ghidra analysis showed `Omsi.exe+0x00011610`
is referenced by the string-to-float parser for invalid `Gleitkommawert`
errors, while `Omsi.exe+0x000120A0` is referenced by integer conversion
wrappers for invalid `Integer-Wert` errors.

For `Systemfehler. Code: 8`, local Ghidra analysis showed
`Omsi.exe+0x0002A000` / `Omsi.exe+0x0002A00C` as Delphi's system-error raising
path around `GetLastError()`. In the 2026-08-05 labeled session, its useful
caller context included `Omsi.exe+0x0007702B`, inside a BMP/GDI bitmap load
path that calls `CreateDIBSection` / `CreateDIBitmap`.

## Interesting Exception Codes

```text
0x0EEDFADE Delphi exception
0xC0000005 access violation
0xC000008C array bounds exceeded
0xC0000094 integer divide by zero
0xC0000095 integer overflow
0xC000008E floating-point divide by zero
0xC0000090 floating-point invalid operation
0xC000001D illegal instruction
0xC00000FD stack overflow
```

## Build

Build as 32-bit. OMSI 2 is a 32-bit process, so a 64-bit DLL will not load.

Example from a Visual Studio Developer Command Prompt configured for x86:

```bat
cmake -S . -B build-x86 -A Win32
cmake --build build-x86 --config Release
```

Or without CMake, from an x86 Native Tools Command Prompt:

```bat
build-msvc-x86.bat
```

The output DLL should be:

```text
build-x86\Release\OmsiCrashProbe.dll
```

GitHub Actions also builds the Win32 Release DLL on every push and pull request.
The build workflow artifact is a zip containing:

```text
OmsiCrashProbe.dll
OmsiCrashProbe.opl
```

Tags named `v*`, for example `v0.1.0`, also run the release-package workflow.
That workflow builds the same Win32 plugin zip, uploads it as a GitHub Actions
artifact, and creates a GitHub Release with the zip attached.

## Install

Copy these two files into:

```text
<OMSI root>\plugins\
```

```text
OmsiCrashProbe.dll
OmsiCrashProbe.opl
```

Then start OMSI normally or through the crash kit.

There is also a helper installer:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-OmsiCrashProbe.ps1
```

## Expected OMSI Plugin Shape

Existing OMSI plugins export names like:

```text
PluginStart
PluginFinalize
AccessVariable
AccessStringVariable
AccessSystemVariable
AccessTrigger
```

Observed `PluginStart` in `SuperRadio.dll` returns with `ret 4`, so this probe
exports:

```cpp
void __stdcall PluginStart(void* omsiContext);
void __stdcall PluginFinalize();
```

The `.def` file aliases the x86 decorated names back to the undecorated export
names OMSI expects:

```text
PluginStart=_PluginStart@4
PluginFinalize=_PluginFinalize@0
```

The probe uses no OMSI variables, so the `.opl` intentionally contains only the
`[dll]` section.

`OmsiCrashProbe.opl` is deliberately left without comments because OMSI plugin
descriptor parsing is simple and may not accept comment syntax consistently:

```text
[dll]
OmsiCrashProbe.dll
```

## Safety

- No binary patching.
- No exception suppression.
- No file writes outside `<OMSI root>\OmsiCrashProbe\probe.log`.
- Version-independent, because it only observes process exceptions.
- Uses a fixed-size in-process signature table for deduplication, with no heap
  allocation in the exception path.
- Caches the loaded module list at plugin startup so stack/RVA resolution does
  not take Toolhelp snapshots during noisy exception bursts.
- Keeps memory/resource snapshots sparse because the virtual-address walk is
  useful but should not run on every repeated first-chance exception.
- Delphi object/string decoding uses guarded memory reads and simply omits the
  decoded fields when the guessed layout is not valid.
- Known-RVA classification is static text based on local Ghidra analysis; it
  does not hook or alter OMSI code.

Use this alongside Windows Error Reporting dumps for fatal crashes. The probe is
especially useful for Delphi/logged exceptions that do not terminate the process.

## License

The probe source code, helper scripts, and original documentation in this
repository are licensed under the MIT License. See `LICENSE`.
