# OmsiCrashProbe

`OmsiCrashProbe` is a minimal OMSI 2 diagnostic plugin for engine-side crash
attribution. The probe DLL does not patch OMSI or try to handle exceptions. It
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
Newer snapshots also include a compact VAS layout summary: the number of free
ranges, the top three free block sizes, committed region counts, and committed
private/mapped/image megabytes. This makes fragmentation visible without dumping
the full address map.
Current snapshots additionally report total reserved VAS, the top three
reserved block sizes, and private/mapped/image committed-region counts.
Each session also records the first observed crossing of the 256, 128, 64, 32,
and 16 MB largest-free-block thresholds without performing extra VAS scans.

The session analyzer also includes a known-error catalog for recurring OMSI
messages such as Direct3D reset failures, range/list checks, invalid float
conversions, Systemfehler Code 8, bitmap/image failures, and access violations
in OMSI or DirectX/audio modules. It summarizes Direct3D reset HRESULTs,
separates Systemfehler Code 8 into context buckets, correlates timed failures
with nearby memory/resource snapshots, emits a VAS exhaustion verdict, and
builds a combined "top suspicious signals" table across `logfile.txt` and
`probe.log`. These labels are triage hints that should be cross-checked against
RVAs, stack candidates, and memory snapshots.

Run the offline analyzer regression fixtures with:

```powershell
.\Test-AnalyzeOmsiCrashSession.ps1
```

The fixtures cover Code 8 ownership buckets and precursors, Direct3D/texture
errors, old and current VAS snapshot formats, threshold crossings, and KnownRVA
signature labels. The GitHub build workflow runs the same suite.

Run the x86 white-box handler tests without launching OMSI:

```bat
Test-OmsiCrashProbeCore.bat
```

They cover exact stack-cache hits and collisions, signature-table saturation,
handler-side lock contention, and saturating counters.

## Large Address Aware

`Set-OmsiLargeAddressAware.bat` enables the PE
`IMAGE_FILE_LARGE_ADDRESS_AWARE` flag through Microsoft's `EDITBIN`. Make and
verify a backup of `Omsi.exe` before running it. Steam verification or an update
may replace the executable and remove the flag.

Each new probe session logs `ExecutableFlags`, and the analyzer reports the LAA
state and PE characteristics so replacement is detected immediately.

The current investigation map lives in `known-error-roadmap.md`. It lists which
common OMSI error families already have static RVA anchors and which ones still
need focused Ghidra passes.

Focused Ghidra notes are kept as small project-authored markdown files. For
example, `ghidra-weak-bucket-notes.md` documents the DirectSound/WAV subpaths
used to sharpen audio crash attribution.
`ghidra-map-vehicle-notes.md` separates the `CV.Calculate - J2`,
`map.translate`, AI cleanup, and map refresh checkpoints observed around VAS
exhaustion.
`ghidra-resource-lifecycle-notes.md` maps PhysObj collision load/unload,
Direct3D texture creation/release, and Delphi VirtualAlloc/VirtualFree paths.
`ghidra-script-parser-notes.md` maps invalid variable, macro, constant, and
function-name diagnostics to their exact parser branches.
`ghidra-stream-callers-notes.md` records the generic stream-helper fan-out and
the narrower read/write chains that require a higher caller for attribution.

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

For `Externe Exception %x` / `C06D007E`, local resource-record analysis showed
`Omsi.exe+0x00028E06..0x00028E1E` as a Delphi external-exception constructor.
That is a formatting/constructor path, so the caller above it is usually more
important than the constructor itself.

In the 2026-08-09 session, the analyzer correlated `Systemfehler. Code: 8`
bursts with the largest free 32-bit virtual-address block dropping to 0 MB.
Follow-up Ghidra analysis labeled `Omsi.exe+0x0039CC30..0x0039EDD0` as the
`TMap.RefreshObjectsKacheln` map-object tile refresh loop, with
`Omsi.exe+0x0039C9D0..0x0039CC29` as a nested object update path that calls the
Delphi conversion wrapper.

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

- The loaded probe DLL performs no binary patching.
- The separate patch transport defaults to audit mode and currently has no
  approved patches.
- No exception suppression.
- The probe DLL writes only `<OMSI root>\OmsiCrashProbe\probe.log`.
- Version-independent, because it only observes process exceptions.
- Uses a fixed-size in-process signature table for deduplication, with no heap
  allocation in the exception path.
- Caches the loaded module list at plugin startup so stack/RVA resolution does
  not take Toolhelp snapshots during noisy exception bursts.
- Builds that immutable module snapshot before installing the handler. Modules
  loaded later remain unresolved until another session because querying the
  Windows loader from exception context could deadlock on the loader lock.
- Filters stack return candidates to executable committed memory, so pointers
  into module data sections are not treated as probable caller frames.
- Keeps memory/resource snapshots sparse because the virtual-address walk is
  useful but should not run on every repeated first-chance exception.
- Caches executable-page protection checks during stack scans while preserving
  the existing executable-memory filter and exact exception signatures.
- Caches page-to-module lookups, including negative results, so repeated stack
  scans do not linearly search the complete module table for every stack word.
- Reuses a computed signature only when all 48 captured stack words plus the
  exception identity match exactly. This avoids repeated module/protection
  resolution without sampling or merging different raw stacks.
- Uses non-blocking handler-side logging locks and bounded signature-table
  overflow accounting so probe contention cannot become a deadlock or log
  storm. Final `ProbeHealth` counters make any dropped diagnostics explicit.
- Keeps one append-only `probe.log` handle per session and emits each record
  with one `WriteFile`; it deliberately avoids synchronous flushes in exception
  context because they would stall the game on every diagnostic record.
- Stops accepting callbacks before finalization and waits up to two seconds for
  active handlers to leave DLL code before destroying shared state.
- Delphi object/string decoding uses guarded memory reads and simply omits the
  decoded fields when the guessed layout is not valid.
- Known-RVA classification is static text based on local Ghidra analysis; it
  does not hook or alter OMSI code.

## Guarded patching groundwork

`Patch-OmsiRuntime.ps1` and the intentionally empty `patch-manifest.json` form
the transport for future verified fixes; they are not currently an OMSI patch.
Audit is the default mode. Applying a future entry requires an approved SHA-256,
matching PE identity, exact file offset, and exact original bytes. See
`patching-design.md` and `ghidra-public-access-violation-notes.md`.

`patch-candidates.json` is a separate, non-applicable research catalog. The
planned native Windows interface is described in `gui-design.md`; it will use
the same guarded core rather than implementing binary writes in the UI.

`OmsiPatchTool.exe` is the first native consumer of `PatchCore`. Its current
commands are read-only and emit JSON:

```powershell
.\OmsiPatchTool.exe inspect "E:\SteamLibrary\steamapps\common\OMSI 2\Omsi.exe"
.\OmsiPatchTool.exe rva "E:\SteamLibrary\steamapps\common\OMSI 2\Omsi.exe" 0x00428140
```

Build it with `build-patch-tool.bat`. The executable uses the static MSVC
runtime so OMSI's adjacent legacy runtime DLLs cannot satisfy its dependencies.

## Native GUI

`OmsiCrashProbe.exe` is the native Win32 front end. Build it with
`build-gui.bat`. Version `0.1.0.0` provides:

- selection and inspection of `Omsi.exe`;
- SHA-256 profile compatibility and Large Address Aware status;
- a compiled-in catalog of the documented bug families and current candidates;
- visible fix state, confidence, RVA, and the static finding; and
- manifest-bound Apply and Rollback actions for individually selected fixes.

Activating a bug row, or pressing `Review selected bug`, opens a native review
dialog with the finding, category, confidence, RVA, proposed solution, and
current compatibility state. Bugs without an approved fix remain informational.
The Apply and Rollback commands remain visible so the lifecycle is clear, but
both are disabled unless the audited state permits exactly one of them.
Compatible fixes enable Apply; installed fixes enable Rollback. Patch ID,
target, and backup path remain available as expandable technical details.

The compact native workspace uses a restrained high-contrast header, grouped
installation status, alternating table rows, contextual fix-state colors, and
a stable responsive layout with a minimum usable window size.

The bug table supports ascending and descending sorting from every column
header. Its filter can show all bugs, only bugs with an approved manifest fix,
or only bugs without one. Filtering is based on manifest ownership, so applied
and currently incompatible fixes still remain in the approved-fix view. That
view enables a second filter for any patch state, not applied, or applied;
"not applied" includes compatible and incompatible fixes that are absent from
the selected installation.

Additional table filters narrow the catalog by category and confidence. A
case-insensitive search field matches bug names and descriptions, and all
filters compose with sorting and the manifest/installation-state filters.

The header includes an About dialog and a GitHub contribution link. `Back up
Omsi.exe` validates the selected PE32 executable and creates a non-overwriting,
timestamped copy under `<OMSI>\OmsiCrashProbe\backups`. This manual snapshot is
separate from the patch-specific backups created transactionally by Apply.

The shared native core provides tested audit, apply, backup, atomic replace,
and rollback primitives. The GUI obtains every offset and byte sequence from
the validated manifest; it never duplicates patch data in UI code.

The native manifest reader now validates schema version 1 with
`nlohmann/json` 3.12.0. It rejects unknown keys, unsafe relative paths,
duplicate IDs or RVAs, malformed hexadecimal values, and invalid byte
sequences. It selects a patch only when SHA-256, PE timestamp, and image size
all match. The
GUI binds entries to documented bugs by RVA, audits each target, and distinguishes
available, applied, and incompatible fixes. Apply and Rollback require explicit
confirmation and are blocked while OMSI is running. They remain disabled while
the committed manifest is empty.

Third-party notices and licenses are documented in `THIRD_PARTY_NOTICES.md` and
packaged with release artifacts.

The executable embeds its DPI/Common Controls manifest and Windows version
resource, including product name, description, author, copyright, file/product
version, original filename, and MIT license note. It is a native x86 Windows
application linked to the static MSVC runtime.

Use this alongside Windows Error Reporting dumps for fatal crashes. The probe is
especially useful for Delphi/logged exceptions that do not terminate the process.

## License

The probe source code, helper scripts, and original documentation in this
repository are licensed under the MIT License. See `LICENSE`.
