# OMSI Known Error Roadmap

This roadmap turns the recurring public/runtime OMSI errors into practical
debugging buckets. It is based on local probe sessions, static strings,
resource-record analysis, and Ghidra RVA labels already present in
`OmsiCrashProbe.cpp`.

It is not a patch plan yet. The purpose is to decide what we can already
classify and what still needs static caller analysis before any hardening is
even considered.

## Current Coverage

| Error family | Coverage | Static anchors already known | Runtime evidence to prefer | Next useful work |
| --- | --- | --- | --- | --- |
| Direct3D device lost/reset | High | `0x00429FD8..0x0042A412`, `0x004029AC..0x00402B80`, `dxerr9.dll` error names | `D3DERR_DEVICELOST`, `D3DERR_INVALIDCALL`, reset-failed log text, stack candidates in the reset path | Analyzer now highlights reset HRESULTs separately from texture allocation failures; validate with future sessions. |
| Direct3D texture allocation / `E_OUTOFMEMORY` | High | creation `0x0024307C..0x00244AB3`, `0x003F891C..0x003F933B`; release `0x003F7258`, `0x003F9C48`, `0x003F9E30` | allocation errors, release refcount warnings, VAS layout | Creation and release owners are mapped; runtime data must distinguish retained references, delayed cleanup, and fragmentation. |
| `Systemfehler. Code: 8` / OS memory resources | High | `0x0002A000..0x0002A09E`, `0x000769E4..0x0007720C`, `0x002D753C..0x002D77B3` | Code 8 log lines, following context tag, VAS/GDI/USER snapshots | Analyzer now separates Code 8 contexts and emits a VAS exhaustion verdict with min largest-free block, dominant context, and texture signals. |
| Bitmap/image failures | High | `0x00070890..0x000708B2`, `0x000708CC..0x00070916`, `0x00072F90..0x00073009`, `0x00078964..0x0007899F`, `0x00098000..0x00098017` | `Bitmap ist ungueltig`, `Unbekannte Bilddateierweiterung`, `Ungueltiges Bild`, `Systemressourcen erschoepft` | Add analyzer hints that tie bitmap failures to GDI/resource counters when snapshots exist. |
| Delphi range/list/argument checks | High | `0x0002ADCC..0x0002C81F`, `0x0004DD85..0x0004DDA9`, `0x000B57F4..0x000B58ED`, `0x00120818..0x00120863`, `0x0011FF8C..0x001243B7`, `0x0020AEA4..0x0020CC14`, `0x0034B148..0x0034C858` | `Fehler bei Bereichspruefung`, `Listenindex ueberschreitet das Maximum`, `Argument ausserhalb des Bereichs`, caller stack above helper | Probe signatures now prefer owner-like OMSI frames over generic Delphi helpers; validate with the next runtime session. |
| Invalid float / float divide by zero | Medium-high | `0x00024F68..0x00024FA9`, `0x00011610..0x00011611`, parser clusters `0x001AB9B8..0x003B90B0` | `Gleitkommawert`, `Gleitkommadivision durch Null`, `EZeroDivide`, parser-cluster KnownRVA labels | Add source-context extraction for nearby logfile text so invalid numeric tokens are easier to identify. |
| Stream read/write failures | Medium | `0x0004DF1C..0x00054B2E`, `0x0004EB15..0x0004EB34` | `Stream-Lesefehler`, `Stream-Schreibfehler`, preceding/following load messages | Find higher-level callers of the stream helpers and label the common file-loader owners. |
| Script variable / invalid command names | High | parser `0x001D1E68..0x001D4076`; variable `0x001D378D..0x001D37E3`; macro `0x001D38D1..0x001D3ABC`; constant `0x001D3BAA..0x001D3C27`; function `0x001D3DE1..0x001D3E52` | `Variablenname ungueltig`, command text, source context and vehicle path already in logfile | The four resource keys and their negative symbol-lookup branches are mapped; validate future stacks against the narrow paths. |
| Map/vehicle update bursts | Medium | `0x002F359C..0x002F3981`, `0x0039C9D0..0x0039EDD0`, `0x003D5374..0x003D8B20`, J2 `0x003D61F8..0x003D6221` | `CV.Calculate`, `map.translate`, `TUV`, VAS largest-free block, caller stacks | Static xrefs now separate the vehicle J2 checkpoint from `TMap.RefreshObjectsKacheln`; validate their runtime ordering in the next session. |
| PhysObj duplicate collision load | High | load `0x003AE8E0..0x003AEC00`, unload `0x003AE554`, owner pair `0x003AB110..0x003AB3FF` | duplicate collision warning, tile refresh timing, reserved VAS blocks | Load and unload are statically symmetric; investigate runtime load-before-unload ordering and repeated owner identity. |
| DirectSound / audio access violations | Medium | `0x00405D60..0x004060DE`, plus `0x00405E32..0x00405F1B`, `0x00405F84..0x00405FC9`, `0x00405FFE..0x0040604B`, `0x0044E383..0x0044E483` | AVs in `DSound.dll`, sound load timing, stack candidates in WAV/DirectSound subpaths | Sharper labels are implemented; validate with future runtime stacks pointing at DirectSound/audio paths. |
| Raw AVs in `Omsi.exe` | Low until stack/RVA is known | Generic Delphi helpers: `0x00006B0C`, `0x00006E68`, `0x0000884C`, plus any KnownRVA stack candidate | Faulting module, read/write address, first two OMSI stack candidates, KnownRVA hits | Analyzer groups final signatures by probable owner; continue adding labels when a stable owner RVA appears. |
| External exception `C06D007E` / resource in use | Medium-low | `0x00028E06..0x00028E1E` Delphi external exception constructor | Module name, surrounding logfile lines, caller above constructor, plugin involvement | Runtime stacks should skip the constructor and prioritize the caller/owner frame. |
| Missing context-sensitive help | Very low | Likely Delphi/VCL help system, no crash-critical anchor | `Keine kontextsensitive Hilfe installiert` | Keep catalogued but deprioritized unless it appears adjacent to fatal errors. |

## Immediate Static Priorities

1. Find higher-level callers of the stream read/write helpers and label common
   file-loader owners.
2. Add source-context extraction for invalid numeric tokens and script parser
   diagnostics already present in `logfile.txt`.
3. Use the analyzer's top suspicious signals section after each session to pick
   the next narrow static pass instead of repeatedly launching OMSI.
4. Keep release automation separate from diagnostics. Release tags package the
   probe, but runtime behaviour remains passive and unchanged.

## Interpretation Rules

- A KnownRVA label is a context hint, not proof of root cause.
- Delphi helper RVAs usually mean "look one caller higher".
- DirectX and driver DLL AVs often identify the boundary where a bad state was
  observed, not the OMSI owner that created the bad state.
- `Systemfehler. Code: 8` should always be interpreted with memory, VAS
  fragmentation, GDI handles, USER handles, and texture pressure together.
- A low largest-free VAS block is more important than total free VAS for large
  Direct3D/GDI allocations in a 32-bit process.
- One-shot 256/128/64/32/16 MB threshold records locate the first observed VAS
  pressure transition without adding address-space walks between snapshots.
- Asset paths in reports must come only from OMSI's own log text. Do not scan
  `SceneryObjects`, `Splines`, `maps`, `OmniNavigation`, `Vehicles`, `Addons`,
  or `SDK`.
