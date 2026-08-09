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
| Direct3D device lost/reset | High | `0x00429FD8..0x0042A412`, `0x004029AC..0x00402B80`, `dxerr9.dll` error names | `D3DERR_DEVICELOST`, `D3DERR_INVALIDCALL`, reset-failed log text, stack candidates in the reset path | Add a session summary section that highlights reset HRESULTs separately from texture allocation failures. |
| Direct3D texture allocation / `E_OUTOFMEMORY` | High | `0x00243F10..0x00243F7B`, `0x0024307C..0x00244AB3`, `0x003F891C..0x003F933B`, `0x002F9F89..0x002FA083` | `Texturladen - Direct9 Error`, `Texture "... " failed!`, VAS largest-free block, private memory, GDI/USER counts | First/last failure timing, Direct9 error-code summaries, and nearest timed memory-snapshot correlation are implemented for future probe logs. |
| `Systemfehler. Code: 8` / OS memory resources | High | `0x0002A000..0x0002A09E`, `0x000769E4..0x0007720C`, `0x002D753C..0x002D77B3` | Code 8 log lines, following context tag, VAS/GDI/USER snapshots | Separate Code 8 contexts into graphics/GDI, texture, vehicle/script, and unknown buckets. |
| Bitmap/image failures | High | `0x00070890..0x000708B2`, `0x000708CC..0x00070916`, `0x00072F90..0x00073009`, `0x00078964..0x0007899F`, `0x00098000..0x00098017` | `Bitmap ist ungueltig`, `Unbekannte Bilddateierweiterung`, `Ungueltiges Bild`, `Systemressourcen erschoepft` | Add analyzer hints that tie bitmap failures to GDI/resource counters when snapshots exist. |
| Delphi range/list/argument checks | High | `0x0002ADCC..0x0002C81F`, `0x0004DD85..0x0004DDA9`, `0x000B57F4..0x000B58ED`, `0x00120818..0x00120863`, `0x0011FF8C..0x001243B7`, `0x0020AEA4..0x0020CC14`, `0x0034B148..0x0034C858` | `Fehler bei Bereichspruefung`, `Listenindex ueberschreitet das Maximum`, `Argument ausserhalb des Bereichs`, caller stack above helper | Probe signatures now prefer owner-like OMSI frames over generic Delphi helpers; validate with the next runtime session. |
| Invalid float / float divide by zero | Medium-high | `0x00024F68..0x00024FA9`, `0x00011610..0x00011611`, parser clusters `0x001AB9B8..0x003B90B0` | `Gleitkommawert`, `Gleitkommadivision durch Null`, `EZeroDivide`, parser-cluster KnownRVA labels | Add source-context extraction for nearby logfile text so invalid numeric tokens are easier to identify. |
| Stream read/write failures | Medium | `0x0004DF1C..0x00054B2E`, `0x0004EB15..0x0004EB34` | `Stream-Lesefehler`, `Stream-Schreibfehler`, preceding/following load messages | Find higher-level callers of the stream helpers and label the common file-loader owners. |
| Script variable / invalid command names | Medium-low | `0x00241C38..0x002425A8` for vehicle/script state stringvars, plus generic parser paths | `Variablenname ungueltig`, command text, vehicle path already in logfile | The weak-bucket string xref pass did not resolve this; next try resource-record/script-parser focused analysis. |
| DirectSound / audio access violations | Medium | `0x00405D60..0x004060DE`, plus `0x00405E32..0x00405F1B`, `0x00405F84..0x00405FC9`, `0x00405FFE..0x0040604B`, `0x0044E383..0x0044E483` | AVs in `DSound.dll`, sound load timing, stack candidates in WAV/DirectSound subpaths | Sharper labels are implemented; validate with future runtime stacks pointing at DirectSound/audio paths. |
| Raw AVs in `Omsi.exe` | Low until stack/RVA is known | Generic Delphi helpers: `0x00006B0C`, `0x00006E68`, `0x0000884C`, plus any KnownRVA stack candidate | Faulting module, read/write address, first two OMSI stack candidates, KnownRVA hits | Improve analyzer output so AVs are grouped by probable owner frame rather than exception address alone. |
| External exception `C06D007E` / resource in use | Low | No sharp OMSI anchor yet | Module name, surrounding logfile lines, plugin involvement | Static string/import pass for resource-contention text and Windows exception boundary paths. |
| Missing context-sensitive help | Very low | Likely Delphi/VCL help system, no crash-critical anchor | `Keine kontextsensitive Hilfe installiert` | Keep catalogued but deprioritized unless it appears adjacent to fatal errors. |

## Immediate Static Priorities

1. Run focused Ghidra passes for unresolved weak buckets:
   invalid variable-name messages and external/resource-in-use exceptions.
2. Keep release automation separate from diagnostics. Release tags package the
   probe, but runtime behaviour remains passive and unchanged.

## Interpretation Rules

- A KnownRVA label is a context hint, not proof of root cause.
- Delphi helper RVAs usually mean "look one caller higher".
- DirectX and driver DLL AVs often identify the boundary where a bad state was
  observed, not the OMSI owner that created the bad state.
- `Systemfehler. Code: 8` should always be interpreted with memory, VAS
  fragmentation, GDI handles, USER handles, and texture pressure together.
- Asset paths in reports must come only from OMSI's own log text. Do not scan
  `SceneryObjects`, `Splines`, `maps`, `OmniNavigation`, `Vehicles`, `Addons`,
  or `SDK`.
