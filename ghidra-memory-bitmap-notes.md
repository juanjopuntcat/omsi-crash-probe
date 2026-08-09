# OMSI memory, stream, and bitmap exception notes

Generated from static Ghidra/resource analysis of `Omsi.exe`; OMSI was not
launched. The scan stayed inside the controlled `_source` analysis path and did
not traverse `SDK`, `Addons`, `SceneryObjects`, `Splines`, `maps`,
`OmniNavigation`, or `Vehicles`.

## New artifacts

- `Export-OmsiResourceStrings.ps1`
- `omsi-resource-strings.tsv`
- `ExportOmsiResourceRecordRefs.java`
- `Run-GhidraOmsiResourceRecordRefs.ps1`
- `ghidra-resource-record-refs.tsv`

## Method

`Export-OmsiResourceStrings.ps1` loads `Omsi.exe` with
`LOAD_LIBRARY_AS_DATAFILE` and resolves string resources with `LoadStringW`.
This maps the executable as data and does not execute OMSI code.

`ExportOmsiResourceRecordRefs.java` then searches Ghidra's initialized memory
for Delphi `TResStringRec`-style records:

```text
DWORD module/resource handle slot
DWORD resource id
```

For each selected resource ID it exports the record location, references to the
record, the containing function when Ghidra has one, and a short instruction
window around the reference.

## High-signal resource IDs

| Resource | ID | Log family |
| --- | ---: | --- |
| `Zu wenig Arbeitsspeicher` | `0xFFF6` | Out-of-memory Delphi exception. |
| `Zu wenig Speicherplatz` | `0xFFFB` | Storage/space-style resource, mostly data refs. |
| `Systemressourcen erschoepft` | `0xFF2F` | GDI/graphics/resource exhaustion. |
| `Fuer diese Anforderung steht nicht genuegend Speicher zur Verfuegung` | `0xFDF1` | Windows-style not-enough-memory message copied by OMSI. |
| `Bitmap ist ungueltig` | `0xFF24` | Invalid bitmap helper. |
| `Ungueltiges Bild` | `0xFF28` | Invalid image path. |
| `Unbekannte Bilddateierweiterung (.%s)` | `0xFF2D` | Unsupported image extension, including PNG in older image paths. |
| `Fehler beim Erstellen des Fenster-Geraetekontexts` | `0xFF18` | Window device-context creation failure. |
| `Systemfehler. Code: %d` | `0xFFCF` | OS error wrapper, already tied to the system-error raiser. |
| `Expandieren des Speicher-Stream wegen Speichermangel nicht moeglich` | `0xFF76` | Memory stream grow/allocation failure. |
| `Stream-Lesefehler` | `0xFF79` | Stream read failure. |
| `Stream-Schreibfehler` | `0xFF63` | Stream write failure. |

## RVA labels added to the probe

These ranges were added to `kKnownOmsiRvas` so future runtime logs can attach a
plain-language subsystem label:

| RVA range | Label | Why it matters |
| --- | --- | --- |
| `0x00028EA4..0x00028EB6` | Delphi out-of-memory exception constructor | Builds the `Zu wenig Arbeitsspeicher` exception object. |
| `0x00030ADC..0x00030CF9` | Delphi resource exception constructor path | Builds localized resource-backed exception objects, including OOM variants. |
| `0x0004DF1C..0x0004DF70` | Stream read error helper | Raises `Stream-Lesefehler` after a read callback returns no positive byte count. |
| `0x0004DF7C..0x0004DFD0` | Stream read error helper 2 | Alternate callback path for `Stream-Lesefehler`. |
| `0x0004EB15..0x0004EB34` | Memory stream expansion failure path | Raises the memory-stream expansion failure resource. |
| `0x0004FF78..0x0004FFAA` | Stream read error path | Raises `Stream-Lesefehler` after a read/fill operation returns zero. |
| `0x00052684..0x000527B6` | Stream read validation path | Raises `Stream-Lesefehler` after stream validation/read helper failure. |
| `0x0005284C..0x00052A38` | Stream read block path | Raises `Stream-Lesefehler` after a block read helper failure. |
| `0x00054ADC..0x00054B2E` | Stream write error path | Raises `Stream-Schreibfehler` after a write helper failure. |
| `0x00070890..0x000708B2` | Bitmap invalid helper | Raises `Bitmap ist ungueltig`. |
| `0x000708CC..0x00070916` | System resources exhausted graphics helper | Raises `Systemressourcen erschoepft` through the graphics path. |
| `0x00072F90..0x00073009` | Unknown image extension path | Raises the unsupported image extension resource. |
| `0x00078964..0x0007899F` | Invalid image path | Raises `Ungueltiges Bild` after image state/flag validation fails. |
| `0x00098000..0x00098017` | Window device context creation failure | Raises the window DC creation failure resource after a null return. |
| `0x0013AFC8..0x0013B018` | System resources exhausted init path | Raises `Systemressourcen erschoepft` after an init/allocation result is null. |
| `0x002D753C..0x002D77B3` | Request not enough memory resource path | References the not-enough-memory request string. |

## Interpretation

These findings do not prove a single root cause for every memory/bitmap log.
They give us better buckets:

- Delphi/RTL memory exceptions: `0x00028EA4`, `0x00030ADC`, and the active
  exception raiser above them.
- Stream failures: clustered in low Delphi stream helpers around
  `0x0004DF1C..0x00054B2E`; the caller above the helper will usually identify
  the file or asset loader.
- Bitmap/image failures: clustered around `0x00070890`, `0x00072F90`, and
  `0x00078964`.
- GDI/resource exhaustion: `0x000708CC`, `0x00098000`, and `0x0013AFC8`;
  these should be interpreted together with the probe's GDI/USER handle and
  virtual-address-space snapshots.

The practical gain is that a future first-chance exception or fatal log can say
"this is the stream read helper" or "this is the graphics resource exhaustion
path" instead of only showing an OMSI RVA.
