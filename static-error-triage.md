# OMSI Static Error Triage

Generated from the clean static scan made on 2026-08-08 18:58.

Source files:

- `static-binary-inventory.tsv`
- `static-error-strings.tsv`
- `static-error-summary.md`
- `ghidra-omsi-string-xrefs.tsv`
- `ghidra-omsi-rva-context.tsv`
- `ghidra-direct3d-xref-notes.md`

Excluded directories:

- `SceneryObjects`
- `Sceneryobjects`
- `Splines`
- `maps`
- `OmniNavigation`
- `OmsiCrashProbe`
- `SDK`
- `Vehicles`
- `Addons`

The installed probe DLL under `plugins\OmsiCrashProbe.dll` is also excluded
from future scans so the reports describe OMSI and its dependencies, not our
diagnostic code.

## High-Signal Findings

### `Omsi.exe`

`Omsi.exe` contains the main user-visible error catalog we see in logfiles and
popups. Static strings confirm these families are engine/runtime-side:

- `Fehler bei Bereichsprüfung`
- `Zugriffsverletzung bei Adresse %p in Modul '%s'. %s von Adresse %p`
- `Zugriffsverletzung bei Adresse %p. %s von Adresse %p`
- `'%s' ist kein gültiger Gleitkommawert`
- `Gleitkommadivision durch Null`
- `Division durch Null`
- `Bitmap ist ungültig`
- `Argument außerhalb des Bereichs`
- `Listenindex überschreitet das Maximum (%d)`
- `Zu wenig Arbeitsspeicher`
- `Systemfehler. Code: %d.`
- `Direct3D-Device lost!`
- `Direct3D-Device resetted!`
- `Direct3D-Device-Reset schlug fehl, Fehler:`
- `Error while creating Direct3D-Device`

This means the next useful static step is not more string hunting; it is finding
the xrefs/callers for these exact strings in Ghidra and mapping them to RVAs.

### `dxerr9.dll`

`dxerr9.dll` is the DirectX error-name/description dictionary. It contains the
names OMSI can append after `Direct3D-Device-Reset schlug fehl, Fehler:`.

Relevant confirmed names include:

- `D3DERR_DEVICELOST`
- `D3DERR_DEVICENOTRESET`
- `D3DERR_INVALIDCALL`
- `D3DERR_OUTOFVIDEOMEMORY`
- `D3DERR_DRIVERINTERNALERROR`
- `D3DERR_DRIVERINVALIDCALL`
- `D3DERR_NOTAVAILABLE`
- `D3DERR_INVALIDDEVICE`
- `D3DXERR_INVALIDDATA`

This supports treating `D3DERR_*` text as HRESULT formatting, not as the place
where the Direct3D failure originates.

### `d3dx9.dll`

`d3dx9.dll` contains D3DX image, texture, mesh, shader, and resource-loader
strings. The useful families are:

- texture/image load APIs such as `D3DXCreateTextureFromFileInMemory`,
  `D3DXLoadSurfaceFromMemory`, and `D3DXGetImageInfoFromFileInMemory`
- `Out of Memory`
- `insufficient memory`
- `Invalid memory pool code %d`
- image parser messages such as unknown PNG/JPEG/zlib/compression errors

For OMSI crashes, this DLL is likely a callee or HRESULT source for texture and
image-load failures. The owner is probably the OMSI caller that fed it bad data,
oversized data, or exhausted resources.

### `qtintf.dll` / `qtintf70.dll`

The Qt interface DLLs contain bitmap, image, and memory strings:

- `CreateBitmap`
- `CreateCompatibleBitmap`
- `CreateDIBitmap`
- `Not enough memory`
- `bad alloc exception thrown`
- `Invalid bit depth for RGB image`
- `Invalid bit depth for RGBA image`
- `QDataStream: Not enough memory to read QByteArray`

These are relevant to bitmap/GDI/resource-pressure errors, but should be treated
separately from OMSI's Delphi exception catalog.

### `BaseType.dll` / `fontsPr.dll`

These contain mostly CryptoPP and C++ runtime exception strings:

- `CryptoPP: invalid group element`
- `invalid string position`
- `_CxxThrowException`
- `UnhandledExceptionFilter`

This looks low priority for the common OMSI crash families unless a runtime log
specifically points at these modules.

### Plugins And Tools

The scan also found strings in `plugins\GPM.dll`, `plugins\SuperRadio.dll`,
`plugins\OmniNavigationDll.dll`, `DEMImport\SRTM\Import.dll`, patchers, and the
uninstaller. Keep these in a separate bucket from base OMSI analysis. They can
raise their own exceptions, but they are not the first target for engine fixes.

## Next Static Step

Ghidra headless has resolved the Direct3D-facing strings. See
`ghidra-direct3d-xref-notes.md` for the confirmed RVAs:

- `Omsi.exe+0x002793A8..0x0027992B`: Direct3D device creation failure path.
- `Omsi.exe+0x00429FD8..0x0042A412`: Direct3D device lost/reset/failure path.

The next static step is to continue the same Ghidra workflow for non-Direct3D
families whose strings are stored in Delphi runtime/resource tables:

- string text
- file offset
- VA/RVA
- functions that reference it
- nearby calls such as `RaiseException`, Direct3D reset calls, bitmap/GDI calls,
  string/float conversion, and list/range checks

That will turn the current catalog into a patch/probe roadmap without opening
OMSI.
