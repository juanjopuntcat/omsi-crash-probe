# OMSI range/list exception notes

Generated from static Ghidra analysis of `Omsi.exe`; OMSI was not launched.

## New artifacts

- `ExportOmsiCallTargetStats.java`
- `Run-GhidraOmsiLowHelperStats.ps1`
- `ghidra-low-helper-call-stats.tsv`
- `ExportOmsiRaiseSites.java`
- `Run-GhidraOmsiRaiseSites.ps1`
- `ghidra-raise-sites-decoded.tsv`
- `Resolve-OmsiRaiseSiteResources.ps1`
- `ghidra-raise-sites-resolved.tsv`
- `ghidra-range-helper-callers.tsv`
- `ghidra-range-helper-context.tsv`
- `ghidra-range-data-context.tsv`
- `ghidra-message-pointer-context.tsv`

## Main findings

`0x00007E8C` is the high-volume Delphi active exception raiser. It has 675
direct call sites from the static Ghidra model. This frame is usually the final
raise frame, not the root cause.

Decoded raise-site classes of interest:

| Class | Raise sites | Unique caller functions | Interpretation |
| --- | ---: | ---: | --- |
| `EArgumentOutOfRangeException` | 233 | 233 | Widespread argument/index/length validation sites. |
| `EListError` | 24 | 23 | List and collection bounds checks. |
| `ERangeError` | 23 total, 22 with caller function | 10 | Delphi range checks, concentrated in low string/list helpers. |

The localized strings `Fehler bei Bereichsprufung`, `Listenindex uberschreitet
das Maximum (%d)`, and `Argument ausserhalb des Bereichs` still have no useful
direct string xrefs. The useful pivot is the exception class used immediately
before `CALL 0x00407E8C`.

The message operands are Delphi `TResStringRec` records, not direct strings.
`Resolve-OmsiRaiseSiteResources.ps1` loads `Omsi.exe` as a resource data file
and resolves those IDs with `LoadStringW`. In the range/list classes of
interest, 260 of 280 raise sites now have a resolved message text.

Resolved high-signal message counts:

| Class/message | Raise sites |
| --- | ---: |
| `EArgumentOutOfRangeException`: `Argument ausserhalb des Bereichs` | 228 |
| `ERangeError`: `Parameter %s darf kein negativer Wert sein` | 9 |
| `ERangeError`: `Listenindex uberschreitet das Maximum (%d)` | 8 |
| `EListError`: `Listenindex uberschreitet das Maximum (%d)` | 3 |
| `ERangeError`: `Kapazitat der Liste ist erschopft (%d)` | 3 |
| `ERangeError`: `Fehler bei Bereichsprufung` | 1 |
| `EArgumentOutOfRangeException`: `String-Index ausserhalb des Bereichs (%d). Muss >= 1 und <= %d sein` | 1 |

## ERangeError

`ERangeError` uses class slot `0x0041CECC`. The observed caller functions are
clustered between `0x0002ADCC` and `0x0002C7B4`, with raise sites extending to
`0x0002C81A`.

Representative caller functions:

- `0x0002ADCC`: two `ERangeError` raises using message slot `0x00859988`.
- `0x0002AE6C`: two `ERangeError` raises using message slot `0x00859988`.
- `0x0002B468`: one `ERangeError` raise.
- `0x0002BA80`: two `ERangeError` raises using message slots `0x00859D44` and `0x00859988`.
- `0x0002C01C`: five `ERangeError` raises; checks negative indexes and upper bounds.
- `0x0002C2C0`: two `ERangeError` raises.
- `0x0002C3CC`: three `ERangeError` raises; checks start/count/length-style bounds.
- `0x0002C6D8`: two `ERangeError` raises.
- `0x0002C74C`: one `ERangeError` raise.
- `0x0002C7B4`: two `ERangeError` raises.

These look like Delphi RTL string/array/list helpers rather than OMSI domain
logic. In runtime logs, the caller above this cluster will usually be more
important than the cluster frame itself.

Resolved `ERangeError` message distribution:

- 9x `Parameter %s darf kein negativer Wert sein`.
- 8x `Listenindex uberschreitet das Maximum (%d)`.
- 3x `Kapazitat der Liste ist erschopft (%d)`.
- 2x `Eingabepuffer fuer %s = %d, %s = %d ueberschritten`.
- 1x `Fehler bei Bereichsprufung`, raised at `0x0004DD9D` from an unassigned
  Ghidra function region around `0x0004DD85..0x0004DDA9`.

## EListError

`EListError` uses class slot `0x0043B7C4`.

Representative caller functions:

- `0x000B57F4..0x000B58ED`: list bounds helper path; constructs `EListError`
  around message slot `0x00859988`.
- `0x000D2188`: direct `EListError` constructor path.
- `0x000D3920`: list operation path using message slot `0x00858C20`.
- `0x00120818`: OMSI-side list access path; `CALL 0x00520110`, tests for a
  negative result, then constructs `EListError` with message slot `0x008589C0`.

`0x00120818..0x00120863` is the most interesting non-RTL list path observed in
this pass.

Resolved `EListError` message distribution:

- 17 sites have no static resource text; they appear to pass dynamic strings or
  use constructor forms without the `TResStringRec` pattern.
- 3x `Listenindex uberschreitet das Maximum (%d)`.
- 2x `Duplikate nicht zulaessig`.
- 1x `Eintrag nicht gefunden`.
- 1x invalid `PageIndex` range message.

## EArgumentOutOfRangeException

`EArgumentOutOfRangeException` uses class slot `0x0041C510`.

Most sites use message slot `0x00859A50`, matching a common argument/index
bounds message family. It is widespread: the decoded raise-site export found
233 sites in 233 unique caller functions, with caller functions ranging from
`0x0001233C` to `0x0034C810`.

Important concentrated range:

- `0x0011FF8C..0x001243B7`: repeated index/length checks around lookups and
  object/list access. It overlaps the `0x00120818` `EListError` path, so the
  probe labels the narrower list path first.
- `0x0020AEA4..0x0020CC14`: another repeated indexed-access cluster using the
  same `Argument ausserhalb des Bereichs` resource.
- `0x0034B148..0x0034C858`: a smaller repeated indexed-access cluster using
  the same resource.

## Probe labels added

`OmsiCrashProbe.cpp` now labels:

- `0x00007E8C..0x00007EF7`: Delphi active exception raiser.
- `0x0002ADCC..0x0002C81F`: Delphi range-check string/list helper cluster.
- `0x0004DD85..0x0004DDA9`: explicit `Fehler bei Bereichsprufung` raise site.
- `0x000B57F4..0x000B58ED`: Delphi list bounds helper.
- `0x00120818..0x00120863`: OMSI list access path.
- `0x0011FF8C..0x001243B7`: argument bounds checking cluster.
- `0x0020AEA4..0x0020CC14`: argument bounds checking cluster 2.
- `0x0034B148..0x0034C858`: argument bounds checking cluster 3.

These labels do not suppress or handle exceptions. They only annotate future
probe logs so repeated signatures can be grouped faster.
