# Guarded binary patching design

`Patch-OmsiRuntime.ps1` is the guarded patch transport. It defaults to `Audit`;
the committed manifest intentionally contains no approved patches.

Each future manifest entry must contain an ID, target path relative to the OMSI
root, allowed SHA-256 hashes, PE timestamp and image size, file offset, original
bytes, same-length replacement bytes, RVA, rationale, and reversibility notes.
RVA documents the analysis; file offset identifies bytes on disk. They are not
interchangeable in a PE file.

Before writing, the tool checks that the resolved target remains below the OMSI
root, verifies the complete binary identity, and compares the exact original
bytes. Apply creates a patch-specific backup and refuses to overwrite one.
Writes go through a temporary file; a failed replacement restores the backup.
Rollback requires that backup.

`Test-PatchOmsiRuntime.ps1` exercises audit, apply, byte verification, backup,
and rollback against a synthetic PE file. It never opens or modifies OMSI.

`binary-profiles.json` records executable identities we have actually inspected.
Profiles distinguish LAA-modified and unmodified executables even when their PE
timestamp and image size agree. A known profile is evidence for compatibility,
not by itself an approved patch.

The native `OmsiPatchTool` currently exposes read-only `inspect` and `rva`
commands with one JSON object on standard output. This is the initial stable
boundary for automation and the GUI.

`PatchCore` now implements native audit, apply, and rollback primitives. They
validate the patch ID, complete original SHA-256, exact original bytes, and
same-length replacement. Apply creates a non-overwriting patch-specific backup,
validates that new backup, writes a new sibling temporary file, flushes it, and
atomically replaces the target. Rollback accepts only a backup that still
matches the approved original. Offline tests exercise the full transaction and
reject repeat application, unsafe IDs, and unexpected bytes.

These mutation primitives are not exposed by the CLI or GUI yet. The next gate
is a strictly validated native manifest reader; UI code must never construct
patch offsets or replacement bytes itself.

Original game binaries, wholesale decompiler output, and copyrighted game data
must never be committed. Releases may contain our probe, scripts, manifests, and
documentation, but not original or modified OMSI executables or DLLs.
