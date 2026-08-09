# Graphical application design

The GUI will be a Windows desktop front end over the existing analyzer and
guarded patch transport. It must not contain a second binary-patching
implementation.

## Main workspace

The first screen is the working application, not a landing page. A compact left
navigation exposes Overview, Diagnostics, Patch candidates, Installed patches,
and Settings. Overview shows the selected OMSI directory, executable identity,
Large Address Aware state, probe installation state, latest session health, and
the number of compatible patches.

Executable identity is matched against `binary-profiles.json`. An unknown build
is shown as unsupported for patching while diagnostics remain available.

Diagnostics opens and groups `logfile.txt`, `probe.log`, and saved analysis
reports. Patch candidates reads `patch-candidates.json` and clearly labels
research state and confidence; it never offers Apply. Installed patches reads
`patch-manifest.json`, audits the selected OMSI build, and enables Apply or
Rollback only for an exact compatible target.

Destructive actions require a confirmation dialog containing patch ID, target,
detected hash, backup path, and the exact operation. Results remain visible in
an activity panel and can be exported for bug reports. Technical detail such as
RVA and expected bytes belongs in an expandable details view, not the primary
status line.

## Core boundary

The GUI consumes machine-readable output from a shared patching core. The core
owns path containment, PE parsing, hashes, expected-byte checks, backup,
transactional replacement, and rollback. The UI owns only selection,
presentation, confirmation, and progress reporting.

The intended implementation is a small native Windows desktop executable built
with the repository's existing MSVC toolchain. This avoids requiring users to
install PowerShell modules, .NET desktop runtimes, or a browser framework. The
PowerShell transport remains useful for development, CI, and recovery.

## Implemented native patch manager

Version `0.1.0.0` implements the native Win32 shell, executable selector, PE
identity and LAA inspection, known-profile recognition, and a dense list of 17
documented bug families. Validated manifest entries bind to rows by unique RVA.
The GUI classifies them as available, applied, or incompatible and exposes one
confirmed Apply or Rollback operation at a time. It blocks mutation while OMSI
is running. No action is currently selectable because the committed approved
manifest is empty. Windows version metadata and the DPI/Common Controls
manifest are embedded resources in `OmsiCrashProbe.exe`.

## Delivery stages

1. Extract PE identity and patch operations into a reusable C++ core with JSON
   status output and offline tests.
2. Build a read-only GUI showing installation, diagnostics, candidates, and
   compatibility.
3. Add audit and backup visibility.
4. Enable Apply and Rollback only after the first patch is approved and the
   native core has parity tests against the PowerShell transport.

Stages 1 through 3 are complete, including native transactional apply and
rollback tests. The manifest-to-row binding and guarded confirmation flow for
stage 4 are implemented; the first real fix still requires its own analysis,
approval, manifest entry, and parity tests before release.
