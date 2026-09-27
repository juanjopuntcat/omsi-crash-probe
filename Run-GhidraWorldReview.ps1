param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Trace H23's integer-to-text path and the selection predicate in the existing
# program. This exports evidence only; it never edits the model or game binary.
$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) { throw "Ghidra not found: $headless" }
$project = (Resolve-Path -LiteralPath $ProjectDir).Path
$functions = @(
    'world_owner', '0x0042695C', 'field_formatter', '0x00022180',
    'decimal_formatter', '0x00021D74', 'control_setter', '0x0008F12C',
    'text_pointer', '0x0000951C', 'text_dispatch', '0x0008E4F8',
    'text_message', '0x00090644', 'selection_lookup', '0x00383BB8',
    'collection_lookup', '0x00391918'
)
$rvas = @(
    '0x0042695C', '0x0042787D', '0x00428140', '0x004281D5',
    '0x00428350', '0x004283CD', '0x0042928D', '0x004292A1',
    '0x00022180', '0x00021D74', '0x00021E04', '0x0008F12C',
    '0x0008E4F8', '0x0000951C', '0x00383BB8', '0x00391918'
)
$targets = @('world_owner=0x0042695C', 'world_global=0x00462F28')
$summary = Join-Path $PSScriptRoot 'ghidra-decompile-world-review.tsv'
& $headless $project $ProjectName -process Omsi.exe -readOnly -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiDecompileFunctions.java (Join-Path $PSScriptRoot 'ghidra-decompile-world-review') $summary @functions `
    -postScript ExportOmsiRvaContext.java (Join-Path $PSScriptRoot 'ghidra-world-review-context.tsv') @rvas `
    -postScript ExportOmsiCallers.java (Join-Path $PSScriptRoot 'ghidra-world-review-refs.tsv') @targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Wrote World/UI exports; inspect $summary for per-function status."
