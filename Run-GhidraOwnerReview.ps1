param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Follow the H02 write chain and H21 geometry callers in the existing program.
# Undefined regions stay undefined; this pass never rewrites the Ghidra model.
$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) { throw "Ghidra not found: $headless" }
$project = (Resolve-Path -LiteralPath $ProjectDir).Path
$functions = @(
    'string_sink', '0x00241BEC', 'string_owner', '0x00241C38',
    'poi_fault_owner', '0x003C3FA8', 'sink_target', '0x003EFA4C',
    'caller_dispatch', '0x002427B8', 'poi_caller_a', '0x003BA930',
    'poi_caller_b', '0x003A03F8', 'io_write', '0x000052C0',
    'callback_dispatch', '0x0034C4F8', 'io_common', '0x00005210'
)
$rvas = @(
    '0x00241BEC', '0x00241C38', '0x002421CE', '0x003C400E',
    '0x003C3FA8', '0x003EFA4C', '0x00242CF7', '0x003C40AC',
    '0x003C4104', '0x003C4160', '0x003C41C0', '0x003AEEDC',
    '0x000052C0', '0x0034C4F8', '0x003C40CF', '0x003C41C6',
    '0x00005210', '0x0034C53C', '0x003C3FB0', '0x003C40ED', '0x00002888'
)
$targets = @(
    'string_sink=0x00241BEC', 'string_owner=0x00241C38',
    'poi_fault_owner=0x003C3FA8', 'io_write=0x000052C0',
    'line_writer=0x003EFA4C'
)
$outputDir = Join-Path $PSScriptRoot 'ghidra-decompile-owner-review'
$summary = Join-Path $PSScriptRoot 'ghidra-decompile-owner-review.tsv'
$context = Join-Path $PSScriptRoot 'ghidra-owner-review-context.tsv'
$callers = Join-Path $PSScriptRoot 'ghidra-owner-review-callers.tsv'

& $headless $project $ProjectName -process Omsi.exe -readOnly -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiDecompileFunctions.java $outputDir $summary @functions `
    -postScript ExportOmsiRvaContext.java $context @rvas `
    -postScript ExportOmsiCallers.java $callers @targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Wrote $summary, $context and $callers"
