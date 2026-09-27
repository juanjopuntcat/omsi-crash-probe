param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$DumpbinPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Keep missing Delphi functions explicit; do not repair the persistent model.
$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) { throw "Ghidra not found: $headless" }
$project = (Resolve-Path -LiteralPath $ProjectDir).Path
$functions = @(
    'cleanup_fault', '0x0042ADE3', 'bus_cleanup', '0x002FE6F8',
    'car_cleanup', '0x002FE85C', 'next_stage', '0x00246764',
    'map_load', '0x002E5C0C', 'map_close', '0x002E57B0',
    'map_constructor', '0x00385ADC', 'map_parser', '0x003860B0',
    'collection_cleanup', '0x0034A630'
)
$rvas = @(
    '0x0042ADE3', '0x0042AE5D', '0x00459D94', '0x00459538',
    '0x002E6053', '0x002E5985', '0x003871D3', '0x0038B11C',
    '0x0042C428', '0x002FE8C7', '0x002FE8EF', '0x002FE9BC'
)
$targets = @('map_slot=0x00459D94', 'map_storage=0x00461588')
$summary = Join-Path $PSScriptRoot 'ghidra-decompile-ai-review.tsv'
& $headless $project $ProjectName -process Omsi.exe -readOnly -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiDecompileFunctions.java (Join-Path $PSScriptRoot 'ghidra-decompile-ai-review') $summary @functions `
    -postScript ExportOmsiRvaContext.java (Join-Path $PSScriptRoot 'ghidra-ai-review-context.tsv') @rvas `
    -postScript ExportOmsiCallers.java (Join-Path $PSScriptRoot 'ghidra-ai-review-refs.tsv') @targets `
    -postScript ExportOmsiStringXrefs.java (Join-Path $PSScriptRoot 'ghidra-ai-review-strings.tsv') 'buses=P.KillNotNeededBuses' 'cars=P.KillNotNeededCars' 'inner=P.KNNC.KM'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# These linear excerpts are specific to the reviewed image. Embedded exception
# tables must not be mistaken for instructions; see ghidra-ai-review-notes.md.
if ($DumpbinPath) {
    if (-not (Test-Path -LiteralPath $DumpbinPath -PathType Leaf)) { throw "dumpbin not found: $DumpbinPath" }
    $binary = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Omsi.exe')).Path
    $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    if ($hash -ne '7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759') {
        throw "Binary differs from the reviewed build: $hash"
    }
    $ranges = [ordered]@{
        stages = '0x0082AD2C,0x0082AE87'
        bus = '0x006FE6F8,0x006FE738'
        car = '0x006FE85C,0x006FE94F'
        car_handler = '0x006FE8E7,0x006FE917'
        next_prefix = '0x00646764,0x006467C8'
        version = '0x00787197,0x007871DA'
    }
    foreach ($range in $ranges.GetEnumerator()) {
        $output = & $DumpbinPath /disasm "/range:$($range.Value)" $binary
        if ($LASTEXITCODE -ne 0) { throw "dumpbin failed: $($range.Key)" }
        $output | Out-File -LiteralPath (Join-Path $PSScriptRoot "ghidra-ai-$($range.Key).log") -Encoding utf8
    }
}

Write-Host "Wrote AI cleanup exports; inspect $summary for missing functions."
