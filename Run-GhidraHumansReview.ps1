param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$DumpbinPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Export the existing model without inventing functions in undefined Delphi code.
$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) { throw "Ghidra not found: $headless" }
$project = (Resolve-Path -LiteralPath $ProjectDir).Path
$functions = @(
    'array_high', '0x0000A804', 'array_length', '0x0000A7FC',
    'human_call', '0x003BC3C0', 'loop_entry', '0x002EF9E4',
    'humans_fault', '0x002EFD03', 'clear_owner', '0x002E57B0',
    'remove_owner', '0x00303D2C', 'detach_owner', '0x0034AEC4',
    'append_owner', '0x00309E3C'
)
$rvas = @(
    '0x00459E58', '0x00461730', '0x002EF9E4', '0x002EFCC8',
    '0x002EFD03', '0x002EFEFC', '0x002EFF08', '0x002F19C3',
    '0x002F19EF', '0x00309E7D', '0x00309F0C', '0x00303DF4'
)
$targets = @(
    'humans_global_slot=0x00459E58', 'humans_storage=0x00461730',
    'loop_entry=0x002EF9E4', 'humans_fault=0x002EFD03',
    'loop_advance=0x002EFEFC'
)
$summary = Join-Path $PSScriptRoot 'ghidra-decompile-humans-review.tsv'
& $headless $project $ProjectName -process Omsi.exe -readOnly -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiDecompileFunctions.java (Join-Path $PSScriptRoot 'ghidra-decompile-humans-review') $summary @functions `
    -postScript ExportOmsiRvaContext.java (Join-Path $PSScriptRoot 'ghidra-humans-review-context.tsv') @rvas `
    -postScript ExportOmsiCallers.java (Join-Path $PSScriptRoot 'ghidra-humans-review-refs.tsv') @targets `
    -postScript ExportOmsiStringXrefs.java (Join-Path $PSScriptRoot 'ghidra-humans-review-strings.tsv') 'outside=RS.HumansOutside'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Optional linear decoding supplements missing functions. Check the exact local
# binary first: these absolute ranges are meaningful only for this build.
# Exception tables and padding in the output are data, not executable instructions.
if ($DumpbinPath) {
    if (-not (Test-Path -LiteralPath $DumpbinPath -PathType Leaf)) {
        throw "dumpbin not found: $DumpbinPath"
    }
    $binary = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Omsi.exe')).Path
    $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    if ($hash -ne '7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759') {
        throw "Binary differs from the reviewed build: $hash"
    }
    $ranges = [ordered]@{
        entry = '0x006EF9E4,0x006EFA39'
        loop = '0x006EFCC8,0x006EFF8C'
        context_call = '0x006F198B,0x006F19D6'
        context_handler = '0x006F19E3,0x006F1A1F'
        append = '0x00709E3C,0x00709FCE'
        remove = '0x00703D2C,0x00703E4D'
    }
    foreach ($range in $ranges.GetEnumerator()) {
        $output = & $DumpbinPath /disasm "/range:$($range.Value)" $binary
        if ($LASTEXITCODE -ne 0) { throw "dumpbin failed: $($range.Key)" }
        $output | Out-File -LiteralPath (Join-Path $PSScriptRoot "ghidra-humans-$($range.Key).log") -Encoding utf8
    }
}

Write-Host "Wrote HumansOutside exports; inspect $summary for missing functions."
