param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-float-cluster-ranges.tsv'),
    [string[]]$Targets = @(
        'float_cluster_001EFB98', '0x001EFB98',
        'float_cluster_003B432C', '0x003B432C',
        'float_cluster_003860B0', '0x003860B0',
        'float_cluster_003922A0', '0x003922A0',
        'float_cluster_00224B40', '0x00224B40',
        'float_cluster_001AB9B8', '0x001AB9B8',
        'float_cluster_0024307C', '0x0024307C',
        'float_cluster_001CE730', '0x001CE730',
        'float_cluster_0034D878', '0x0034D878',
        'float_cluster_00353658', '0x00353658'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
$scriptPath = $PSScriptRoot

if (-not (Test-Path -LiteralPath $headless)) {
    throw "Ghidra analyzeHeadless.bat not found: $headless"
}

if (-not (Test-Path -LiteralPath $ProjectDir)) {
    throw "Ghidra project directory not found. Run Run-GhidraOmsiStringXrefs.ps1 first: $ProjectDir"
}

& $headless `
    $ProjectDir `
    $ProjectName `
    -process Omsi.exe `
    -noanalysis `
    -scriptPath $scriptPath `
    -postScript ExportOmsiFunctionRanges.java $OutputPath @Targets

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
