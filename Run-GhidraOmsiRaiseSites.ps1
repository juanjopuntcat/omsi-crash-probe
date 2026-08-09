param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-raise-sites-decoded.tsv'),
    [string]$RaiseRva = '0x00007E8C'
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
    -postScript ExportOmsiRaiseSites.java $OutputPath $RaiseRva

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
