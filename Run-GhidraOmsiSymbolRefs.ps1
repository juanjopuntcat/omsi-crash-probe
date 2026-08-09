param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-omsi-symbol-refs.tsv'),
    [string[]]$Symbols = @(
        'dGeomTriMeshDataCreate',
        'dGeomTriMeshDataDestroy',
        'D3DXCreateTextureFromFileExA',
        'D3DXCreateTextureFromFileExW',
        'VirtualAlloc',
        'VirtualFree',
        'HeapAlloc',
        'HeapFree'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) {
    throw "Ghidra analyzeHeadless.bat not found: $headless"
}
if (-not (Test-Path -LiteralPath $ProjectDir)) {
    throw "Ghidra project directory not found: $ProjectDir"
}

& $headless `
    $ProjectDir `
    $ProjectName `
    -process Omsi.exe `
    -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiSymbolRefs.java $OutputPath @Symbols

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
