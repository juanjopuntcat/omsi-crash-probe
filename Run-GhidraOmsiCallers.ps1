param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-omsi-helper-callers.tsv'),
    [string[]]$Targets = @(
        'delphi_exception_raise=0x00021124',
        'delphi_system_error=0x0002A000',
        'string_to_float_parser=0x00024F68',
        'delphi_conversion_wrapper=0x0002237C',
        'bmp_gdi_bitmap_load=0x00076C10',
        'direct9_error_formatter=0x004029AC',
        'direct3d_device_creation=0x002793A8',
        'direct3d_device_reset=0x00429FD8'
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
    -postScript ExportOmsiCallers.java $OutputPath @Targets

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
