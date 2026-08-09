param(
    [string]$OmsiRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-omsi-string-xrefs.tsv'),
    [string[]]$Targets = @(),
    [switch]$UseExistingProject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
$omsiExe = Join-Path $OmsiRoot 'Omsi.exe'
$scriptPath = $PSScriptRoot

if (-not (Test-Path -LiteralPath $headless)) {
    throw "Ghidra analyzeHeadless.bat not found: $headless"
}

if (-not (Test-Path -LiteralPath $omsiExe)) {
    throw "Omsi.exe not found: $omsiExe"
}

New-Item -ItemType Directory -Force -Path $ProjectDir | Out-Null

$programArgs = if ($UseExistingProject) {
    @('-process', 'Omsi.exe', '-noanalysis')
}
else {
    @('-import', $omsiExe, '-overwrite')
}

$headlessArgs = @($ProjectDir, $ProjectName) + $programArgs + @(
    '-scriptPath', $scriptPath,
    '-postScript', 'ExportOmsiStringXrefs.java', $OutputPath
) + $Targets

& $headless @headlessArgs

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
