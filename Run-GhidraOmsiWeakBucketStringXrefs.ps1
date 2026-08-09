param(
    [string]$OmsiRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-weak-bucket-string-xrefs.tsv'),
    [string[]]$Targets = @(
        'directsound=DirectSound',
        'dsound=DSound',
        'wave=WAV',
        'riff=RIFF',
        'sound=Sound',
        'sound_lower=sound',
        'variable_name=Variablenname',
        'invalid_variable=ungultig',
        'command=Befehl',
        'plugin_refs=PlugInRefrVars',
        'resource_in_use=Ressource',
        'external_exception=Externe Exception'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Focused static xref pass for weaker roadmap buckets. It imports/processes only
# Omsi.exe and never traverses content folders such as Vehicles, maps, Addons, or
# SceneryObjects.
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

& $headless `
    $ProjectDir `
    $ProjectName `
    -import $omsiExe `
    -overwrite `
    -scriptPath $scriptPath `
    -postScript ExportOmsiStringXrefs.java $OutputPath @Targets

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
