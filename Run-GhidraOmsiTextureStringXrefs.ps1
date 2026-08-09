param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-texture-string-xrefs.tsv'),

    # Focused strings for the texture-memory failure family seen in logfile.txt.
    # These are string fragments, not regular expressions.
    [string[]]$Targets = @(
        'texture_load_error_wrapper=Fehlercode beim Texturenladen',
        'texture_manager_memory=Speicherbedarf Texturmanager',
        'texture_list_type=PIDirect3DTexture9',
        'texture_array_type=TArrayOfIDirect3DTexture9',
        'texture_stage_index=Too high texture stage index',
        'direct3d_texture_type=IDirect3DTexture9',
        'first_index_of_texture=firstIndexOfTexture'
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

# Ghidra needs a JDK, not just a JRE. Codex/escalated shells do not always
# inherit the same PATH as an interactive terminal, so set JAVA_HOME from common
# Windows JDK locations when it is missing or points at a JRE.
$javaHomeLooksLikeJdk = $env:JAVA_HOME -and
    ($env:JAVA_HOME -notmatch '\\jre[-\\]') -and
    (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME 'bin\java.exe'))

if (-not $javaHomeLooksLikeJdk) {
    $jdk = Get-ChildItem -LiteralPath 'C:\Program Files\Eclipse Adoptium','C:\Program Files\Java','C:\Program Files\Microsoft' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'jdk' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'bin\java.exe')) } |
        Sort-Object Name -Descending |
        Select-Object -First 1

    if ($jdk) {
        $env:JAVA_HOME = $jdk.FullName
        $env:Path = (Join-Path $jdk.FullName 'bin') + ';' + $env:Path
    }
}

# Reuse the existing analyzed project. The Java script scans defined strings and
# writes only xrefs for the target fragments above.
& $headless `
    $ProjectDir `
    $ProjectName `
    -process Omsi.exe `
    -noanalysis `
    -scriptPath $scriptPath `
    -postScript ExportOmsiStringXrefs.java $OutputPath @Targets

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
