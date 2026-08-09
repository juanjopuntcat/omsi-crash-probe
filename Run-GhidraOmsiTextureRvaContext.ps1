param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-texture-rva-context.tsv'),

    # RVAs found by Run-GhidraOmsiTextureStringXrefs.ps1 and the decompiled
    # D3DXCreateTextureFromFileExW call site.
    [string[]]$Rvas = @(
        '0x002F9FE5',
        '0x00243F6F',
        '0x003F91FB',
        '0x003FCC24'
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

& $headless `
    $ProjectDir `
    $ProjectName `
    -process Omsi.exe `
    -noanalysis `
    -scriptPath $scriptPath `
    -postScript ExportOmsiRvaContext.java $OutputPath @Rvas

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
