param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$OutputPath = (Join-Path $PSScriptRoot 'ghidra-resource-record-refs.tsv'),

    # Resource IDs that match real OMSI logfile families. The Java script looks
    # for Delphi TResStringRec-style records that point at these resource IDs.
    [string[]]$Targets = @(
        'zu_wenig_arbeitsspeicher=0xFFF6',
        'zu_wenig_speicherplatz=0xFFFB',
        'systemressourcen_erschoepft=0xFF2F',
        'request_not_enough_memory=0xFDF1',
        'bitmap_ist_ungueltig=0xFF24',
        'ungueltiges_bild=0xFF28',
        'unknown_image_extension=0xFF2D',
        'window_dc_create_failed=0xFF18',
        'systemfehler_code=0xFFCF',
        'stream_expand_no_memory=0xFF76',
        'stream_read_error=0xFF79',
        'stream_write_error=0xFF63'
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

# Reuse the already-analyzed Ghidra project and process only Omsi.exe. We pass
# -noanalysis because this export is a lightweight read over the existing model.
& $headless `
    $ProjectDir `
    $ProjectName `
    -process Omsi.exe `
    -noanalysis `
    -scriptPath $scriptPath `
    -postScript ExportOmsiResourceRecordRefs.java $OutputPath @Targets

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Wrote $OutputPath"
