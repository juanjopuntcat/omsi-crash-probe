param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic',
    [string]$DumpbinPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Preserve gaps in the existing Delphi function model rather than repairing it.
$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) { throw "Ghidra not found: $headless" }
$project = (Resolve-Path -LiteralPath $ProjectDir).Path
$functions = @(
    'recovery_owner', '0x00429E84', 'reset_site', '0x0042A386',
    'release_global', '0x003FA44C', 'restore_global', '0x003FA488',
    'release_manager', '0x003F7258', 'release_entry', '0x003F9C48',
    'release_interface', '0x0000C050', 'world_lost', '0x002E6D48',
    'world_restore', '0x002E6D64', 'restore_manager', '0x00400CAC',
    'restore_ui', '0x004257CC', 'force_reset_writer', '0x00306354',
    'error_name', '0x00162A84'
)
$rvas = @(
    '0x00429F67', '0x00429FD8', '0x0042A386', '0x0042A5E1',
    '0x00458824', '0x00462F24', '0x0042B8D8', '0x0042BB7C',
    '0x004647FC', '0x00306631'
)
$targets = @('forced_reset=0x00462F24', 'force_slot=0x00459244')
$summary = Join-Path $PSScriptRoot 'ghidra-decompile-d3d-review.tsv'
& $headless $project $ProjectName -process Omsi.exe -readOnly -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiDecompileFunctions.java (Join-Path $PSScriptRoot 'ghidra-decompile-d3d-review') $summary @functions `
    -postScript ExportOmsiRvaContext.java (Join-Path $PSScriptRoot 'ghidra-d3d-review-context.tsv') @rvas `
    -postScript ExportOmsiCallers.java (Join-Path $PSScriptRoot 'ghidra-d3d-review-refs.tsv') @targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Linear excerpts are build-specific and include embedded exception tables.
# Exact handler entries are exported separately; see the review notes.
if ($DumpbinPath) {
    if (-not (Test-Path -LiteralPath $DumpbinPath -PathType Leaf)) { throw "dumpbin not found: $DumpbinPath" }
    $binary = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\Omsi.exe')).Path
    $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    if ($hash -ne '7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759') {
        throw "Binary differs from the reviewed build: $hash"
    }
    $ranges = [ordered]@{
        state = '0x00829E84,0x00829FE4'
        release = '0x00829FE4,0x0082A377'
        reset = '0x0082A377,0x0082A603'
        handler_array = '0x0082A1AC,0x0082A1ED'
        handler_surface = '0x0082A220,0x0082A261'
        handler_world = '0x0082A294,0x0082A2D5'
        handler_dimensions = '0x0082A336,0x0082A377'
        handler_restore_manager = '0x0082A425,0x0082A466'
        handler_restore_global = '0x0082A4A0,0x0082A4E1'
        handler_restore_world = '0x0082A520,0x0082A561'
        handler_restore_ui = '0x0082A5A0,0x0082A5E8'
        continuation = '0x0082A603,0x0082A6B4'
        cleanup = '0x0082B5CD,0x0082B83C'
        formatter = '0x00562A84,0x00562A8A'
    }
    foreach ($range in $ranges.GetEnumerator()) {
        $output = & $DumpbinPath /disasm "/range:$($range.Value)" $binary
        if ($LASTEXITCODE -ne 0) { throw "dumpbin failed: $($range.Key)" }
        $output | Out-File -LiteralPath (Join-Path $PSScriptRoot "ghidra-d3d-$($range.Key).log") -Encoding utf8
    }
}

Write-Host "Wrote Direct3D exports; inspect $summary for missing functions."
