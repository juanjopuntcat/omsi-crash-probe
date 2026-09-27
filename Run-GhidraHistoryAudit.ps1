param(
    [string]$GhidraRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\ghidra_12.1.2')).Path,
    [string]$ProjectDir = (Join-Path $PSScriptRoot 'ghidra-projects'),
    [string]$ProjectName = 'OmsiStatic'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Process only the existing OMSI program. Never import directories or rewrite
# the analysis database when an address is undefined or points into an operand.
$headless = Join-Path $GhidraRoot 'support\analyzeHeadless.bat'
if (-not (Test-Path -LiteralPath $headless)) { throw "Ghidra not found: $headless" }
$project = (Resolve-Path -LiteralPath $ProjectDir).Path
$rvas = @(
    '0x002421CE', '0x00006E6C', '0x00008850', '0x003C400E',
    '0x001D49B0', '0x00429C09', '0x00006B14', '0x00004911',
    '0x002F4F1D', '0x003D61F8', '0x002EFEFC', '0x0042AE5D'
)
$targets = @(
    'plugin=PlugInRefrVars', 'poi=POI.GHAA', 'skylights=RS.SkyLights',
    'cmoi=CMOI.R.3', 'cleanup=P.KNNC.KM', 'buses=P.KillNotNeededBuses',
    'cv_i=CV.Calculate - I', 'cv_j2=CV.Calculate - J2',
    'unscheduled=UnschedClearSteuerl', 'visu=visu drivers translate 2',
    'help=kontextsensitive', 'resource=The requested resource is in use'
)
$rvaOutput = Join-Path $PSScriptRoot 'ghidra-history-rva-context.tsv'
$stringOutput = Join-Path $PSScriptRoot 'ghidra-history-string-xrefs.tsv'

& $headless $project $ProjectName -process Omsi.exe -readOnly -noanalysis `
    -scriptPath $PSScriptRoot `
    -postScript ExportOmsiRvaContext.java $rvaOutput @rvas `
    -postScript ExportOmsiStringXrefs.java $stringOutput @targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Wrote $rvaOutput and $stringOutput"
