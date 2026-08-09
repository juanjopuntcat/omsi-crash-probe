param(
    [string]$PowerShellPath = 'powershell'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$fixtureRoot = Join-Path $PSScriptRoot 'tests\fixtures'
$analyzer = Join-Path $PSScriptRoot 'Analyze-OmsiCrashSession.ps1'
$logfile = Join-Path $fixtureRoot 'logfile-synthetic.txt'
$probeLog = Join-Path $fixtureRoot 'probe-synthetic.log'
$knownRvas = Join-Path $PSScriptRoot 'OmsiCrashProbe.cpp'
$testOutput = Join-Path ([IO.Path]::GetTempPath()) ('omsi-crash-probe-analysis-' + [Guid]::NewGuid().ToString('N') + '.md')

function Assert-ReportContains {
    param(
        [string]$Report,
        [string]$Pattern,
        [string]$Description
    )

    if ($Report -notmatch $Pattern) {
        throw "Missing expected report content: $Description ($Pattern)"
    }
}

try {
    & $PowerShellPath -NoProfile -ExecutionPolicy Bypass -File $analyzer `
        -OmsiRoot $PSScriptRoot `
        -ProbeLogPath $probeLog `
        -LogfilePath $logfile `
        -KnownRvaSourcePath $knownRvas `
        -OutputPath $testOutput `
        -Top 20

    if ($LASTEXITCODE -ne 0) {
        throw "Analyzer exited with code $LASTEXITCODE"
    }

    $report = Get-Content -LiteralPath $testOutput -Raw
    Assert-ReportContains $report 'vehicle / script / asset owner\s*\|\s*1' 'CV.Calculate Code 8 bucket'
    Assert-ReportContains $report 'map translation / visibility update\s*\|\s*2' 'map.translate and TUV bucket'
    Assert-ReportContains $report 'AI bus cleanup / memory management\s*\|\s*1' 'KillNotNeeded bucket'
    Assert-ReportContains $report 'PhysObj tries to load another collision mesh' 'pre-Code 8 PhysObj line'
    Assert-ReportContains $report 'D3DERR_INVALIDCALL' 'Direct3D reset HRESULT'
    Assert-ReportContains $report 'E_OUTOFMEMORY' 'texture allocation HRESULT'
    Assert-ReportContains $report '128,64,32' 'top reserved VAS blocks'
    Assert-ReportContains $report '600/100/200' 'private/mapped/image region counts'
    Assert-ReportContains $report 'VAS threshold crossings' 'threshold section'
    Assert-ReportContains $report 'CV.Calculate J2 checkpoint' 'KnownRVA signature label'
    Assert-ReportContains $report 'Critical 32-bit VAS exhaustion / fragmentation' 'VAS verdict'
    Assert-ReportContains $report 'Executable-page cache: 900 hits, 100 misses, 90% hit rate' 'stack page-cache statistics'
    Assert-ReportContains $report 'Large Address Aware: True \(0X81AE\)' 'executable LAA status'
    Assert-ReportContains $report 'Script command.*synthetic_bad' 'invalid script variable context'
    Assert-ReportContains $report 'Numeric / floating point.*not-a-number' 'invalid numeric token context'
    Assert-ReportContains $report 'Script compilation stopped' 'following script context line'

    Write-Host 'All analyzer fixture tests passed.'
}
finally {
    if (Test-Path -LiteralPath $testOutput) {
        Remove-Item -LiteralPath $testOutput -Force
    }
}
