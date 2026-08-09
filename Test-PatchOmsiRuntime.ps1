$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('omsi-patcher-test-' + [Guid]::NewGuid().ToString('N'))

$candidateCatalog = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'patch-candidates.json') -Raw | ConvertFrom-Json
if ($candidateCatalog.schemaVersion -ne 1 -or @($candidateCatalog.candidates).Count -eq 0) {
    throw 'Patch candidate catalog is empty or has an unsupported schema'
}
$binaryProfiles = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'binary-profiles.json') -Raw | ConvertFrom-Json
if ($binaryProfiles.schemaVersion -ne 1 -or @($binaryProfiles.profiles).Count -eq 0) {
    throw 'Binary profile catalog is empty or has an unsupported schema'
}

try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $target = Join-Path $root 'Synthetic.exe'
    $bytes = [byte[]]::new(512)
    $bytes[0] = 0x4D; $bytes[1] = 0x5A
    [BitConverter]::GetBytes([int]0x80).CopyTo($bytes, 0x3C)
    [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes, 0x80)
    [BitConverter]::GetBytes([uint32]0x12345678).CopyTo($bytes, 0x88)
    [BitConverter]::GetBytes([uint32]0x00100000).CopyTo($bytes, 0xD0)
    $bytes[0x120] = 0xAA; $bytes[0x121] = 0xBB
    [IO.File]::WriteAllBytes($target, $bytes)
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    $manifestPath = Join-Path $root 'manifest.json'
    @{
        schemaVersion = 1
        patches = @(@{
            id = 'synthetic-byte-change'
            target = 'Synthetic.exe'
            allowedSha256 = @($hash)
            peTimeDateStamp = '0x12345678'
            peSizeOfImage = '0x00100000'
            fileOffset = '0x120'
            expectedBytes = 'AA BB'
            replacementBytes = '11 22'
        })
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding ASCII

    $patcher = Join-Path $PSScriptRoot 'Patch-OmsiRuntime.ps1'
    & $patcher -Mode Audit -OmsiRoot $root -ManifestPath $manifestPath
    & $patcher -Mode Apply -OmsiRoot $root -ManifestPath $manifestPath
    $patched = [IO.File]::ReadAllBytes($target)
    if ($patched[0x120] -ne 0x11 -or $patched[0x121] -ne 0x22) { throw 'Apply did not write replacement bytes' }
    & $patcher -Mode Rollback -OmsiRoot $root -ManifestPath $manifestPath
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $hash) { throw 'Rollback did not restore the original file' }
    Write-Host 'All guarded patch transport tests passed.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
