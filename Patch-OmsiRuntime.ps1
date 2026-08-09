param(
    [ValidateSet('Audit', 'Apply', 'Rollback')]
    [string]$Mode = 'Audit',
    [string]$OmsiRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$ManifestPath = (Join-Path $PSScriptRoot 'patch-manifest.json'),
    [string]$PatchId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-HexBytes([string]$Text) {
    $compact = $Text -replace '[^0-9A-Fa-f]', ''
    if (($compact.Length % 2) -ne 0) { throw "Odd-length hex byte string: $Text" }
    $bytes = [byte[]]::new($compact.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($compact.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Test-BytesEqual([byte[]]$Left, [byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($i = 0; $i -lt $Left.Length; $i++) {
        if ($Left[$i] -ne $Right[$i]) { return $false }
    }
    return $true
}

function Get-PeIdentity([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { throw "$Path is not a PE file" }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($pe -lt 0 -or ($pe + 0x58) -ge $bytes.Length -or [BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) { throw "$Path has an invalid PE header" }
    [pscustomobject]@{
        Bytes = $bytes
        TimeDateStamp = ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, $pe + 8))
        SizeOfImage = ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, $pe + 0x50))
        Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1) { throw "Unsupported patch manifest schema: $($manifest.schemaVersion)" }
$patches = @($manifest.patches | Where-Object { -not $PatchId -or $_.id -eq $PatchId })
if ($PatchId -and $patches.Count -eq 0) { throw "Unknown patch id: $PatchId" }
if ($patches.Count -eq 0) { Write-Host 'No approved patches in the manifest.'; return }

foreach ($patch in $patches) {
    $target = [IO.Path]::GetFullPath((Join-Path $OmsiRoot $patch.target))
    $root = [IO.Path]::GetFullPath($OmsiRoot).TrimEnd('\') + '\'
    if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw "Patch target escapes OMSI root: $($patch.target)" }
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Patch target is missing: $target" }

    $backup = "$target.omsicrashprobe-$($patch.id).bak"
    if ($Mode -eq 'Rollback') {
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw "$($patch.id): backup is missing" }
        $backupIdentity = Get-PeIdentity $backup
        $allowedHashes = @($patch.allowedSha256 | ForEach-Object { $_.ToUpperInvariant() })
        if ($backupIdentity.Sha256 -notin $allowedHashes) { throw "$($patch.id): backup SHA-256 is not an approved original" }
        Copy-Item -LiteralPath $backup -Destination $target -Force
        Write-Host "ROLLED BACK $($patch.id): $target"
        continue
    }

    $identity = Get-PeIdentity $target
    $allowedHashes = @($patch.allowedSha256 | ForEach-Object { $_.ToUpperInvariant() })
    if ($identity.Sha256 -notin $allowedHashes) { throw "$($patch.id): SHA-256 mismatch ($($identity.Sha256))" }
    if ($patch.peTimeDateStamp -and $identity.TimeDateStamp -ne $patch.peTimeDateStamp) { throw "$($patch.id): PE timestamp mismatch" }
    if ($patch.peSizeOfImage -and $identity.SizeOfImage -ne $patch.peSizeOfImage) { throw "$($patch.id): PE image-size mismatch" }

    $expected = Convert-HexBytes $patch.expectedBytes
    $replacement = Convert-HexBytes $patch.replacementBytes
    if ($expected.Length -ne $replacement.Length) { throw "$($patch.id): replacement must preserve byte length" }
    $offset = [Convert]::ToInt64(($patch.fileOffset -replace '^0x', ''), 16)
    if ($offset -lt 0 -or ($offset + $expected.Length) -gt $identity.Bytes.Length) { throw "$($patch.id): file offset is outside target" }
    $actual = [byte[]]$identity.Bytes[$offset..($offset + $expected.Length - 1)]
    if (-not (Test-BytesEqual $actual $expected)) { throw "$($patch.id): expected bytes do not match" }

    if ($Mode -eq 'Audit') { Write-Host "AUDIT OK $($patch.id): $target"; continue }
    if (Test-Path -LiteralPath $backup) { throw "$($patch.id): refusing to overwrite existing backup $backup" }
    Copy-Item -LiteralPath $target -Destination $backup
    $patched = $identity.Bytes.Clone()
    [Array]::Copy($replacement, 0, $patched, $offset, $replacement.Length)
    $temporary = "$target.omsicrashprobe.tmp"
    try {
        [IO.File]::WriteAllBytes($temporary, $patched)
        Move-Item -LiteralPath $temporary -Destination $target -Force
    } catch {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $backup -Destination $target -Force
        throw
    }
    Write-Host "APPLIED $($patch.id): $target (backup: $backup)"
}
